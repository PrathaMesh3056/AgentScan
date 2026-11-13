"""Small stdlib-only entry point for the separate gateway process."""

from __future__ import annotations

import argparse
import asyncio
import os
import re
import sys
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from starlette.applications import Starlette

    from agentscan.gateway.catalog import ToolCatalog
    from agentscan.gateway.config import GatewaySettings
    from agentscan.gateway.policy import VerifiedPolicyBundle
    from agentscan.gateway.receipts import ReceiptChainStore
    from agentscan.gateway.recovery import ReconciliationResult
    from agentscan.gateway.runtime import GatewayRuntime
    from agentscan.gateway.upstream import UpstreamClient

_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class GatewayCliError(RuntimeError):
    """A bounded, operator-facing gateway startup or reconciliation error."""


@dataclass(frozen=True, slots=True)
class GatewayService:
    """Started gateway resources, owned by `open_gateway_service`."""

    settings: GatewaySettings
    bundle: VerifiedPolicyBundle
    store: ReceiptChainStore
    upstream: UpstreamClient
    catalog: ToolCatalog
    runtime: GatewayRuntime
    app: Starlette


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agentscan-gateway")
    parser.add_argument(
        "command",
        nargs="?",
        choices=("serve", "verify", "policy", "reconcile"),
        help="gateway operation",
    )
    parser.add_argument("command_args", nargs=argparse.REMAINDER)
    return parser


def _build_policy_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agentscan-gateway policy")
    subparsers = parser.add_subparsers(dest="policy_command", required=True)

    sign_parser = subparsers.add_parser("sign", help="sign an unsigned policy object")
    sign_parser.add_argument("--policy", required=True, help="unsigned policy YAML file")
    sign_parser.add_argument("--private-key", required=True, help="Ed25519 private key PEM file")
    sign_parser.add_argument("--bundle-id", required=True)
    sign_parser.add_argument("--tenant", required=True)
    sign_parser.add_argument("--issued-at", required=True)
    sign_parser.add_argument("--expires-at", required=True)
    sign_parser.add_argument("--out", required=True, help="output signed bundle YAML file")

    verify_parser = subparsers.add_parser("verify", help="verify a signed policy bundle")
    verify_parser.add_argument("--bundle", required=True, help="signed policy bundle YAML file")
    verify_parser.add_argument("--public-key", required=True, help="Ed25519 public key PEM file")
    return parser


def _build_serve_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agentscan-gateway serve")
    parser.add_argument("--config", required=True, help="gateway TOML configuration file")
    return parser


def _build_reconcile_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agentscan-gateway reconcile")
    parser.add_argument("--config", required=True, help="gateway TOML configuration file")
    parser.add_argument(
        "--idempotency-key",
        required=True,
        help="raw idempotency key used for the pending decision",
    )
    parser.add_argument(
        "--request-hash",
        default=None,
        help="optional stored sha256 request hash when the key alone is ambiguous",
    )
    return parser


def _upstream_credential(settings: GatewaySettings) -> str:
    value = os.environ.get(settings.upstream_credential_env)
    if not value:
        raise GatewayCliError(
            f"missing upstream credential environment variable: {settings.upstream_credential_env}"
        )
    return value


def _receipt_store(settings: GatewaySettings) -> ReceiptChainStore:
    from agentscan.gateway.receipts import ReceiptChainStore

    return ReceiptChainStore(
        settings.receipt_dir,
        tenant=settings.tenant,
        gateway_id=settings.gateway_id,
        chain_id=settings.chain_id,
        writer_id=settings.writer_id,
        retention_days=settings.retention_days,
    )


def _load_policy_bundle(settings: GatewaySettings) -> VerifiedPolicyBundle:
    from agentscan.gateway.policy import verify_policy_file

    return verify_policy_file(settings.policy_bundle, settings.policy_public_key)


def _make_upstream(settings: GatewaySettings, credential: str) -> UpstreamClient:
    from agentscan.gateway.upstream import UpstreamClient

    return UpstreamClient(
        url=settings.upstream_url,
        server_id=settings.upstream_server_id,
        credential=credential,
        tenant=settings.tenant,
        timeout_seconds=settings.upstream_timeout_seconds,
    )


@asynccontextmanager
async def open_gateway_service(config_path: str | Path) -> AsyncIterator[GatewayService]:
    """Load, recover, and start the gateway; close every resource on exit."""
    from agentscan.gateway.catalog import ToolCatalog
    from agentscan.gateway.config import load_config
    from agentscan.gateway.identity import IdentityVerifier, load_trust_keys
    from agentscan.gateway.metrics import MetricsRegistry
    from agentscan.gateway.recovery import recover
    from agentscan.gateway.runtime import GatewayRuntime
    from agentscan.gateway.server import create_app
    from agentscan.gateway.sessions import SessionRegistry

    settings = load_config(config_path).gateway
    credential = _upstream_credential(settings)
    bundle = _load_policy_bundle(settings)
    store = _receipt_store(settings)
    upstream: UpstreamClient | None = None
    try:
        store.acquire_writer_lease()
        recovery = recover(store)
        upstream = _make_upstream(settings, credential)
        await upstream.start()
        catalog = ToolCatalog(settings.upstream_server_id)
        catalog.replace(await upstream.list_tools())
        metrics = MetricsRegistry()
        runtime = GatewayRuntime(
            settings=settings,
            bundle=bundle,
            store=store,
            index=recovery.index,
            upstream=upstream,
            catalog=catalog,
            metrics=metrics,
        )
        verifier = IdentityVerifier(
            trusted_issuer=settings.trusted_issuer,
            audience=settings.audience,
            tenant=settings.tenant,
            trust_keys=load_trust_keys(settings.trust_keys),
            clock_skew_seconds=settings.clock_skew_seconds,
        )
        sessions = SessionRegistry(
            idle_timeout_seconds=settings.session_idle_timeout_seconds,
            max_lifetime_seconds=settings.session_max_lifetime_seconds,
        )
        app = create_app(
            settings,
            identity_verifier=verifier,
            sessions=sessions,
            runtime=runtime,
            metrics=metrics,
        )
        yield GatewayService(
            settings=settings,
            bundle=bundle,
            store=store,
            upstream=upstream,
            catalog=catalog,
            runtime=runtime,
            app=app,
        )
    finally:
        if upstream is not None:
            await upstream.aclose()
        store.close()


def serve(config_path: str | Path, *, server_factory: Callable[..., Any] | None = None) -> None:
    """Run the gateway under uvicorn until shutdown."""

    async def run() -> None:
        async with open_gateway_service(config_path) as service:
            if server_factory is not None:
                server = server_factory(service)
                await server.serve()
                return
            import uvicorn

            settings = service.settings
            config = uvicorn.Config(
                service.app,
                host=settings.listen_host,
                port=settings.listen_port,
                log_level="info",
                ssl_certfile=settings.tls_certfile or None,
                ssl_keyfile=settings.tls_keyfile or None,
            )
            await uvicorn.Server(config).serve()

    asyncio.run(run())


async def reconcile_gateway(
    config_path: str | Path,
    *,
    idempotency_key: str,
    request_hash: str | None = None,
) -> ReconciliationResult:
    """Query the authenticated upstream and reconcile one stored decision."""
    from agentscan.gateway.config import load_config
    from agentscan.gateway.idempotency import hash_key
    from agentscan.gateway.recovery import UpstreamConfirmation, reconcile

    if request_hash is not None and not _SHA256_RE.fullmatch(request_hash):
        raise GatewayCliError("request hash must use sha256:<64 lowercase hex>")
    settings = load_config(config_path).gateway
    credential = _upstream_credential(settings)
    bundle = _load_policy_bundle(settings)
    key_hash = hash_key(idempotency_key, max_bytes=settings.max_idempotency_key_bytes)
    store = _receipt_store(settings)
    upstream: UpstreamClient | None = None
    try:
        store.acquire_writer_lease()
        decisions = [
            receipt
            for receipt in store.receipts
            if receipt.phase == "decision"
            and receipt.idempotency_key == key_hash
            and (request_hash is None or receipt.request_hash == request_hash)
        ]
        if len(decisions) != 1:
            raise GatewayCliError("idempotency key does not identify exactly one stored decision")
        decision = decisions[0]
        policy_tool = bundle.policy.tools.get(decision.tool.name)
        operation = policy_tool.status_operation if policy_tool is not None else None
        if not operation:
            raise GatewayCliError("tool has no authenticated status operation")
        upstream = _make_upstream(settings, credential)
        await upstream.start()
        effect = await upstream.check_effect(
            operation,
            key_hash=key_hash,
            request_hash=decision.request_hash,
        )
        confirmation = UpstreamConfirmation(
            status=effect.status,
            key_hash=effect.key_hash,
            request_hash=effect.request_hash,
            confirmation_id=effect.confirmation_id,
            observed_at=effect.observed_at,
            authenticated=True,
        )
        return reconcile(
            store,
            idempotency_key=idempotency_key,
            confirmation=confirmation,
            max_key_bytes=settings.max_idempotency_key_bytes,
        )
    finally:
        if upstream is not None:
            await upstream.aclose()
        store.close()


def _run_policy(command_args: list[str]) -> None:
    policy_parser = _build_policy_parser()
    policy_args = policy_parser.parse_args(command_args)
    from agentscan.gateway.policy import (
        PolicyError,
        sign_policy_file,
        verify_policy_file,
    )

    try:
        if policy_args.policy_command == "sign":
            sign_policy_file(
                policy_args.policy,
                policy_args.private_key,
                bundle_id=policy_args.bundle_id,
                tenant=policy_args.tenant,
                issued_at=policy_args.issued_at,
                expires_at=policy_args.expires_at,
                output_path=policy_args.out,
            )
            print(f"signed bundle: {policy_args.out}")
        else:
            verified = verify_policy_file(policy_args.bundle, policy_args.public_key)
            print(f"policy_hash={verified.policy_hash}")
            print(f"key_id={verified.key_id}")
    except (PolicyError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1) from None


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    if args.command is None:
        return
    try:
        if args.command == "policy":
            _run_policy(args.command_args)
            return
        if args.command == "serve":
            serve_args = _build_serve_parser().parse_args(args.command_args)
            serve(serve_args.config)
            return
        if args.command == "reconcile":
            reconcile_args = _build_reconcile_parser().parse_args(args.command_args)
            result = asyncio.run(
                reconcile_gateway(
                    reconcile_args.config,
                    idempotency_key=reconcile_args.idempotency_key,
                    request_hash=reconcile_args.request_hash,
                )
            )
            receipt = result.appended.evidence.hash if result.appended is not None else "none"
            print(f"reconciliation={result.status.value} receipt={receipt}")
            return
        parser.error(f"{args.command} is not available yet")
    except KeyboardInterrupt:
        return
    except SystemExit:
        raise
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
