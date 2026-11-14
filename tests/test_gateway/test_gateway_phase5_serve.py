"""Phase 5 slice 3: end-to-end serve wiring and authenticated reconciliation."""

from __future__ import annotations

import asyncio
import json
import socket
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import jwt
import pytest
import uvicorn
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.exceptions import McpError

from agentscan.gateway import cli
from agentscan.gateway.catalog import tool_schema_hash
from agentscan.gateway.idempotency import hash_key
from agentscan.gateway.mock_upstream import MockUpstreamConfig, create_mock_upstream_app
from agentscan.gateway.policy import sign_policy, verify_policy_file, write_signed_policy_atomic
from agentscan.gateway.receipts import (
    GENESIS_HASH,
    GatewayReceipt,
    ReceiptAuthorization,
    ReceiptChainStore,
    ReceiptEvidence,
    ReceiptResult,
    ReceiptTool,
    utc_timestamp,
)
from agentscan.gateway.recovery import ReconciliationStatus
from agentscan.gateway.upstream import UpstreamClient

TENANT = "tenant-demo"
SERVER_ID = "mock-crm"
CREDENTIAL_ENV = "AGENTSCAN_TEST_UPSTREAM_CREDENTIAL"
CREDENTIAL = "gateway-credential-canary"
RAW_KEY = "e2e-idempotency-key"

DELETE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "customer_id": {"type": "string", "pattern": "^cust-[0-9]{4}$"},
    },
    "required": ["customer_id"],
    "additionalProperties": False,
}


def _pem(private: Ed25519PrivateKey) -> bytes:
    return private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _public_pem(private: Ed25519PrivateKey) -> str:
    return (
        private.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("ascii")
    )


def _timestamp(delta: timedelta) -> str:
    return (datetime.now(UTC) + delta).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _tool_entry(*, rules: list[dict[str, Any]], status_operation: str | None) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "server": SERVER_ID,
        "risk": "high",
        "enforcement": "inline",
        "resource_tenant_enforced": "upstream",
        "schema_hash": tool_schema_hash(DELETE_SCHEMA),
        "rules": rules,
    }
    if status_operation is not None:
        entry["status_operation"] = status_operation
    return entry


def _default_rules() -> list[dict[str, Any]]:
    return [
        {"id": "deny-intern", "principal_role": "intern", "decision": "deny"},
        {
            "id": "allow-delete",
            "principal_role": "operator",
            "tenant_match": True,
            "arguments": {"customer_id": {"pattern": "^cust-[0-9]+$"}},
            "decision": "allow",
        },
    ]


def _write_policy_and_trust(
    tmp_path: Path,
    private: Ed25519PrivateKey,
    *,
    rules: list[dict[str, Any]],
    status_operation: str | None = "internal:check_effect",
) -> tuple[Path, Path, Path]:
    policy_path = tmp_path / "policy.yaml"
    public_path = tmp_path / "policy.pub"
    trust_path = tmp_path / "trust.json"
    envelope = sign_policy(
        {
            "version": 1,
            "policy_id": "policy-e2e",
            "tenant": TENANT,
            "default": "deny",
            "tools": {
                "delete_customer_record": _tool_entry(
                    rules=rules, status_operation=status_operation
                )
            },
        },
        _pem(private),
        bundle_id="bundle-e2e",
        tenant=TENANT,
        issued_at=_timestamp(timedelta(minutes=-1)),
        expires_at=_timestamp(timedelta(days=1)),
    )
    write_signed_policy_atomic(envelope, policy_path)
    public_path.write_bytes(_public_pem(private).encode("ascii"))
    trust_path.write_text(
        json.dumps({"keys": {"test-key": _public_pem(private)}}), encoding="utf-8"
    )
    return policy_path, public_path, trust_path


def _write_config(
    tmp_path: Path,
    *,
    upstream_port: int,
    gateway_port: int,
    policy_path: Path,
    public_path: Path,
    trust_path: Path,
    mode: str = "enforce",
    upstream_timeout_seconds: float = 5.0,
) -> Path:
    receipt_dir = tmp_path / "receipts"
    config_path = tmp_path / "gateway.toml"
    config_path.write_text(
        "\n".join(
            [
                "[gateway]",
                f"tenant = {json.dumps(TENANT)}",
                'gateway_id = "gw-e2e"',
                f"chain_id = {json.dumps(TENANT + '/gw-e2e')}",
                'writer_id = "writer-e2e"',
                'audience = "agentscan"',
                'trusted_issuer = "issuer-a"',
                'listen_host = "127.0.0.1"',
                f"listen_port = {gateway_port}",
                f'upstream_url = "http://127.0.0.1:{upstream_port}/mcp"',
                f"upstream_server_id = {json.dumps(SERVER_ID)}",
                f"upstream_credential_env = {json.dumps(CREDENTIAL_ENV)}",
                f"policy_bundle = {json.dumps(policy_path.as_posix())}",
                f"policy_public_key = {json.dumps(public_path.as_posix())}",
                f"trust_keys = {json.dumps(trust_path.as_posix())}",
                f"receipt_dir = {json.dumps(receipt_dir.as_posix())}",
                f'allowed_hosts = ["127.0.0.1:{gateway_port}"]',
                f'allowed_origins = ["http://127.0.0.1:{gateway_port}"]',
                f'mode = "{mode}"',
                f"upstream_timeout_seconds = {upstream_timeout_seconds}",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return config_path


def _token(private: Ed25519PrivateKey, *, role: str = "operator", tenant: str = TENANT) -> str:
    now = int(time.time())
    return jwt.encode(
        {
            "iss": "issuer-a",
            "sub": "principal-e2e",
            "aud": "agentscan",
            "exp": now + 600,
            "iat": now,
            "tenant": tenant,
            "agent": "agent-e2e",
            "role": role,
            "scope": ["delete_customer_record"],
        },
        private,
        algorithm="EdDSA",
        headers={"kid": "test-key"},
    )


def _listener() -> socket.socket:
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(128)
    return listener


async def _start_server(
    app: Any, listener: socket.socket
) -> tuple[uvicorn.Server, asyncio.Task[Any]]:
    server = uvicorn.Server(uvicorn.Config(app, log_level="critical", lifespan="on"))
    task = asyncio.create_task(server.serve(sockets=[listener]))
    for _ in range(300):
        if server.started:
            return server, task
        if task.done():
            raise RuntimeError("gateway server exited before startup")
        await asyncio.sleep(0.01)
    raise RuntimeError("gateway server did not start")


async def _stop_server(
    server: uvicorn.Server, task: asyncio.Task[Any], listener: socket.socket
) -> None:
    server.should_exit = True
    try:
        await asyncio.wait_for(task, timeout=5)
    except TimeoutError:
        task.cancel()
    listener.close()


@asynccontextmanager
async def _mock_upstream(*, crash_after_start: bool = False) -> AsyncIterator[int]:
    app = create_mock_upstream_app(
        MockUpstreamConfig(
            gateway_credential=CREDENTIAL,
            tenant=TENANT,
            crash_after_start=crash_after_start,
        )
    )
    listener = _listener()
    port = listener.getsockname()[1]
    server, task = await _start_server(app, listener)
    try:
        yield port
    finally:
        await _stop_server(server, task, listener)


@asynccontextmanager
async def _gateway_stack(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    mode: str = "enforce",
    rules: list[dict[str, Any]] | None = None,
    crash_after_start: bool = False,
) -> AsyncIterator[tuple[cli.GatewayService, httpx.AsyncClient, Ed25519PrivateKey, int]]:
    private = Ed25519PrivateKey.generate()
    policy_path, public_path, trust_path = _write_policy_and_trust(
        tmp_path,
        private,
        rules=rules if rules is not None else _default_rules(),
    )
    async with _mock_upstream(crash_after_start=crash_after_start) as upstream_port:
        listener = _listener()
        gateway_port = listener.getsockname()[1]
        config_path = _write_config(
            tmp_path,
            upstream_port=upstream_port,
            gateway_port=gateway_port,
            policy_path=policy_path,
            public_path=public_path,
            trust_path=trust_path,
            mode=mode,
        )
        monkeypatch.setenv(CREDENTIAL_ENV, CREDENTIAL)
        async with cli.open_gateway_service(config_path) as service:
            server, task = await _start_server(service.app, listener)
            client = httpx.AsyncClient(
                base_url=f"http://127.0.0.1:{gateway_port}",
                headers={
                    "Authorization": f"Bearer {_token(private)}",
                    "Accept": "application/json",
                },
                timeout=5,
            )
            try:
                yield service, client, private, gateway_port
            finally:
                await client.aclose()
                await _stop_server(server, task, listener)


@asynccontextmanager
async def _mcp_session(client: httpx.AsyncClient) -> AsyncIterator[ClientSession]:
    async with (
        streamable_http_client(str(client.base_url) + "/mcp", http_client=client) as (
            read_stream,
            write_stream,
            _get_session_id,
        ),
        ClientSession(read_stream, write_stream) as session,
    ):
        await session.initialize()
        yield session


def _decision(
    *,
    key_hash: str,
    request_hash: str,
    policy_hash: str,
    key_id: str,
) -> GatewayReceipt:
    return GatewayReceipt(
        trace_id="trace-reconcile-1",
        phase="decision",
        tenant_id=TENANT,
        gateway_id="gw-e2e",
        chain_id=f"{TENANT}/gw-e2e",
        writer_epoch=1,
        writer_id="writer-e2e",
        idempotency_key=key_hash,
        principal="principal-e2e",
        agent="agent-e2e",
        tool=ReceiptTool(
            name="delete_customer_record",
            server=SERVER_ID,
            schema_hash=tool_schema_hash(DELETE_SCHEMA),
            identity_hash="sha256:" + "a" * 64,
        ),
        arguments={"customer_id": "cust-1001"},
        arguments_hash=request_hash,
        authorization=ReceiptAuthorization(
            decision="allow",
            policy_id="policy-e2e",
            rule_id="allow-delete",
            resource_tenant_enforced="upstream",
            reason="allow_rule",
        ),
        policy_decision="allow",
        enforcement_mode="inline",
        effective_action="forwarded",
        would_deny=False,
        result=ReceiptResult(status="pending", summary="awaiting upstream outcome"),
        evidence=ReceiptEvidence(hash="", prev_hash=GENESIS_HASH),
        timestamp=utc_timestamp(datetime.now(UTC)),
        request_hash=request_hash,
        policy_hash=policy_hash,
        policy_key_id=key_id,
        decision_latency_ms=1.0,
        mcp_request_id="1",
    )


def _seed_pending(
    config_path: Path,
    *,
    raw_key: str,
    request_hash: str,
) -> None:
    from agentscan.gateway.config import load_config

    settings = load_config(config_path).gateway
    bundle = verify_policy_file(settings.policy_bundle, settings.policy_public_key)
    store = ReceiptChainStore(
        settings.receipt_dir,
        tenant=settings.tenant,
        gateway_id=settings.gateway_id,
        chain_id=settings.chain_id,
        writer_id=settings.writer_id,
    )
    store.acquire_writer_lease()
    try:
        store.append(
            _decision(
                key_hash=hash_key(raw_key, max_bytes=settings.max_idempotency_key_bytes),
                request_hash=request_hash,
                policy_hash=bundle.policy_hash,
                key_id=bundle.key_id,
            )
        )
    finally:
        store.close()


async def test_serve_allows_then_denies_and_records_receipts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async with _gateway_stack(tmp_path, monkeypatch) as (service, client, private, _port):
        async with _mcp_session(client) as session:
            allowed = await session.call_tool(
                "delete_customer_record",
                {"customer_id": "cust-1001"},
                meta={"agentscan.idempotency_key": RAW_KEY},
            )
            assert not allowed.isError
            assert allowed.content[0].text == "deleted cust-1001"

            replayed = await session.call_tool(
                "delete_customer_record",
                {"customer_id": "cust-1001"},
                meta={"agentscan.idempotency_key": RAW_KEY},
            )
            assert not replayed.isError
            assert replayed.content[0].text == "replayed outcome: success"
            assert len(service.store.receipts) == 2

        intern_client = httpx.AsyncClient(
            base_url=str(client.base_url),
            headers={
                "Authorization": f"Bearer {_token(private, role='intern')}",
                "Accept": "application/json",
            },
            timeout=5,
        )
        try:
            async with _mcp_session(intern_client) as session:
                with pytest.raises(McpError) as policy_denied:
                    await session.call_tool(
                        "delete_customer_record",
                        {"customer_id": "cust-1001"},
                        meta={"agentscan.idempotency_key": "deny-key"},
                    )
        finally:
            await intern_client.aclose()
        assert policy_denied.value.error.data["agentscan_code"] == "POLICY_DENIED"
        assert [receipt.result.status for receipt in service.store.receipts] == [
            "pending",
            "success",
            "denied",
        ]
        assert service.store.receipts[-1].authorization.reason == "explicit_deny"


async def test_serve_shadow_forwards_would_deny(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rules = [{"id": "deny-all", "decision": "deny"}]
    async with _gateway_stack(tmp_path, monkeypatch, mode="shadow", rules=rules) as (
        service,
        client,
        _private,
        _port,
    ):
        async with _mcp_session(client) as session:
            result = await session.call_tool(
                "delete_customer_record",
                {"customer_id": "cust-1001"},
                meta={"agentscan.idempotency_key": RAW_KEY},
            )
        assert not result.isError
        assert result.content[0].text == "deleted cust-1001"
        decision, outcome = service.store.receipts
        assert decision.enforcement_mode == "shadow"
        assert decision.would_deny is True
        assert decision.effective_action == "forwarded"
        assert decision.policy_decision == "deny"
        assert outcome.result.status == "success"


async def test_serve_rejects_cross_tenant_before_dispatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async with _gateway_stack(tmp_path, monkeypatch) as (service, client, private, _port):
        other = httpx.AsyncClient(
            base_url=str(client.base_url),
            headers={"Authorization": f"Bearer {_token(private, tenant='tenant-other')}"},
            timeout=5,
        )
        try:
            response = await other.post(
                "/mcp",
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-11-25",
                        "capabilities": {},
                        "clientInfo": {"name": "cross-tenant", "version": "1"},
                    },
                },
            )
        finally:
            await other.aclose()
        assert response.status_code in {401, 403}
        assert service.store.receipts == ()


async def test_startup_recovery_closes_pending_decision(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    private = Ed25519PrivateKey.generate()
    policy_path, public_path, trust_path = _write_policy_and_trust(
        tmp_path, private, rules=_default_rules()
    )
    async with _mock_upstream() as upstream_port:
        listener = _listener()
        gateway_port = listener.getsockname()[1]
        config_path = _write_config(
            tmp_path,
            upstream_port=upstream_port,
            gateway_port=gateway_port,
            policy_path=policy_path,
            public_path=public_path,
            trust_path=trust_path,
        )
        _seed_pending(config_path, raw_key=RAW_KEY, request_hash="sha256:" + "3" * 64)
        monkeypatch.setenv(CREDENTIAL_ENV, CREDENTIAL)
        async with cli.open_gateway_service(config_path) as service:
            assert [receipt.phase for receipt in service.store.receipts] == ["decision", "outcome"]
            assert service.store.receipts[-1].result.status == "unknown"
            assert service.store.receipts[-1].reconciliation is not None
        listener.close()


async def test_reconcile_cli_records_upstream_confirmation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    private = Ed25519PrivateKey.generate()
    policy_path, public_path, trust_path = _write_policy_and_trust(
        tmp_path, private, rules=_default_rules()
    )
    request_hash = "sha256:" + "4" * 64
    async with _mock_upstream(crash_after_start=True) as upstream_port:
        config_path = _write_config(
            tmp_path,
            upstream_port=upstream_port,
            gateway_port=1,
            policy_path=policy_path,
            public_path=public_path,
            trust_path=trust_path,
        )
        key_hash = hash_key(RAW_KEY, max_bytes=256)
        upstream = UpstreamClient(
            url=f"http://127.0.0.1:{upstream_port}/mcp",
            server_id=SERVER_ID,
            credential=CREDENTIAL,
            tenant=TENANT,
            timeout_seconds=5.0,
        )
        await upstream.start()
        try:
            failed = await upstream.call_tool(
                "delete_customer_record",
                {"customer_id": "cust-1001"},
                meta={"agentscan.key_hash": key_hash, "agentscan.request_hash": request_hash},
            )
            assert failed.isError
        finally:
            await upstream.aclose()
        _seed_pending(config_path, raw_key=RAW_KEY, request_hash=request_hash)
        monkeypatch.setenv(CREDENTIAL_ENV, CREDENTIAL)

        first = await cli.reconcile_gateway(config_path, idempotency_key=RAW_KEY)
        assert first.status == ReconciliationStatus.UNKNOWN
        assert first.appended is not None
        assert first.appended.result.status == "unknown"
        assert first.appended.reconciliation is not None
        assert first.appended.reconciliation["confirmation_id"].startswith("mock-")
        second = await cli.reconcile_gateway(config_path, idempotency_key=RAW_KEY)
        assert second.status == ReconciliationStatus.UNKNOWN
        assert second.appended is None


async def test_serve_missing_credential_fails_before_lease(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    private = Ed25519PrivateKey.generate()
    policy_path, public_path, trust_path = _write_policy_and_trust(
        tmp_path, private, rules=_default_rules()
    )
    config_path = _write_config(
        tmp_path,
        upstream_port=1,
        gateway_port=1,
        policy_path=policy_path,
        public_path=public_path,
        trust_path=trust_path,
    )
    monkeypatch.delenv(CREDENTIAL_ENV, raising=False)
    with pytest.raises(cli.GatewayCliError, match="missing upstream credential"):
        async with cli.open_gateway_service(config_path):
            pass
    from agentscan.gateway.config import load_config

    settings = load_config(config_path).gateway
    store = ReceiptChainStore(
        settings.receipt_dir,
        tenant=settings.tenant,
        gateway_id=settings.gateway_id,
        chain_id=settings.chain_id,
        writer_id=settings.writer_id,
    )
    store.acquire_writer_lease()
    store.close()


async def test_serve_upstream_start_failure_releases_lease(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    private = Ed25519PrivateKey.generate()
    policy_path, public_path, trust_path = _write_policy_and_trust(
        tmp_path, private, rules=_default_rules()
    )
    closed = _listener()
    closed_port = closed.getsockname()[1]
    closed.close()
    config_path = _write_config(
        tmp_path,
        upstream_port=closed_port,
        gateway_port=1,
        policy_path=policy_path,
        public_path=public_path,
        trust_path=trust_path,
        upstream_timeout_seconds=0.5,
    )
    monkeypatch.setenv(CREDENTIAL_ENV, CREDENTIAL)
    with pytest.raises(Exception, match="upstream"):
        async with cli.open_gateway_service(config_path):
            pass
    from agentscan.gateway.config import load_config

    settings = load_config(config_path).gateway
    store = ReceiptChainStore(
        settings.receipt_dir,
        tenant=settings.tenant,
        gateway_id=settings.gateway_id,
        chain_id=settings.chain_id,
        writer_id=settings.writer_id,
    )
    store.acquire_writer_lease()
    store.close()
