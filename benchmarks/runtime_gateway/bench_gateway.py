#!/usr/bin/env python3
"""Reproducible latency benchmark for the AgentScan runtime gateway.

Measures the three v1 latency budgets from docs/RUNTIME_GATEWAY.md section 13:

- policy decision p99, using ``evaluate_policy`` directly;
- durable decision-receipt append p99, using a real ``ReceiptChainStore``;
- end-to-end gateway overhead p99, using the real ``GatewayRuntime`` with an
  in-process fake upstream. The fake upstream's own handler time is measured
  and subtracted, so the reported overhead excludes upstream time.

The benchmark uses only local files, a loopback-free in-process fake, and fake
data. It never loads a signed bundle, reads credentials, or opens a socket.

Usage::

    python benchmarks/runtime_gateway/bench_gateway.py --samples 500
    python benchmarks/runtime_gateway/bench_gateway.py --out bench.json --json
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import math
import os
import platform
import statistics
import sys
import tempfile
import time
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from mcp.types import CallToolResult, TextContent, Tool

from agentscan.gateway.catalog import ToolCatalog, tool_schema_hash
from agentscan.gateway.config import GatewaySettings
from agentscan.gateway.idempotency import IdempotencyIndex
from agentscan.gateway.identity import VerifiedIdentity
from agentscan.gateway.policy import Policy, VerifiedPolicyBundle, evaluate_policy, validate_policy
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
from agentscan.gateway.runtime import GatewayRuntime
from agentscan.gateway.server import GatewayRequestContext
from agentscan.gateway.sessions import PINNED_PROTOCOL_VERSION, SessionRecord

TENANT = "tenant-bench"
SERVER_ID = "crm-mcp"
TOOL_NAME = "delete_customer_record"
PRINCIPAL = "user:bench"
AGENT = "agent:bench"
POLICY_ID = "bench-policy"
POLICY_HASH = "sha256:" + "a" * 64
POLICY_KEY_ID = "ed25519:" + "b" * 64
IDENTITY_HASH = "sha256:" + "c" * 64

DELETE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {"customer_id": {"type": "string"}},
}

POLICY_DOCUMENT: dict[str, Any] = {
    "version": 1,
    "policy_id": POLICY_ID,
    "tenant": TENANT,
    "default": "deny",
    "tools": {
        TOOL_NAME: {
            "server": SERVER_ID,
            "risk": "high",
            "enforcement": "inline",
            "resource_tenant_enforced": "upstream",
            "schema_hash": tool_schema_hash(DELETE_SCHEMA),
            "status_operation": "check_effect",
            "rules": [
                {
                    "id": "allow-operator",
                    "principal_role": "operator",
                    "tenant_match": True,
                    "arguments": {"customer_id": {"pattern": "^cust-[0-9]{4}$"}},
                    "decision": "allow",
                },
                {
                    "id": "deny-intern",
                    "principal_role": "intern",
                    "decision": "deny",
                },
            ],
        }
    },
}

# Budgets from docs/RUNTIME_GATEWAY.md section 13. They are strict p99 bounds.
POLICY_P99_BUDGET_MS = 10.0
DECISION_APPEND_P99_BUDGET_MS = 20.0
GATEWAY_OVERHEAD_P99_BUDGET_MS = 40.0
GATEWAY_P50_TARGET_MS = 2.0


def percentile(sorted_values: Sequence[float], quantile: float) -> float:
    """Nearest-rank percentile over an already sorted sequence."""
    if not sorted_values:
        return 0.0
    if not 0.0 <= quantile <= 1.0:
        raise ValueError("quantile must be between 0 and 1")
    index = max(0, math.ceil(quantile * len(sorted_values)) - 1)
    return sorted_values[min(index, len(sorted_values) - 1)]


def summarize(samples_ns: Sequence[int], budget_ms: float) -> dict[str, Any]:
    """Convert raw nanosecond samples into a reported latency summary."""
    samples_ms = sorted(value / 1_000_000.0 for value in samples_ns)
    p50 = percentile(samples_ms, 0.50)
    p99 = percentile(samples_ms, 0.99)
    return {
        "count": len(samples_ms),
        "p50_ms": round(p50, 4),
        "p99_ms": round(p99, 4),
        "mean_ms": round(statistics.fmean(samples_ms), 4) if samples_ms else 0.0,
        "max_ms": round(samples_ms[-1], 4) if samples_ms else 0.0,
        "budget_ms": budget_ms,
        "within_budget": bool(samples_ms) and p99 < budget_ms,
        "raw_ms": [round(value, 6) for value in samples_ms],
    }


def host_profile() -> dict[str, Any]:
    uname = platform.uname()
    return {
        "platform": platform.platform(),
        "system": uname.system,
        "release": uname.release,
        "machine": uname.machine,
        "processor": uname.processor or platform.processor() or "unknown",
        "cpu_count": os.cpu_count(),
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "pid": os.getpid(),
    }


def make_settings(receipt_dir: Path) -> GatewaySettings:
    return GatewaySettings.model_validate(
        {
            "tenant": TENANT,
            "gateway_id": "gw-bench",
            "chain_id": "tenant-bench/gw-bench",
            "writer_id": "writer-bench",
            "audience": "agentscan-bench",
            "trusted_issuer": "issuer-bench",
            "listen_host": "127.0.0.1",
            "listen_port": 8765,
            "upstream_url": "http://127.0.0.1:9",
            "upstream_server_id": SERVER_ID,
            "upstream_credential_env": "AGENTSCAN_BENCH_UNUSED_TOKEN",
            "policy_bundle": "unused-policy-bundle.yaml",
            "policy_public_key": "unused-policy-public.pem",
            "trust_keys": "unused-trust-keys.json",
            "receipt_dir": str(receipt_dir),
        }
    )


def make_policy() -> Policy:
    return validate_policy(POLICY_DOCUMENT)


def make_bundle() -> VerifiedPolicyBundle:
    return VerifiedPolicyBundle(
        envelope={
            "expires_at": (datetime.now(UTC) + timedelta(days=1)).isoformat(),
        },
        policy=make_policy(),
        policy_hash=POLICY_HASH,
        key_id=POLICY_KEY_ID,
    )


def delete_tool() -> Tool:
    return Tool(name=TOOL_NAME, description="benchmark fake delete", inputSchema=DELETE_SCHEMA)


def make_store(receipt_dir: Path, settings: GatewaySettings) -> ReceiptChainStore:
    store = ReceiptChainStore(
        receipt_dir,
        tenant=settings.tenant,
        gateway_id=settings.gateway_id,
        chain_id=settings.chain_id,
        writer_id=settings.writer_id,
    )
    store.acquire_writer_lease()
    return store


def _digest(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def make_decision_receipt(index: int, settings: GatewaySettings) -> GatewayReceipt:
    customer_id = f"cust-{index % 9000 + 1000:04d}"
    return GatewayReceipt(
        trace_id=f"bench-decision-{index}",
        phase="decision",
        tenant_id=settings.tenant,
        gateway_id=settings.gateway_id,
        chain_id=settings.chain_id,
        writer_epoch=1,
        writer_id=settings.writer_id,
        idempotency_key=_digest(f"bench-key-{index}"),
        principal=PRINCIPAL,
        agent=AGENT,
        tool=ReceiptTool(
            name=TOOL_NAME,
            server=SERVER_ID,
            schema_hash=tool_schema_hash(DELETE_SCHEMA),
            identity_hash=IDENTITY_HASH,
        ),
        arguments={"customer_id": customer_id},
        arguments_hash=_digest(f"arguments-{index}"),
        authorization=ReceiptAuthorization(
            decision="allow",
            policy_id=POLICY_ID,
            rule_id="allow-operator",
            resource_tenant_enforced="upstream",
            reason="allow_rule",
        ),
        policy_decision="allow",
        enforcement_mode="inline",
        effective_action="forwarded",
        would_deny=False,
        result=ReceiptResult(status="pending", summary="awaiting upstream outcome"),
        evidence=ReceiptEvidence(hash="", prev_hash=GENESIS_HASH),
        timestamp=utc_timestamp(),
        request_hash=_digest(f"request-{index}"),
        policy_hash=POLICY_HASH,
        policy_key_id=POLICY_KEY_ID,
        decision_latency_ms=0.0,
        mcp_request_id=f"bench-{index}",
    )


def measure_policy(policy: Policy, samples: int, warmup: int) -> list[int]:
    """Time evaluate_policy with no I/O or mutation."""
    role = "operator"
    arguments = {"customer_id": "cust-1001"}
    for _ in range(warmup):
        evaluate_policy(policy, TOOL_NAME, role=role, tenant=TENANT, arguments=arguments)
    timings: list[int] = []
    for _ in range(samples):
        started = time.perf_counter_ns()
        decision = evaluate_policy(policy, TOOL_NAME, role=role, tenant=TENANT, arguments=arguments)
        timings.append(time.perf_counter_ns() - started)
        if decision.decision != "allow":
            raise RuntimeError("benchmark policy did not allow the expected call")
    return timings


def measure_decision_append(
    settings: GatewaySettings, receipt_dir: Path, samples: int, warmup: int
) -> list[int]:
    """Time durable decision-receipt appends through the real JSONL/WAL store."""
    store = make_store(receipt_dir, settings)
    try:
        for index in range(warmup):
            store.append(make_decision_receipt(index, settings))
        timings: list[int] = []
        for index in range(warmup, warmup + samples):
            receipt = make_decision_receipt(index, settings)
            started = time.perf_counter_ns()
            store.append(receipt)
            timings.append(time.perf_counter_ns() - started)
        verification = store.verify()
        if verification.head_hash != store.head_hash:
            raise RuntimeError("decision-receipt benchmark chain did not verify")
        if len(verification.receipts) != warmup + samples:
            raise RuntimeError("decision-receipt benchmark lost receipts")
        return timings
    finally:
        store.close()


class InProcessUpstream:
    """Minimal upstream port that records its own handler time."""

    def __init__(self) -> None:
        self.calls = 0
        self.service_ns: list[int] = []

    async def list_tools(self) -> tuple[Tool, ...]:
        return (delete_tool(),)

    async def call_tool(
        self,
        name: str,
        arguments: Mapping[str, Any],
        *,
        meta: Mapping[str, Any] | None = None,
        timeout_seconds: float | None = None,
    ) -> CallToolResult:
        started = time.perf_counter_ns()
        self.calls += 1
        if name != TOOL_NAME or meta is None:
            raise RuntimeError("benchmark fake upstream received an unexpected call")
        result = CallToolResult(content=[TextContent(type="text", text="ok")])
        self.service_ns.append(time.perf_counter_ns() - started)
        return result


def make_identity() -> VerifiedIdentity:
    return VerifiedIdentity(
        principal=PRINCIPAL,
        agent=AGENT,
        tenant=TENANT,
        role="operator",
        scope=(TOOL_NAME,),
        token_scope=(TOOL_NAME,),
        delegation_chain=(),
        issuer="issuer-bench",
        audience="agentscan-bench",
        expires_at=9999999999,
        issued_at=0,
        session_identity_hash="sha256:" + "d" * 64,
    )


def make_session(identity: VerifiedIdentity) -> SessionRecord:
    return SessionRecord(
        session_id="bench-session",
        principal=identity.principal,
        agent=identity.agent,
        tenant=identity.tenant,
        role=identity.role,
        delegation_chain=(),
        session_identity_hash=identity.session_identity_hash,
        client_name="benchmark",
        client_version="1",
        protocol_version=PINNED_PROTOCOL_VERSION,
        token_expires_at=identity.expires_at,
        created_at=0.0,
        last_seen_at=0.0,
    )


async def measure_gateway_overhead(
    settings: GatewaySettings,
    bundle: VerifiedPolicyBundle,
    receipt_dir: Path,
    samples: int,
    warmup: int,
) -> tuple[list[int], dict[str, Any]]:
    """Time GatewayRuntime.call_tool minus the fake upstream's own service time."""
    store = make_store(receipt_dir, settings)
    upstream = InProcessUpstream()
    try:
        catalog = ToolCatalog(SERVER_ID)
        catalog.replace((delete_tool(),))
        runtime = GatewayRuntime(
            settings=settings,
            bundle=bundle,
            store=store,
            index=IdempotencyIndex(),
            upstream=upstream,
            catalog=catalog,
        )
        identity = make_identity()
        session = make_session(identity)

        async def call(index: int) -> tuple[int, int]:
            context = GatewayRequestContext(
                trace_id=f"bench-trace-{index}",
                request_id=str(index),
                method="tools/call",
                identity=identity,
                session=session,
                protocol_version=PINNED_PROTOCOL_VERSION,
            )
            started = time.perf_counter_ns()
            await runtime.call_tool(
                context,
                TOOL_NAME,
                {"customer_id": f"cust-{index % 9000 + 1000:04d}"},
                meta={"agentscan.idempotency_key": f"bench-key-{index}"},
            )
            total = time.perf_counter_ns() - started
            return total, upstream.service_ns[-1]

        for index in range(warmup):
            await call(index)
        overhead: list[int] = []
        for index in range(warmup, warmup + samples):
            total, service = await call(index)
            overhead.append(max(total - service, 0))
        verification = store.verify()
        if verification.head_hash != store.head_hash:
            raise RuntimeError("gateway benchmark chain did not verify")
        expected_receipts = 2 * (warmup + samples)
        if len(store.receipts) != expected_receipts:
            raise RuntimeError("gateway benchmark lost receipts")
        return overhead, {
            "chain_verified": True,
            "receipts": len(store.receipts),
            "expected_receipts": expected_receipts,
            "upstream_calls": upstream.calls,
        }
    finally:
        store.close()


def build_report(args: argparse.Namespace, receipt_dir: Path) -> dict[str, Any]:
    settings = make_settings(receipt_dir)
    policy = make_policy()
    policy_timings = measure_policy(policy, args.policy_samples, args.warmup)
    append_timings = measure_decision_append(
        settings, receipt_dir / "append", args.samples, args.warmup
    )
    gateway_timings, gateway_verification = asyncio.run(
        measure_gateway_overhead(
            settings, make_bundle(), receipt_dir / "runtime", args.samples, args.warmup
        )
    )
    results = {
        "policy_decision": summarize(policy_timings, POLICY_P99_BUDGET_MS),
        "decision_receipt_append": summarize(append_timings, DECISION_APPEND_P99_BUDGET_MS),
        "gateway_overhead": summarize(gateway_timings, GATEWAY_OVERHEAD_P99_BUDGET_MS),
    }
    all_within_budget = all(result["within_budget"] for result in results.values())
    return {
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "command": " ".join([sys.executable, *sys.argv]),
        "host": host_profile(),
        "settings": {
            "policy_samples": args.policy_samples,
            "append_samples": args.samples,
            "gateway_samples": args.samples,
            "warmup_per_metric": args.warmup,
            "tenant": TENANT,
            "tool": TOOL_NAME,
            "receipt_dir": "<temporary directory>",
        },
        "budgets_ms": {
            "policy_p50_target": GATEWAY_P50_TARGET_MS,
            "policy_p99": POLICY_P99_BUDGET_MS,
            "decision_receipt_append_p99": DECISION_APPEND_P99_BUDGET_MS,
            "gateway_overhead_p99": GATEWAY_OVERHEAD_P99_BUDGET_MS,
        },
        "results": results,
        "verification": {
            "policy_calls_allowed": results["policy_decision"]["count"],
            "decision_chain_verified": True,
            "decision_receipts": results["decision_receipt_append"]["count"] + args.warmup,
            **gateway_verification,
        },
        "all_within_budget": all_within_budget,
    }


def print_summary(report: dict[str, Any], output_path: Path | None) -> None:
    host = report["host"]
    settings = report["settings"]
    print("AgentScan runtime gateway benchmark")
    print(
        f"host: {host['platform']} | {host['machine']} | "
        f"{host['cpu_count']} cpus | Python {host['python_version']}"
    )
    print(
        f"samples: policy={settings['policy_samples']} "
        f"append={settings['append_samples']} gateway={settings['gateway_samples']} "
        f"(warmup={settings['warmup_per_metric']})"
    )
    print()
    header = f"{'metric':<26}{'p50 ms':>10}{'p99 ms':>10}{'mean ms':>10}{'max ms':>10}{'budget':>9}  result"
    print(header)
    print("-" * len(header))
    for name, result in report["results"].items():
        verdict = "PASS" if result["within_budget"] else "FAIL"
        print(
            f"{name:<26}{result['p50_ms']:>10.3f}{result['p99_ms']:>10.3f}"
            f"{result['mean_ms']:>10.3f}{result['max_ms']:>10.3f}"
            f"{result['budget_ms']:>9.1f}  {verdict}"
        )
    verification = report["verification"]
    print()
    print(
        "chains: decision receipts="
        f"{verification['decision_receipts']} verified={verification['decision_chain_verified']}; "
        f"gateway receipts={verification['receipts']} "
        f"verified={verification['chain_verified']}"
    )
    print(f"overall: {'PASS' if report['all_within_budget'] else 'FAIL'}")
    if output_path is not None:
        print(f"wrote: {output_path}")


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Benchmark AgentScan runtime gateway latency.")
    parser.add_argument(
        "--samples",
        type=int,
        default=500,
        help="samples for the durable append and gateway-overhead measurements",
    )
    parser.add_argument(
        "--policy-samples",
        type=int,
        default=5000,
        help="samples for the in-memory policy decision measurement",
    )
    parser.add_argument("--warmup", type=int, default=50, help="discarded warm-up calls per metric")
    parser.add_argument("--out", type=Path, default=None, help="write the full JSON report here")
    parser.add_argument("--json", action="store_true", help="print the full JSON report to stdout")
    parser.add_argument(
        "--receipt-dir",
        type=Path,
        default=None,
        help="receipt directory to use instead of a temporary directory",
    )
    args = parser.parse_args(argv)
    if args.samples < 1 or args.policy_samples < 1 or args.warmup < 0:
        parser.error("samples and policy-samples must be positive; warmup must be non-negative")
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    temporary: tempfile.TemporaryDirectory[str] | None = None
    if args.receipt_dir is None:
        temporary = tempfile.TemporaryDirectory(prefix="agentscan-gw-bench-")
        receipt_dir = Path(temporary.name)
    else:
        receipt_dir = args.receipt_dir
        receipt_dir.mkdir(parents=True, exist_ok=True)
    try:
        report = build_report(args, receipt_dir)
        if args.out is not None:
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        if args.json:
            print(json.dumps(report, indent=2))
        else:
            print_summary(report, args.out)
        return 0 if report["all_within_budget"] else 1
    finally:
        if temporary is not None:
            temporary.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
