"""Phase 5 slice 2 tests: GatewayRuntime dispatch through policy and receipts."""

from __future__ import annotations

import asyncio
import itertools
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from mcp.types import CallToolResult, TextContent, Tool

import agentscan.gateway.runtime as runtime_module
from agentscan.gateway.catalog import ToolCatalog, tool_schema_hash
from agentscan.gateway.config import GatewaySettings
from agentscan.gateway.errors import GatewayError
from agentscan.gateway.idempotency import (
    IdempotencyIndex,
    IdempotencyState,
    hash_key,
    pair_receipts,
)
from agentscan.gateway.identity import VerifiedIdentity
from agentscan.gateway.models import ErrorCode
from agentscan.gateway.policy import VerifiedPolicyBundle, validate_policy
from agentscan.gateway.receipts import ReceiptChainStore, verify_jsonl_file
from agentscan.gateway.runtime import GatewayRuntime
from agentscan.gateway.server import GatewayRequestContext
from agentscan.gateway.sessions import PINNED_PROTOCOL_VERSION, SessionRecord
from agentscan.gateway.upstream import UpstreamTimeout, UpstreamUnavailable

TENANT = "tenant-a"
CANARY = "canary-secret-value"

DELETE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {"customer_id": {"type": "string"}},
}
READ_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {"record_id": {"type": "string"}},
}

_TRACE_IDS = itertools.count(1)


def next_trace_id() -> str:
    return f"trace-{next(_TRACE_IDS)}"


def make_settings(*, mode: str = "enforce") -> GatewaySettings:
    return GatewaySettings.model_validate(
        {
            "tenant": TENANT,
            "gateway_id": "gw",
            "chain_id": "tenant-a/gw",
            "writer_id": "writer-1",
            "audience": "agentscan",
            "trusted_issuer": "issuer-a",
            "listen_host": "127.0.0.1",
            "listen_port": 8765,
            "upstream_url": "http://127.0.0.1:9999",
            "upstream_server_id": "crm-mcp",
            "upstream_credential_env": "FAKE_TOKEN",
            "policy_bundle": "policy.yaml",
            "policy_public_key": "policy.pub",
            "trust_keys": "trust.json",
            "receipt_dir": "receipts",
            "mode": mode,
        }
    )


def delete_entry(
    *,
    schema_hash: str | None = None,
    rules: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "server": "crm-mcp",
        "risk": "high",
        "enforcement": "inline",
        "resource_tenant_enforced": "upstream",
        "schema_hash": schema_hash or tool_schema_hash(DELETE_SCHEMA),
        "rules": rules
        if rules is not None
        else [
            {
                "id": "allow-delete",
                "principal_role": "operator",
                "tenant_match": True,
                "arguments": {"customer_id": {"pattern": r"^cust-[0-9]+$"}},
                "decision": "allow",
            }
        ],
    }


def read_entry() -> dict[str, Any]:
    return {
        "server": "crm-mcp",
        "risk": "low",
        "enforcement": "observe",
        "schema_hash": tool_schema_hash(READ_SCHEMA),
        "rules": [
            {
                "id": "deny-read",
                "arguments": {"record_id": {"pattern": ".*"}},
                "decision": "deny",
            }
        ],
    }


def make_bundle(
    entries: dict[str, dict[str, Any]],
    *,
    expires_at: str | None = None,
    tenant: str = TENANT,
) -> VerifiedPolicyBundle:
    policy = validate_policy(
        {
            "version": 1,
            "policy_id": "policy-1",
            "tenant": tenant,
            "default": "deny",
            "tools": entries,
        }
    )
    return VerifiedPolicyBundle(
        envelope={
            "expires_at": expires_at or (datetime.now(UTC) + timedelta(days=1)).isoformat(),
        },
        policy=policy,
        policy_hash="sha256:" + "b" * 64,
        key_id="ed25519:" + "c" * 64,
    )


def delete_tool() -> Tool:
    return Tool(name="delete_customer_record", description="delete", inputSchema=DELETE_SCHEMA)


def read_tool() -> Tool:
    return Tool(name="read_record", description="read", inputSchema=READ_SCHEMA)


class FakeUpstream:
    def __init__(
        self,
        tools: tuple[Tool, ...] = (),
        *,
        list_error: Exception | None = None,
        call_error: Exception | None = None,
        call_result: CallToolResult | None = None,
        gate: asyncio.Event | None = None,
    ) -> None:
        self.tools = tools
        self.list_error = list_error
        self.call_error = call_error
        self.call_result = call_result
        self.gate = gate
        self.list_calls = 0
        self.calls: list[dict[str, Any]] = []

    async def list_tools(self) -> tuple[Tool, ...]:
        self.list_calls += 1
        if self.list_error is not None:
            raise self.list_error
        return self.tools

    async def call_tool(
        self,
        name: str,
        arguments: Mapping[str, Any],
        *,
        meta: Mapping[str, Any] | None = None,
        timeout_seconds: float | None = None,
    ) -> CallToolResult:
        self.calls.append(
            {
                "name": name,
                "arguments": dict(arguments),
                "meta": dict(meta) if meta is not None else None,
                "timeout_seconds": timeout_seconds,
            }
        )
        if self.gate is not None:
            await self.gate.wait()
        if self.call_error is not None:
            raise self.call_error
        if self.call_result is not None:
            return self.call_result
        return CallToolResult(content=[TextContent(type="text", text="ok")])


def make_runtime(
    tmp_path,
    entries: dict[str, dict[str, Any]],
    tools: tuple[Tool, ...],
    *,
    mode: str = "enforce",
    upstream: FakeUpstream | None = None,
    expires_at: str | None = None,
    tenant: str = TENANT,
) -> tuple[GatewayRuntime, FakeUpstream, ReceiptChainStore]:
    settings = make_settings(mode=mode)
    store = ReceiptChainStore(
        tmp_path,
        tenant=TENANT,
        gateway_id=settings.gateway_id,
        chain_id=settings.chain_id,
        writer_id=settings.writer_id,
    )
    store.acquire_writer_lease()
    fake = upstream if upstream is not None else FakeUpstream(tools)
    runtime = GatewayRuntime(
        settings=settings,
        bundle=make_bundle(entries, expires_at=expires_at, tenant=tenant),
        store=store,
        index=IdempotencyIndex(),
        upstream=fake,
        catalog=ToolCatalog("crm-mcp"),
    )
    return runtime, fake, store


def make_identity(
    *,
    tenant: str = TENANT,
    principal: str = "user:123",
    agent: str = "agent:support",
    role: str = "operator",
) -> VerifiedIdentity:
    scope = ("delete_customer_record", "read_record")
    return VerifiedIdentity(
        principal=principal,
        agent=agent,
        tenant=tenant,
        role=role,
        scope=scope,
        token_scope=scope,
        delegation_chain=(),
        issuer="issuer-a",
        audience="agentscan",
        expires_at=9999999999,
        issued_at=0,
        session_identity_hash="sha256:" + "a" * 64,
    )


def make_session(identity: VerifiedIdentity) -> SessionRecord:
    return SessionRecord(
        session_id="session-1",
        principal=identity.principal,
        agent=identity.agent,
        tenant=identity.tenant,
        role=identity.role,
        delegation_chain=(),
        session_identity_hash=identity.session_identity_hash,
        client_name=None,
        client_version=None,
        protocol_version=PINNED_PROTOCOL_VERSION,
        token_expires_at=identity.expires_at,
        created_at=0.0,
        last_seen_at=0.0,
    )


def make_context(identity: VerifiedIdentity, trace_id: str | None = None) -> GatewayRequestContext:
    return GatewayRequestContext(
        trace_id=trace_id or next_trace_id(),
        request_id="1",
        method="tools/call",
        identity=identity,
        session=make_session(identity),
        protocol_version=PINNED_PROTOCOL_VERSION,
    )


def key_meta(raw_key: str) -> dict[str, str]:
    return {"agentscan.idempotency_key": raw_key}


async def test_allow_inline_records_pending_and_success_and_replays(tmp_path) -> None:
    runtime, fake, store = make_runtime(
        tmp_path, {"delete_customer_record": delete_entry()}, (delete_tool(),)
    )
    identity = make_identity()
    arguments = {"customer_id": "cust-1001", "token": CANARY}
    result = await runtime.call_tool(
        make_context(identity), "delete_customer_record", arguments, meta=key_meta("retry-1")
    )
    assert not result.isError
    assert len(fake.calls) == 1
    sent_meta = fake.calls[0]["meta"]
    assert sent_meta is not None
    assert set(sent_meta) == {"agentscan.key_hash", "agentscan.request_hash"}
    assert sent_meta["agentscan.key_hash"] == hash_key("retry-1", max_bytes=256)

    decision, outcome = store.receipts
    assert decision.phase == "decision" and outcome.phase == "outcome"
    assert decision.result.status == "pending"
    assert decision.idempotency_key == hash_key("retry-1", max_bytes=256)
    assert decision.tool.name == "delete_customer_record"
    assert decision.tool.server == "crm-mcp"
    assert decision.tool.schema_hash == tool_schema_hash(DELETE_SCHEMA)
    assert decision.authorization.decision == "allow"
    assert decision.authorization.reason == "allow_rule"
    assert decision.enforcement_mode == "inline"
    assert decision.effective_action == "forwarded"
    assert decision.would_deny is False
    assert decision.arguments["token"] == "[REDACTED]"
    assert outcome.result.status == "success"
    assert outcome.response_hash is not None

    pairs = pair_receipts(store.receipts)
    assert [pair.state for pair in pairs] == [IdempotencyState.SUCCESS]
    assert verify_jsonl_file(store.chain_path).receipts == store.receipts
    assert CANARY.encode() not in store.chain_path.read_bytes()

    replayed = await runtime.call_tool(
        make_context(identity), "delete_customer_record", arguments, meta=key_meta("retry-1")
    )
    assert not replayed.isError
    assert replayed.content[0].text == "replayed outcome: success"
    assert replayed.structuredContent == {"status": "success", "replayed": True}
    assert len(store.receipts) == 2
    assert len(fake.calls) == 1
    store.close()


async def test_deny_inline_blocks_with_single_denied_receipt(tmp_path) -> None:
    rules: list[dict[str, Any]] = [
        {"id": "deny-intern", "principal_role": "intern", "decision": "deny"},
        {
            "id": "allow-delete",
            "principal_role": "operator",
            "tenant_match": True,
            "arguments": {"customer_id": {"pattern": r"^cust-[0-9]+$"}},
            "decision": "allow",
        },
    ]
    runtime, fake, store = make_runtime(
        tmp_path, {"delete_customer_record": delete_entry(rules=rules)}, (delete_tool(),)
    )
    with pytest.raises(GatewayError) as exc:
        await runtime.call_tool(
            make_context(make_identity(role="intern")),
            "delete_customer_record",
            {"customer_id": "cust-1001"},
            meta=key_meta("retry-1"),
        )
    assert exc.value.code == ErrorCode.POLICY_DENIED
    assert exc.value.http_status == 403
    assert fake.calls == []
    (denied,) = store.receipts
    assert denied.result.status == "denied"
    assert denied.authorization.decision == "deny"
    assert denied.authorization.reason == "explicit_deny"
    assert denied.authorization.rule_id == "deny-intern"
    assert denied.policy_decision == "deny"
    assert denied.enforcement_mode == "inline"
    assert denied.effective_action == "blocked"
    assert denied.would_deny is True
    assert denied.idempotency_key is None
    assert verify_jsonl_file(store.chain_path).receipts == store.receipts
    store.close()


async def test_shadow_deny_is_forwarded_and_recorded(tmp_path) -> None:
    runtime, fake, store = make_runtime(
        tmp_path, {"read_record": read_entry()}, (read_tool(),), mode="shadow"
    )
    result = await runtime.call_tool(
        make_context(make_identity()), "read_record", {"record_id": "rec-1"}
    )
    assert not result.isError
    decision, outcome = store.receipts
    assert decision.result.status == "pending"
    assert decision.enforcement_mode == "shadow"
    assert decision.would_deny is True
    assert decision.effective_action == "forwarded"
    assert decision.authorization.decision == "deny"
    assert decision.idempotency_key is None
    assert outcome.result.status == "success"
    assert len(fake.calls) == 1
    assert fake.calls[0]["meta"] is None
    assert verify_jsonl_file(store.chain_path).receipts == store.receipts
    store.close()


async def test_observe_deny_is_forwarded(tmp_path) -> None:
    runtime, _fake, store = make_runtime(tmp_path, {"read_record": read_entry()}, (read_tool(),))
    result = await runtime.call_tool(
        make_context(make_identity()), "read_record", {"record_id": "rec-1"}
    )
    assert not result.isError
    decision, outcome = store.receipts
    assert decision.enforcement_mode == "observe"
    assert decision.effective_action == "forwarded"
    assert decision.would_deny is True
    assert decision.idempotency_key is None
    assert outcome.result.status == "success"
    store.close()


async def test_require_approval_blocks_even_in_shadow_mode(tmp_path) -> None:
    rules: list[dict[str, Any]] = [
        {
            "id": "require-bulk",
            "arguments": {"customer_id": {"pattern": ".*"}},
            "decision": "require_approval",
        },
        {
            "id": "allow-delete",
            "principal_role": "operator",
            "tenant_match": True,
            "arguments": {"customer_id": {"pattern": r"^cust-[0-9]+$"}},
            "decision": "allow",
        },
    ]
    runtime, fake, store = make_runtime(
        tmp_path,
        {"delete_customer_record": delete_entry(rules=rules)},
        (delete_tool(),),
        mode="shadow",
    )
    with pytest.raises(GatewayError) as exc:
        await runtime.call_tool(
            make_context(make_identity()),
            "delete_customer_record",
            {"customer_id": "cust-1001"},
            meta=key_meta("retry-1"),
        )
    assert exc.value.code == ErrorCode.APPROVAL_REQUIRED
    assert fake.calls == []
    (denied,) = store.receipts
    assert denied.result.status == "denied"
    assert denied.policy_decision == "require_approval"
    assert denied.authorization.decision == "deny"
    assert denied.effective_action == "blocked"
    assert denied.enforcement_mode == "shadow"
    store.close()


async def test_schema_drift_denies_without_dispatch(tmp_path) -> None:
    runtime, fake, store = make_runtime(
        tmp_path,
        {"delete_customer_record": delete_entry(schema_hash="sha256:" + "d" * 64)},
        (delete_tool(),),
    )
    with pytest.raises(GatewayError) as exc:
        await runtime.call_tool(
            make_context(make_identity()),
            "delete_customer_record",
            {"customer_id": "cust-1001"},
            meta=key_meta("retry-1"),
        )
    assert exc.value.code == ErrorCode.SCHEMA_DRIFT
    assert fake.calls == []
    (denied,) = store.receipts
    assert denied.result.status == "denied"
    assert denied.result.summary == "schema drift detected"
    assert denied.authorization.reason == "schema_drift"
    assert denied.idempotency_key is None
    assert denied.effective_action == "blocked"
    assert denied.would_deny is True
    store.close()


async def test_missing_catalog_tool_fails_closed_without_receipt(tmp_path) -> None:
    runtime, fake, store = make_runtime(
        tmp_path, {"delete_customer_record": delete_entry()}, (delete_tool(), read_tool())
    )
    with pytest.raises(GatewayError) as exc:
        await runtime.call_tool(make_context(make_identity()), "unknown_tool", {})
    assert exc.value.code == ErrorCode.GATEWAY_UNAVAILABLE
    assert fake.calls == []
    assert store.receipts == ()
    store.close()


async def test_high_risk_without_idempotency_key_is_denied(tmp_path) -> None:
    runtime, fake, store = make_runtime(
        tmp_path, {"delete_customer_record": delete_entry()}, (delete_tool(),)
    )
    with pytest.raises(GatewayError) as exc:
        await runtime.call_tool(
            make_context(make_identity()),
            "delete_customer_record",
            {"customer_id": "cust-1001"},
        )
    assert exc.value.code == ErrorCode.IDEMPOTENCY_REQUIRED
    assert fake.calls == []
    (denied,) = store.receipts
    assert denied.result.status == "denied"
    assert denied.idempotency_key is None
    assert denied.authorization.reason == "idempotency_required"
    assert denied.effective_action == "blocked"
    assert denied.would_deny is False
    store.close()


async def test_same_key_with_different_arguments_conflicts(tmp_path) -> None:
    runtime, fake, store = make_runtime(
        tmp_path, {"delete_customer_record": delete_entry()}, (delete_tool(),)
    )
    identity = make_identity()
    first = await runtime.call_tool(
        make_context(identity),
        "delete_customer_record",
        {"customer_id": "cust-1001"},
        meta=key_meta("retry-1"),
    )
    assert not first.isError
    with pytest.raises(GatewayError) as exc:
        await runtime.call_tool(
            make_context(identity),
            "delete_customer_record",
            {"customer_id": "cust-2002"},
            meta=key_meta("retry-1"),
        )
    assert exc.value.code == ErrorCode.IDEMPOTENCY_CONFLICT
    assert len(fake.calls) == 1
    assert len(store.receipts) == 2
    store.close()


async def test_new_key_with_same_content_while_pending_is_unknown(tmp_path) -> None:
    gate = asyncio.Event()
    upstream = FakeUpstream((delete_tool(),), gate=gate)
    runtime, fake, store = make_runtime(
        tmp_path, {"delete_customer_record": delete_entry()}, (), upstream=upstream
    )
    identity = make_identity()
    arguments = {"customer_id": "cust-1001"}
    pending_task = asyncio.create_task(
        runtime.call_tool(
            make_context(identity), "delete_customer_record", arguments, meta=key_meta("key-a")
        )
    )
    for _ in range(500):
        if len(store.receipts) == 1:
            break
        await asyncio.sleep(0.01)
    assert len(store.receipts) == 1
    with pytest.raises(GatewayError) as exc:
        await runtime.call_tool(
            make_context(identity), "delete_customer_record", arguments, meta=key_meta("key-b")
        )
    assert exc.value.code == ErrorCode.OUTCOME_UNKNOWN
    assert len(fake.calls) == 1
    assert len(store.receipts) == 1
    gate.set()
    result = await asyncio.wait_for(pending_task, 5)
    assert not result.isError
    assert len(store.receipts) == 2
    store.close()


async def test_timeout_records_timeout_outcome_and_tool_error(tmp_path) -> None:
    upstream = FakeUpstream((delete_tool(),), call_error=UpstreamTimeout())
    runtime, fake, store = make_runtime(
        tmp_path, {"delete_customer_record": delete_entry()}, (), upstream=upstream
    )
    result = await runtime.call_tool(
        make_context(make_identity()),
        "delete_customer_record",
        {"customer_id": "cust-1001"},
        meta=key_meta("retry-1"),
    )
    assert result.isError
    assert result.content[0].text == "TIMEOUT: upstream request timed out"
    assert len(fake.calls) == 1
    assert fake.calls[0]["timeout_seconds"] == 5.0
    _decision, outcome = store.receipts
    assert outcome.result.status == "timeout"
    assert outcome.response_hash is not None
    assert verify_jsonl_file(store.chain_path).receipts == store.receipts
    store.close()


async def test_upstream_error_result_is_sanitized(tmp_path) -> None:
    upstream = FakeUpstream(
        (delete_tool(),),
        call_result=CallToolResult(
            content=[TextContent(type="text", text="boom " + CANARY)], isError=True
        ),
    )
    runtime, fake, store = make_runtime(
        tmp_path, {"delete_customer_record": delete_entry()}, (), upstream=upstream
    )
    result = await runtime.call_tool(
        make_context(make_identity()),
        "delete_customer_record",
        {"customer_id": "cust-1001"},
        meta=key_meta("retry-1"),
    )
    assert result.isError
    assert result.content[0].text == "UPSTREAM_ERROR: upstream tool call failed"
    assert CANARY not in result.content[0].text
    assert len(fake.calls) == 1
    _decision, outcome = store.receipts
    assert outcome.result.status == "error"
    assert outcome.response_hash is not None
    assert CANARY.encode() not in store.chain_path.read_bytes()
    store.close()


async def test_unavailable_after_send_records_unknown_outcome(tmp_path) -> None:
    upstream = FakeUpstream((delete_tool(),), call_error=UpstreamUnavailable(may_have_sent=True))
    runtime, fake, store = make_runtime(
        tmp_path, {"delete_customer_record": delete_entry()}, (), upstream=upstream
    )
    result = await runtime.call_tool(
        make_context(make_identity()),
        "delete_customer_record",
        {"customer_id": "cust-1001"},
        meta=key_meta("retry-1"),
    )
    assert result.isError
    assert result.content[0].text == "OUTCOME_UNKNOWN: upstream effect could not be confirmed"
    assert len(fake.calls) == 1
    _decision, outcome = store.receipts
    assert outcome.result.status == "unknown"
    assert outcome.response_hash is None
    assert verify_jsonl_file(store.chain_path).receipts == store.receipts
    store.close()


async def test_outcome_append_fallback_surfaces_unknown_result(tmp_path, monkeypatch) -> None:
    runtime, fake, store = make_runtime(
        tmp_path, {"delete_customer_record": delete_entry()}, (delete_tool(),)
    )
    real_append = runtime_module.append_outcome
    attempts = 0

    def flaky_append(
        store_arg: ReceiptChainStore,
        decision: Any,
        *,
        status: Any,
        summary: Any,
        response_hash: Any,
        reconciliation: Any = None,
        now: Any = None,
    ) -> Any:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RuntimeError("simulated outcome append failure")
        return real_append(
            store_arg,
            decision,
            status=status,
            summary=summary,
            response_hash=response_hash,
            reconciliation=reconciliation,
            now=now,
        )

    monkeypatch.setattr(runtime_module, "append_outcome", flaky_append)
    result = await runtime.call_tool(
        make_context(make_identity()),
        "delete_customer_record",
        {"customer_id": "cust-1001"},
        meta=key_meta("retry-1"),
    )
    assert result.isError
    assert result.content[0].text == "OUTCOME_UNKNOWN: upstream effect could not be confirmed"
    assert attempts == 2
    assert len(fake.calls) == 1
    _decision, outcome = store.receipts
    assert outcome.result.status == "unknown"
    assert outcome.response_hash is None
    assert verify_jsonl_file(store.chain_path).receipts == store.receipts
    store.close()


async def test_sink_failure_short_circuits_later_calls(tmp_path, monkeypatch) -> None:
    runtime, fake, store = make_runtime(
        tmp_path, {"delete_customer_record": delete_entry()}, (delete_tool(),)
    )
    real_append = runtime_module.append_outcome

    def failing_append(*_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("simulated sink failure")

    monkeypatch.setattr(runtime_module, "append_outcome", failing_append)
    with pytest.raises(GatewayError) as exc:
        await runtime.call_tool(
            make_context(make_identity()),
            "delete_customer_record",
            {"customer_id": "cust-1001"},
            meta=key_meta("retry-1"),
        )
    assert exc.value.code == ErrorCode.GATEWAY_UNAVAILABLE
    assert len(fake.calls) == 1
    assert runtime.readiness().receipt_sink_healthy is False

    monkeypatch.setattr(runtime_module, "append_outcome", real_append)
    with pytest.raises(GatewayError) as blocked:
        await runtime.call_tool(
            make_context(make_identity()),
            "delete_customer_record",
            {"customer_id": "cust-1001"},
            meta=key_meta("retry-1"),
        )
    assert blocked.value.code == ErrorCode.GATEWAY_UNAVAILABLE
    assert len(fake.calls) == 1
    store.close()


async def test_schema_drift_preserves_observe_enforcement(tmp_path) -> None:
    entry = read_entry()
    entry["schema_hash"] = "sha256:" + "d" * 64
    runtime, fake, store = make_runtime(tmp_path, {"read_record": entry}, (read_tool(),))
    with pytest.raises(GatewayError) as exc:
        await runtime.call_tool(
            make_context(make_identity()), "read_record", {"record_id": "rec-1"}
        )
    assert exc.value.code == ErrorCode.SCHEMA_DRIFT
    assert fake.calls == []
    (denied,) = store.receipts
    assert denied.enforcement_mode == "observe"
    assert denied.authorization.reason == "schema_drift"
    store.close()


async def test_catalog_refresh_failure_denies_without_receipt(tmp_path) -> None:
    upstream = FakeUpstream((), list_error=UpstreamUnavailable())
    runtime, fake, store = make_runtime(
        tmp_path, {"delete_customer_record": delete_entry()}, (), upstream=upstream
    )
    with pytest.raises(GatewayError) as exc:
        await runtime.call_tool(
            make_context(make_identity()),
            "delete_customer_record",
            {"customer_id": "cust-1001"},
            meta=key_meta("retry-1"),
        )
    assert exc.value.code == ErrorCode.GATEWAY_UNAVAILABLE
    assert fake.calls == []
    assert fake.list_calls == 1
    assert store.receipts == ()
    store.close()


async def test_readiness_requires_healthy_policy_chain_and_catalog(tmp_path) -> None:
    runtime, _fake, store = make_runtime(
        tmp_path, {"delete_customer_record": delete_entry()}, (delete_tool(),)
    )
    identity = make_identity()
    listing = await runtime.list_tools(
        GatewayRequestContext(
            trace_id=next_trace_id(),
            request_id="1",
            method="tools/list",
            identity=identity,
            session=make_session(identity),
            protocol_version=PINNED_PROTOCOL_VERSION,
        )
    )
    assert [tool.name for tool in listing] == ["delete_customer_record"]
    ready = runtime.readiness()
    assert ready.issues() == ()
    assert ready.policy_loaded
    assert not ready.policy_expired
    assert ready.chain_verified
    assert ready.writer_lease_held
    assert ready.receipt_sink_healthy
    assert ready.upstream_catalog_loaded
    store.close()

    expired_runtime, _expired_fake, expired_store = make_runtime(
        tmp_path / "expired",
        {"delete_customer_record": delete_entry()},
        (delete_tool(),),
        expires_at=(datetime.now(UTC) - timedelta(days=1)).isoformat(),
    )
    assert "policy_expired" in expired_runtime.readiness().issues()
    expired_store.close()

    mismatched_runtime, _mismatched_fake, mismatched_store = make_runtime(
        tmp_path / "mismatched",
        {"delete_customer_record": delete_entry()},
        (delete_tool(),),
        tenant="tenant-b",
    )
    assert "policy_missing" in mismatched_runtime.readiness().issues()
    mismatched_store.close()

    released_runtime, _released_fake, released_store = make_runtime(
        tmp_path / "released", {"delete_customer_record": delete_entry()}, (delete_tool(),)
    )
    released_store.release_writer_lease()
    assert "writer_lease_missing" in released_runtime.readiness().issues()
    released_store.close()

    unloaded_runtime, _unloaded_fake, unloaded_store = make_runtime(
        tmp_path / "unloaded", {"delete_customer_record": delete_entry()}, (delete_tool(),)
    )
    assert "catalog_unavailable" in unloaded_runtime.readiness().issues()
    unloaded_store.close()

    unhealthy_runtime, _unhealthy_fake, unhealthy_store = make_runtime(
        tmp_path / "unhealthy", {"delete_customer_record": delete_entry()}, (delete_tool(),)
    )
    unhealthy_store._healthy = False
    assert "receipt_sink_unhealthy" in unhealthy_runtime.readiness().issues()
    unhealthy_store.close()


def test_runtime_rejects_store_scope_mismatch(tmp_path) -> None:
    settings = make_settings()
    store = ReceiptChainStore(
        tmp_path,
        tenant="tenant-other",
        gateway_id=settings.gateway_id,
        chain_id=settings.chain_id,
        writer_id=settings.writer_id,
    )
    store.acquire_writer_lease()
    try:
        with pytest.raises(ValueError, match="store scope does not match gateway settings"):
            GatewayRuntime(
                settings=settings,
                bundle=make_bundle({"delete_customer_record": delete_entry()}),
                store=store,
                index=IdempotencyIndex(),
                upstream=FakeUpstream((delete_tool(),)),
                catalog=ToolCatalog("crm-mcp"),
            )
    finally:
        store.close()
