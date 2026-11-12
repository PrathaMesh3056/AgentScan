"""Phase 5 slice 1 tests: upstream client, catalog, and mock upstream."""

from __future__ import annotations

import asyncio
import hashlib
import socket
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx
import pytest
import uvicorn
from mcp.types import CallToolResult, TextContent, Tool

from agentscan.gateway.catalog import (
    CatalogError,
    CatalogTool,
    ToolCatalog,
    tool_identity_hash,
    tool_schema_hash,
)
from agentscan.gateway.mock_upstream import (
    DEFAULT_TENANT,
    PUBLIC_TOOL,
    STATUS_TOOL,
    MockUpstreamConfig,
    MockUpstreamState,
    create_mock_upstream_app,
)
from agentscan.gateway.policy import validate_policy
from agentscan.gateway.upstream import (
    UpstreamClient,
    UpstreamProtocolError,
    UpstreamTimeout,
    UpstreamUnavailable,
)

GATEWAY_CREDENTIAL = "gw-secret-canary"
FAKE_AGENT_JWT = "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJhZ2VudC1hIn0.gw-canary-signature"
TENANT_HEADER = "X-AgentScan-Tenant"

DELETE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "customer_id": {"type": "string", "pattern": "^cust-[0-9]{4}$"},
    },
    "required": ["customer_id"],
    "additionalProperties": False,
}


def _hash_of(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _meta(key_hash: str, request_hash: str) -> dict[str, str]:
    return {"agentscan.key_hash": key_hash, "agentscan.request_hash": request_hash}


def _delete_tool(name: str = PUBLIC_TOOL, schema: dict[str, Any] | None = None) -> Tool:
    return Tool(
        name=name,
        description="Deletes a fake customer record; demo data only",
        inputSchema=DELETE_SCHEMA if schema is None else schema,
    )


@asynccontextmanager
async def _mock_server(
    config: MockUpstreamConfig,
) -> AsyncIterator[tuple[int, MockUpstreamState]]:
    app = create_mock_upstream_app(config)
    state = app.state.mock_state
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(128)
    port = listener.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, log_level="critical", lifespan="on"))
    task = asyncio.create_task(server.serve(sockets=[listener]))
    try:
        for _ in range(200):
            if server.started:
                break
            await asyncio.sleep(0.01)
        assert server.started
        yield port, state
    finally:
        server.should_exit = True
        try:
            await asyncio.wait_for(task, timeout=5)
        except TimeoutError:
            task.cancel()
        listener.close()


@asynccontextmanager
async def _started_client(
    port: int, *, timeout_seconds: float = 5.0, tenant: str = DEFAULT_TENANT
) -> AsyncIterator[UpstreamClient]:
    client = UpstreamClient(
        url=f"http://127.0.0.1:{port}/mcp",
        server_id="mock-crm",
        credential=GATEWAY_CREDENTIAL,
        tenant=tenant,
        timeout_seconds=timeout_seconds,
    )
    await client.start()
    try:
        yield client
    finally:
        await client.aclose()


# --- catalog: schema and identity hashes ------------------------------------


def test_tool_schema_hash_is_stable_and_sensitive() -> None:
    schema_a = {"type": "object", "properties": {"a": {"type": "string"}}}
    schema_b = {"properties": {"a": {"type": "string"}}, "type": "object"}
    first = tool_schema_hash(schema_a)
    assert first == tool_schema_hash(schema_b)
    assert first.startswith("sha256:")
    changed = {"type": "object", "properties": {"a": {"type": "integer"}}}
    assert tool_schema_hash(changed) != first


def test_tool_schema_hash_ignores_non_schema_metadata_and_rejects_bad_input() -> None:
    schema = {"type": "object"}
    assert tool_schema_hash(schema) == tool_schema_hash(dict(reversed(list(schema.items()))))
    with pytest.raises(CatalogError):
        tool_schema_hash("not-a-mapping")  # type: ignore[arg-type]
    with pytest.raises(CatalogError):
        tool_schema_hash({"amount": float("nan")})
    with pytest.raises(CatalogError):
        tool_schema_hash({"bad": {1, 2}})


def test_tool_identity_hash_binds_server_name_and_schema() -> None:
    base = tool_identity_hash("mock-crm", PUBLIC_TOOL, DELETE_SCHEMA)
    assert base == tool_identity_hash("mock-crm", PUBLIC_TOOL, DELETE_SCHEMA)
    assert base != tool_identity_hash("other-crm", PUBLIC_TOOL, DELETE_SCHEMA)
    assert base != tool_identity_hash("mock-crm", "other_tool", DELETE_SCHEMA)
    drifted = dict(DELETE_SCHEMA, required=["customer_id", "region"])
    assert base != tool_identity_hash("mock-crm", PUBLIC_TOOL, drifted)
    # Description is not part of identity: hashing takes no description input.
    assert base.startswith("sha256:")


# --- catalog: snapshot and policy checks ------------------------------------


def _policy_document(tools: dict[str, dict[str, Any]]) -> dict[str, Any]:
    return {
        "version": 1,
        "policy_id": "test-policy",
        "tenant": "tenant-demo",
        "default": "deny",
        "tools": tools,
    }


def _tool_entry(
    schema_hash: str,
    server: str = "mock-crm",
    arguments: dict[str, dict[str, str]] | None = None,
) -> dict[str, Any]:
    return {
        "server": server,
        "risk": "high",
        "enforcement": "inline",
        "resource_tenant_enforced": "upstream",
        "schema_hash": schema_hash,
        "rules": [
            {
                "id": "allow-fake",
                "decision": "allow",
                "arguments": arguments or {},
            }
        ],
    }


def test_tool_catalog_replace_is_atomic_and_rejects_duplicates() -> None:
    catalog = ToolCatalog("mock-crm")
    assert not catalog.loaded
    catalog.replace([_delete_tool()])
    assert catalog.loaded
    snapshot = catalog.entries
    assert len(snapshot) == 1
    assert isinstance(snapshot[0], CatalogTool)
    duplicated = [_delete_tool(), _delete_tool()]
    with pytest.raises(CatalogError):
        catalog.replace(duplicated)
    assert catalog.entries == snapshot
    assert catalog.loaded
    assert catalog.get(PUBLIC_TOOL) is snapshot[0]
    assert catalog.get("missing") is None
    fresh = ToolCatalog("mock-crm")
    with pytest.raises(CatalogError):
        fresh.replace([_delete_tool(), _delete_tool()])
    assert not fresh.loaded and fresh.entries == ()


def test_check_policy_detects_all_mismatch_kinds() -> None:
    catalog = ToolCatalog("mock-crm")
    catalog.replace(
        [
            _delete_tool(),
            Tool(
                name="audit_query",
                description="fake",
                inputSchema={"type": "object", "properties": {"region": {"type": "string"}}},
            ),
            Tool(
                name="report_export",
                description="fake",
                inputSchema={"type": "object", "properties": {"region": {"type": "string"}}},
            ),
        ]
    )
    schema_hash = catalog.entries[0].schema_hash
    audit_hash = catalog.entries[1].schema_hash
    report_hash = catalog.entries[2].schema_hash
    policy = validate_policy(
        _policy_document(
            {
                PUBLIC_TOOL: _tool_entry(schema_hash, arguments={"customer_id": {"pattern": "."}}),
                "wrong_server": _tool_entry(
                    schema_hash, server="other-crm", arguments={"x": {"pattern": "."}}
                ),
                "missing_tool": _tool_entry(schema_hash),
                "audit_query": _tool_entry(_hash_of("drifted-audit")),
                "report_export": _tool_entry(report_hash, arguments={"zone": {"pattern": "."}}),
            }
        )
    )
    del audit_hash
    mismatches = catalog.check_policy(policy)
    reasons = {(m.tool_name, m.reason) for m in mismatches}
    assert (PUBLIC_TOOL, "server_mismatch") not in reasons
    assert ("wrong_server", "server_mismatch") in reasons
    assert ("missing_tool", "missing_upstream") in reasons
    assert ("audit_query", "schema_drift") in reasons
    assert ("report_export", "rule_argument_missing") in reasons
    details = " ".join(m.detail for m in mismatches)
    assert "cust-" not in details and "http" not in details and "canary" not in details


def test_approved_tools_includes_only_exact_matches_in_catalog_order() -> None:
    catalog = ToolCatalog("mock-crm")
    good = _delete_tool()
    other = Tool(
        name="list_customers",
        description="fake",
        inputSchema={"type": "object", "properties": {"limit": {"type": "integer"}}},
    )
    export = Tool(
        name="report_export",
        description="fake",
        inputSchema={"type": "object", "properties": {"region": {"type": "string"}}},
    )
    catalog.replace([good, other, export])
    entries = catalog.entries
    policy = validate_policy(
        _policy_document(
            {
                PUBLIC_TOOL: _tool_entry(
                    entries[0].schema_hash, arguments={"customer_id": {"pattern": "."}}
                ),
                # Present upstream, but declared on another server: excluded.
                "list_customers": _tool_entry(entries[1].schema_hash, server="other-crm"),
                # Present upstream, correct server, drifted schema hash: excluded.
                "report_export": _tool_entry(_hash_of("drifted-export")),
                # Not upstream at all: cannot be approved.
                "missing_tool": _tool_entry(_hash_of("whatever")),
            }
        )
    )
    approved = catalog.approved_tools(policy)
    assert [tool.name for tool in approved] == [PUBLIC_TOOL]
    assert approved[0] is good


# --- mock upstream and upstream client --------------------------------------


@pytest.mark.asyncio
async def test_upstream_client_lists_and_calls_the_public_tool() -> None:
    key_hash = _hash_of("gw-key-canary-1")
    request_hash = _hash_of('{"customer_id":"cust-1001"}')
    async with _mock_server(MockUpstreamConfig(gateway_credential=GATEWAY_CREDENTIAL)) as (
        port,
        state,
    ):
        async with _started_client(port) as client:
            tools = await client.list_tools()
            assert [tool.name for tool in tools] == [PUBLIC_TOOL]
            assert STATUS_TOOL not in {tool.name for tool in tools}
            result = await client.call_tool(
                PUBLIC_TOOL,
                {"customer_id": "cust-1001"},
                meta=_meta(key_hash, request_hash),
            )
            assert isinstance(result, CallToolResult)
            assert result.isError is False
            assert any(
                isinstance(item, TextContent) and "deleted cust-1001" in item.text
                for item in result.content
            )
        statuses = [record.status for record in state.records]
        assert statuses == ["started", "success"]
        assert state.deleted == {"cust-1001"}


@pytest.mark.asyncio
async def test_mock_upstream_rejects_missing_and_agent_credentials() -> None:
    async with _mock_server(MockUpstreamConfig(gateway_credential=GATEWAY_CREDENTIAL)) as (
        port,
        _state,
    ):
        base = f"http://127.0.0.1:{port}"
        accept = {"Accept": "application/json, text/event-stream"}
        async with httpx.AsyncClient(base_url=base, timeout=5) as http:
            anonymous = await http.post(
                "/mcp",
                headers=accept,
                json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            )
            assert anonymous.status_code == 401
            assert anonymous.json() == {"error": "unauthorized"}
            assert GATEWAY_CREDENTIAL not in anonymous.text
            agent_token = httpx.AsyncClient(
                base_url=base,
                headers={
                    "Authorization": f"Bearer {FAKE_AGENT_JWT}",
                    TENANT_HEADER: DEFAULT_TENANT,
                },
                timeout=5,
            )
            try:
                rejected = await agent_token.post(
                    "/mcp",
                    headers=accept,
                    json={"jsonrpc": "2.0", "id": 2, "method": "initialize", "params": {}},
                )
                assert rejected.status_code == 401
                assert FAKE_AGENT_JWT not in rejected.text
            finally:
                await agent_token.aclose()
            gateway_client = httpx.AsyncClient(
                base_url=base,
                headers={
                    "Authorization": f"Bearer {GATEWAY_CREDENTIAL}",
                    TENANT_HEADER: DEFAULT_TENANT,
                },
                timeout=5,
            )
            try:
                accepted = await gateway_client.post(
                    "/mcp",
                    headers=accept,
                    json={
                        "jsonrpc": "2.0",
                        "id": 3,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2025-11-25",
                            "capabilities": {},
                            "clientInfo": {"name": "test", "version": "1"},
                        },
                    },
                )
                assert accepted.status_code == 200
                assert "result" in accepted.json()
                assert accepted.json()["result"]["protocolVersion"] == "2025-11-25"
            finally:
                await gateway_client.aclose()


@pytest.mark.asyncio
async def test_cross_tenant_delete_is_denied_and_recorded() -> None:
    key_hash = _hash_of("gw-key-canary-cross")
    request_hash = _hash_of('{"customer_id":"cust-2001"}')
    async with _mock_server(MockUpstreamConfig(gateway_credential=GATEWAY_CREDENTIAL)) as (
        port,
        state,
    ):
        async with _started_client(port) as client:
            result = await client.call_tool(
                PUBLIC_TOOL,
                {"customer_id": "cust-2001"},
                meta=_meta(key_hash, request_hash),
            )
        assert result.isError is True
        assert any(
            isinstance(item, TextContent) and "RESOURCE_TENANT_UNVERIFIED" in item.text
            for item in result.content
        )
        assert "cust-2001" not in state.deleted
        assert any(record.status == "denied" for record in state.records)
        assert not any(record.status in ("started", "success") for record in state.records)


@pytest.mark.asyncio
async def test_check_effect_statuses_and_conflict() -> None:
    key_hash = _hash_of("gw-key-canary-2")
    request_hash = _hash_of('{"customer_id":"cust-1002"}')
    other_request_hash = _hash_of('{"customer_id":"cust-1002-2"}')
    async with _mock_server(MockUpstreamConfig(gateway_credential=GATEWAY_CREDENTIAL)) as (
        port,
        state,
    ):
        async with _started_client(port) as client:
            tools = await client.list_tools()
            assert STATUS_TOOL not in {tool.name for tool in tools}
            unknown = await client.check_effect(
                STATUS_TOOL, key_hash=key_hash, request_hash=request_hash
            )
            assert unknown.status == "no_effect"
            assert unknown.key_hash == key_hash
            assert unknown.request_hash == request_hash
            assert unknown.confirmation_id.startswith("mock-")
            result = await client.call_tool(
                PUBLIC_TOOL,
                {"customer_id": "cust-1002"},
                meta=_meta(key_hash, request_hash),
            )
            assert result.isError is False
            applied = await client.check_effect(
                STATUS_TOOL, key_hash=key_hash, request_hash=request_hash
            )
            assert applied.status == "applied"
            assert applied.request_hash == request_hash
            with pytest.raises(UpstreamProtocolError):
                await client.check_effect(
                    STATUS_TOOL, key_hash=key_hash, request_hash=other_request_hash
                )
        statuses = [record.status for record in state.records]
        assert statuses.count("success") == 1
        assert state.deleted == {"cust-1002"}


@pytest.mark.asyncio
async def test_crash_after_start_leaves_unknown_outcome() -> None:
    key_hash = _hash_of("gw-key-canary-crash")
    request_hash = _hash_of('{"customer_id":"cust-1001"}')
    config = MockUpstreamConfig(gateway_credential=GATEWAY_CREDENTIAL, crash_after_start=True)
    async with _mock_server(config) as (port, state):
        async with _started_client(port) as client:
            result = await client.call_tool(
                PUBLIC_TOOL,
                {"customer_id": "cust-1001"},
                meta=_meta(key_hash, request_hash),
            )
            assert result.isError is True
            effect = await client.check_effect(
                STATUS_TOOL, key_hash=key_hash, request_hash=request_hash
            )
        assert effect.status == "unknown"
        assert state.deleted == set()
        assert [record.status for record in state.records] == ["started"]


@pytest.mark.asyncio
async def test_upstream_timeout_is_bounded_and_sanitized() -> None:
    key_hash = _hash_of("gw-key-canary-slow")
    request_hash = _hash_of('{"customer_id":"cust-1001"}')
    config = MockUpstreamConfig(gateway_credential=GATEWAY_CREDENTIAL, call_delay_seconds=1.5)
    async with _mock_server(config) as (port, state):
        with pytest.raises(UpstreamTimeout) as excinfo:
            async with _started_client(port, timeout_seconds=0.2) as client:
                await client.call_tool(
                    PUBLIC_TOOL,
                    {"customer_id": "cust-1001"},
                    meta=_meta(key_hash, request_hash),
                )
        assert excinfo.value.may_have_sent is True
        message = str(excinfo.value)
        assert f"http://127.0.0.1:{port}" not in message
        assert GATEWAY_CREDENTIAL not in message
        assert FAKE_AGENT_JWT not in message
        assert state.deleted == set()


@pytest.mark.asyncio
async def test_unreachable_loopback_port_raises_sanitized_unavailable() -> None:
    # Port 0 cannot serve client connections, so the TCP connect fails fast;
    # this Windows environment drops SYNs to closed ports instead of refusing.
    client = UpstreamClient(
        url="http://127.0.0.1:0/mcp",
        server_id="mock-crm",
        credential=GATEWAY_CREDENTIAL,
        tenant=DEFAULT_TENANT,
        timeout_seconds=1.0,
    )
    try:
        with pytest.raises(UpstreamUnavailable) as excinfo:
            await client.start()
        assert client.started is False
        message = str(excinfo.value)
        assert "127.0.0.1:0" not in message
        assert GATEWAY_CREDENTIAL not in message
        assert FAKE_AGENT_JWT not in message
    finally:
        await client.aclose()


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com/mcp",
        "http://10.1.2.3/mcp",
        "https://user:pass@example.com/mcp",
        "https://example.com/mcp?query=1",
        "https://example.com/mcp#fragment",
        "ftp://example.com/mcp",
        "not-a-url",
        "",
    ],
)
def test_upstream_client_rejects_unsafe_urls(url: str) -> None:
    with pytest.raises(ValueError):
        UpstreamClient(
            url=url,
            server_id="mock-crm",
            credential=GATEWAY_CREDENTIAL,
            tenant=DEFAULT_TENANT,
        )


def test_upstream_client_accepts_https_and_loopback_http() -> None:
    loopback = UpstreamClient(
        url="http://127.0.0.1:9999/mcp",
        server_id="mock-crm",
        credential=GATEWAY_CREDENTIAL,
        tenant=DEFAULT_TENANT,
    )
    assert loopback.started is False
    secure = UpstreamClient(
        url="https://example.com/mcp",
        server_id="mock-crm",
        credential=GATEWAY_CREDENTIAL,
        tenant=DEFAULT_TENANT,
    )
    assert secure.started is False


@pytest.mark.asyncio
async def test_check_effect_rejects_invalid_hash_input() -> None:
    async with (
        _mock_server(MockUpstreamConfig(gateway_credential=GATEWAY_CREDENTIAL)) as (
            port,
            _state,
        ),
        _started_client(port) as client,
    ):
        with pytest.raises(ValueError):
            await client.check_effect(
                STATUS_TOOL, key_hash="not-a-hash", request_hash=_hash_of("x")
            )
        with pytest.raises(ValueError):
            await client.check_effect(
                STATUS_TOOL, key_hash=_hash_of("x"), request_hash="sha256:short"
            )


@pytest.mark.asyncio
async def test_upstream_client_requires_start_before_use() -> None:
    client = UpstreamClient(
        url="http://127.0.0.1:9999/mcp",
        server_id="mock-crm",
        credential=GATEWAY_CREDENTIAL,
        tenant=DEFAULT_TENANT,
    )
    with pytest.raises(UpstreamUnavailable):
        await client.list_tools()
    with pytest.raises(UpstreamUnavailable):
        await client.call_tool(PUBLIC_TOOL, {})
    await client.aclose()
    assert client.started is False
