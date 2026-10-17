"""Independent baseline and transport checks; no external servers or SDK required."""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
from unittest.mock import AsyncMock

import httpx
import pytest
import respx
from pydantic import ValidationError

from agentscan.core.client import AgentScanClient
from agentscan.core.connectors.mcp import McpSseConnector, McpStdioConnector, _McpClientMixin
from agentscan.core.connectors.registry import CallableConnector, use_connector
from agentscan.core.context import ScanContext, active_context
from agentscan.core.mcp_inventory import (
    McpInventoryBaseline,
    compare_mcp_inventory,
    fingerprint_mcp_tool,
)
from agentscan.core.models import Target
from agentscan.core.outcomes import TargetRequestError

ENDPOINT = "mcp+sse://inventory.example/mcp"
TOOL = {"name": "public_search", "description": "Public search", "inputSchema": {"type": "object"}}
# Independently encode the documented byte format rather than call the scanner
# to approve whichever result it currently produces.
APPROVED_BYTES = (
    b'{"description":"Public search","inputSchema":{"type":"object"},"name":"public_search"}'
)
APPROVED_HASH = hashlib.sha256(APPROVED_BYTES).hexdigest()


def baseline(tools=None):
    return McpInventoryBaseline(
        endpoint=ENDPOINT, tools=tools if tools is not None else {"public_search": APPROVED_HASH}
    )


def test_canonical_hash_matches_independent_approved_bytes_and_key_order():
    assert fingerprint_mcp_tool(TOOL) == APPROVED_HASH
    assert fingerprint_mcp_tool(dict(reversed(list(TOOL.items())))) == APPROVED_HASH
    assert compare_mcp_inventory([TOOL], baseline())["deviation_count"] == 0


@pytest.mark.parametrize(
    "field,value",
    [
        ("description", "New instructions"),
        ("inputSchema", {"type": "object", "properties": {"destination": {"type": "string"}}}),
        ("annotations", {"readOnlyHint": True}),
        ("outputSchema", {"type": "object"}),
        ("futureMetadata", {"routing": "changed"}),
    ],
)
def test_all_metadata_changes_count_even_permission_hint_or_unknown_field(field, value):
    changed = {**TOOL, field: value}
    result = compare_mcp_inventory([changed], baseline())
    assert result["deviation_counts"] == {
        "unexpected_tool": 0,
        "metadata_changed": 1,
        "missing_tool": 0,
    }
    assert result["deviations"][0]["expected_sha256"] == APPROVED_HASH


def test_identity_is_exact_and_missing_tools_are_explicit():
    renamed = {**TOOL, "name": "Public_Search"}
    result = compare_mcp_inventory([renamed], baseline())
    assert result["deviation_count"] == 2
    assert result["deviation_counts"] == {
        "unexpected_tool": 1,
        "metadata_changed": 0,
        "missing_tool": 1,
    }


def test_explicit_empty_baseline_is_meaningful():
    assert compare_mcp_inventory([], baseline({}))["deviation_count"] == 0
    assert compare_mcp_inventory([TOOL], baseline({}))["deviation_counts"]["unexpected_tool"] == 1
    with pytest.raises(ValidationError):
        McpInventoryBaseline(endpoint=ENDPOINT)


@pytest.mark.parametrize(
    "invalid",
    [
        None,
        [],
        {1: APPROVED_HASH},
        {"": APPROVED_HASH},
        {"bad name": APPROVED_HASH},
        {"n" * 129: APPROVED_HASH},
        {"tøol": APPROVED_HASH},
        {"tool": 1},
        {"tool": "A" * 64},
        {"tool": "0" * 63},
        {f"tool{i}": APPROVED_HASH for i in range(1001)},
    ],
)
def test_baseline_rejects_unsupported_keys_hashes_and_sizes(invalid):
    with pytest.raises(ValidationError):
        baseline(invalid) if invalid is not None else McpInventoryBaseline(
            endpoint=ENDPOINT, tools=None
        )


@pytest.mark.parametrize("endpoint", [1, "", " " + ENDPOINT, ENDPOINT + "\n", "x" * 8193])
def test_endpoint_binding_is_strict_and_bounded(endpoint):
    with pytest.raises(ValidationError):
        McpInventoryBaseline(endpoint=endpoint, tools={})


def test_baseline_rejects_unknown_fields_and_algorithm():
    with pytest.raises(ValidationError):
        McpInventoryBaseline(endpoint=ENDPOINT, tools={}, extra=True)
    with pytest.raises(ValidationError):
        McpInventoryBaseline(endpoint=ENDPOINT, tools={}, algorithm="auto-trust-first-response")


@pytest.mark.parametrize(
    "tool",
    [
        {},
        {**TOOL, "name": 1},
        {**TOOL, "name": "a b"},
        {**TOOL, "description": None},
        {**TOOL, "inputSchema": []},
        {**TOOL, "inputSchema": {"type": "string"}},
        {**TOOL, "outputSchema": None},
        {**TOOL, "annotations": []},
        {**TOOL, "unknown": float("nan")},
        {**TOOL, "unknown": float("inf")},
        {**TOOL, "unknown": (1, 2)},
        {**TOOL, "unknown": {1: "coerced-key"}},
        {**TOOL, "unknown": {1, 2}},
    ],
)
def test_malformed_tool_never_becomes_clean_inventory(tool):
    with pytest.raises(ValueError):
        compare_mcp_inventory([TOOL, tool], baseline())


def test_duplicate_identity_invalidates_whole_snapshot_instead_of_last_wins():
    with pytest.raises(ValueError, match="duplicate"):
        compare_mcp_inventory([TOOL, {**TOOL, "description": "changed"}], baseline())


def test_cycles_depth_and_metadata_size_are_bounded():
    cycle = {**TOOL}
    cycle["cycle"] = cycle
    nested = {}
    value = nested
    for _ in range(70):
        value["next"] = {}
        value = value["next"]
    for tool in (
        cycle,
        {**TOOL, "nested": nested},
        {**TOOL, "description": "x" * (4 * 1024 * 1024)},
    ):
        with pytest.raises(ValueError):
            fingerprint_mcp_tool(tool)


def test_catalog_aggregate_bytes_and_structural_nodes_are_bounded():
    first = {**TOOL, "description": "x" * (2 * 1024 * 1024)}
    second = {**first, "name": "other"}
    with pytest.raises(ValueError, match="aggregate"):
        compare_mcp_inventory([first, second], baseline())
    with pytest.raises(ValueError, match="structural"):
        fingerprint_mcp_tool({**TOOL, "unknown": [0] * 100_001})


def test_deviation_details_are_bounded_without_losing_total_counts():
    tools = [{**TOOL, "name": f"tool{i:03d}"} for i in range(125)]
    result = compare_mcp_inventory(tools, baseline({}))
    assert result["deviation_count"] == 125
    assert result["deviation_counts"]["unexpected_tool"] == 125
    assert len(result["deviations"]) == 100
    assert result["truncated"] is True
    assert "description" not in json.dumps(result)


async def test_snapshot_is_detached_and_requires_completed_handshake():
    class Snapshot(_McpClientMixin):
        _tools = [copy.deepcopy(TOOL)]

    connector = Snapshot()
    assert await connector.get_mcp_tools() is None
    connector._catalog_complete = True
    snapshot = await connector.get_mcp_tools()
    snapshot[0]["inputSchema"]["mutated"] = True
    assert connector._tools == [TOOL]


async def test_client_respects_selected_connector_without_probe_or_trace():
    class InventoryConnector(CallableConnector):
        async def get_mcp_tools(self):
            return [copy.deepcopy(TOOL)]

    connector = InventoryConnector(
        lambda _: pytest.fail("Inventory must not call a tool or send a message")
    )
    context = ScanContext()
    token = active_context.set(context)
    try:
        with use_connector(connector):
            async with AgentScanClient(Target(url=ENDPOINT)) as client:
                assert await client.inspect_mcp_tools() == [TOOL]
        assert context.traffic_entries == []
    finally:
        active_context.reset(token)


async def test_non_mcp_connector_is_explicitly_unsupported():
    with use_connector(CallableConnector(lambda _: pytest.fail("No probe allowed"))):
        async with AgentScanClient(Target(url="https://chat.example/")) as client:
            assert await client.inspect_mcp_tools() is None


async def test_lazy_stdio_style_connector_initializes_once_without_http_client_sentinel():
    class ProcessConnector(CallableConnector):
        starts = 0
        stops = 0

        async def __aenter__(self):
            self.starts += 1
            await asyncio.sleep(0)
            return self

        async def __aexit__(self, *exc):
            self.stops += 1

        async def get_mcp_tools(self):
            return [copy.deepcopy(TOOL)]

    connector = ProcessConnector(lambda _: pytest.fail("No tools allowed"))
    with use_connector(connector):
        client = AgentScanClient.from_target(Target(url="mcp://stdio?command=python"))
        await asyncio.gather(client.inspect_mcp_tools(), client.inspect_mcp_tools())
        assert connector.starts == 1
        await client.close()
        assert connector.stops == 1
        await client.inspect_mcp_tools()
        assert connector.starts == 2
        await client.close()


async def test_real_transport_discovery_and_cleanup_never_invoke_tool():
    methods = []

    def reply(request):
        if request.method == "DELETE":
            return httpx.Response(204)
        body = json.loads(request.content)
        method = body["method"]
        methods.append(method)
        assert method != "tools/call"
        if method == "initialize":
            result = {"protocolVersion": "2025-06-18"}
        elif method == "notifications/initialized":
            return httpx.Response(202)
        else:
            assert method == "tools/list"
            result = {"tools": [TOOL]}
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": result})

    context = ScanContext(request_budget=3)
    token = active_context.set(context)
    try:
        with respx.mock:
            respx.route(url="http://inventory.example/mcp").mock(side_effect=reply)
            async with AgentScanClient(Target(url=ENDPOINT)) as client:
                assert (
                    compare_mcp_inventory(await client.inspect_mcp_tools(), baseline())[
                        "deviation_count"
                    ]
                    == 0
                )
                assert await client.inspect_mcp_tools() == [TOOL]
        assert methods == ["initialize", "notifications/initialized", "tools/list"]
        assert context.target_requests == 3
    finally:
        active_context.reset(token)


@pytest.mark.parametrize("connector_type", [McpSseConnector, McpStdioConnector])
@pytest.mark.parametrize("operation", ["_rpc", "_notify"])
async def test_transport_budget_rejects_before_io(connector_type, operation):
    url = ENDPOINT if connector_type is McpSseConnector else "mcp://stdio?command=python"
    connector = connector_type(Target(url=url))
    connector._post_rpc = AsyncMock(side_effect=AssertionError("No HTTP allowed"))
    connector._write_frame = AsyncMock(side_effect=AssertionError("No process I/O allowed"))
    token = active_context.set(ScanContext(request_budget=1, target_requests=1))
    try:
        with pytest.raises(TargetRequestError, match="budget"):
            await getattr(connector, operation)("tools/list")
        connector._post_rpc.assert_not_awaited()
        connector._write_frame.assert_not_awaited()
    finally:
        active_context.reset(token)
