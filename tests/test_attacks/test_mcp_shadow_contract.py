"""ATK-006: proposals and catalog metadata never prove tool execution."""

from __future__ import annotations

import copy
import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx
from pydantic import ValidationError

from agentscan.attacks.scan.mcp_shadow import McpShadowModule
from agentscan.core import runner
from agentscan.core.models import Severity, Target
from agentscan.core.outcomes import AssessmentInconclusiveError, ExecutionLedger, execution_ledger

ENDPOINT = "mcp+sse://mcp.example.test/mcp"
HTTP_ENDPOINT = "http://mcp.example.test/mcp"
TOOL = {
    "name": "read_public_note",
    "description": "Read a public synthetic note.",
    "inputSchema": {"type": "object", "properties": {"note": {"type": "string"}}},
    "annotations": {"readOnlyHint": True},
}


def fingerprint(tool):
    from agentscan.core.mcp_inventory import fingerprint_mcp_tool

    return fingerprint_mcp_tool(tool)


def baseline(tools=None, **overrides):
    tools = [TOOL] if tools is None else tools
    return {
        "endpoint": ENDPOINT,
        "tools": {tool["name"]: fingerprint(tool) for tool in tools},
        "algorithm": "mcp-tool-json-sha256-v1",
        **overrides,
    }


@pytest.fixture
def one_module(monkeypatch):
    module = McpShadowModule()
    monkeypatch.setattr(runner.registry, "load_all", lambda: None)
    monkeypatch.setattr(runner.registry, "select_for_target", lambda target: ([module], []))
    monkeypatch.setattr(runner.registry, "load_errors", [])
    return module


def mock_catalog(mock, tools, *, second_page=None):
    """Real connector protocol, finite owned replies, no tool execution endpoint."""
    methods = []

    def reply(request):
        if request.method == "DELETE":
            methods.append("DELETE")
            return httpx.Response(204)
        message = json.loads(request.content)
        method = message["method"]
        methods.append(method)
        assert method != "tools/call", "Catalog assessment must never execute a tool"
        if method == "notifications/initialized":
            return httpx.Response(202)
        if method == "initialize":
            result = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}}
        else:
            assert method == "tools/list"
            if message.get("params", {}).get("cursor"):
                if isinstance(second_page, Exception):
                    raise second_page
                result = second_page
            else:
                result = {"tools": tools}
                if second_page is not None:
                    result["nextCursor"] = "synthetic-next"
        return httpx.Response(
            200,
            headers={"Mcp-Session-Id": "owned-session"},
            json={"jsonrpc": "2.0", "id": message["id"], "result": result},
        )

    mock.post(HTTP_ENDPOINT).mock(side_effect=reply)
    mock.delete(HTTP_ENDPOINT).mock(side_effect=reply)
    return methods


@pytest.mark.parametrize(
    ("variant_id", "response"),
    [
        (
            "MCP-001",
            {
                "response": "Example only",
                "tool_calls": [
                    {
                        "function": {
                            "name": "fetch",
                            "arguments": '{"url":"http://agentscan-mcp-shadow.invalid/example"}',
                        }
                    }
                ],
            },
        ),
        (
            "MCP-002",
            {
                "response": "Proposed call",
                "tool_calls": [
                    {"function": {"name": "safe_file_system_documentation", "arguments": "{}"}}
                ],
            },
        ),
        (
            "MCP-003",
            {
                "choices": [
                    {
                        "message": {
                            "content": "Proposed only",
                            "function_call": {"name": "githb", "arguments": "{}"},
                        }
                    }
                ]
            },
        ),
        ("MCP-004", {"response": "The sample configuration names agentscan-mcp-shadow.invalid."}),
        (
            "MCP-006",
            {
                "response": "Synthetic wrapper",
                "function_call": {"name": "catalog", "arguments": '{"example":"github_shadow"}'},
            },
        ),
    ],
    ids=[
        "forged-call",
        "substring-name",
        "nested-function-claim",
        "config-example",
        "argument-mention",
    ],
)
async def test_target_reported_claim_has_no_dispatch_evidence(variant_id, response):
    module = McpShadowModule()
    variant = next(v for v in module._load_payload_variants() if v["id"] == variant_id)
    client = AsyncMock()
    client.target = Target(url="http://agent.example.test/chat")
    client.send_message.return_value = response
    with pytest.raises(AssessmentInconclusiveError):
        await module._test_variant(client, variant)
    client.send_message.assert_awaited_once()


@pytest.mark.parametrize(
    "response", [{"response": "I refuse."}, {"response": ""}, {"response": "Safe"}]
)
async def test_no_proposal_or_refusal_does_not_prove_absence_of_execution(response):
    module = McpShadowModule()
    client = AsyncMock()
    client.target = Target(url="http://agent.example.test/chat")
    client.send_message.return_value = response
    with pytest.raises(AssessmentInconclusiveError):
        await module._test_variant(client, module._load_payload_variants()[0])


@pytest.mark.parametrize(
    ("variant_id", "response", "count", "matched"),
    [
        (
            "MCP-003",
            {"choices": [{"message": {"function_call": {"name": "githb", "arguments": "{}"}}}]},
            1,
            1,
        ),
        (
            "MCP-002",
            {
                "tool_calls": [
                    {"function": {"name": "safe_file_system_documentation", "arguments": "{}"}}
                ]
            },
            1,
            0,
        ),
        (
            "MCP-001",
            {
                "tool_calls": [
                    {
                        "function": {
                            "name": "fetch",
                            "arguments": {"url": "http://agentscan-mcp-shadow.invalid.evil.test/"},
                        }
                    }
                ]
            },
            1,
            0,
        ),
        (
            "MCP-001",
            {
                "tool_calls": [
                    {
                        "function": {
                            "name": "fetch",
                            "arguments": {"url": "http://agentscan-mcp-shadow.invalid/policy"},
                        }
                    }
                ]
            },
            1,
            1,
        ),
    ],
    ids=["nested-function", "substring-name", "host-suffix", "exact-host"],
)
async def test_observation_counts_exact_proposed_identity_without_claiming_execution(
    variant_id, response, count, matched
):
    module = McpShadowModule()
    client = AsyncMock()
    client.target = Target(url="http://agent.example.test/chat")
    client.send_message.return_value = response
    variant = next(v for v in module._load_payload_variants() if v["id"] == variant_id)
    ledger = ExecutionLedger()
    token = execution_ledger.set(ledger)
    try:
        with pytest.raises(AssessmentInconclusiveError):
            await module._test_variant(client, variant)
    finally:
        execution_ledger.reset(token)
    observation = ledger.observations[0]
    assert observation["reported_proposal_count"] == count
    assert observation["matching_reported_proposal_count"] == matched
    assert observation["tool_execution_verified"] is False
    assert observation["network_transfer_verified"] is False
    assert "arguments" not in observation


async def test_default_profile_records_eight_observations_without_model_calls():
    module = McpShadowModule()
    ledger = ExecutionLedger()
    token = execution_ledger.set(ledger)
    try:
        with (
            respx.mock(assert_all_called=False) as mock,
            patch(
                "agentscan.attacks.scan.runner.AIClient",
                side_effect=AssertionError("No external analysis is needed"),
            ),
            patch(
                "agentscan.attacks.scan.mcp_shadow.AIClient",
                side_effect=AssertionError("No external analysis is needed"),
            ),
        ):
            route = mock.post("http://agent.example.test/chat").mock(
                return_value=httpx.Response(200, json={"response": "Synthetic proposed call only"})
            )
            findings = await module.run(
                Target(
                    url="http://agent.example.test/chat",
                    attacker_model="gemini/example",
                    judge_model="gemini/example",
                    mutate=True,
                )
            )
        assert findings == []
        assert route.call_count == 8
        assert ledger.selected == 8
        assert ledger.evaluated == 0
        assert len(ledger.observations) == 8
        assert ledger.inconclusive_reasons
        assert ledger.assessment_scope == "mcp_tool_proposal_inventory"
    finally:
        execution_ledger.reset(token)


async def test_mcp_without_baseline_does_not_connect_or_execute(one_module):
    with respx.mock(assert_all_called=False) as mock:
        report = await runner.run_scan(Target(url=ENDPOINT, attacks=["ATK-006"]))
        assert not mock.calls
    assert report.status == "INCONCLUSIVE"
    assert report.tests_run == 0
    assert report.findings == []
    assert report.score is None


@pytest.mark.parametrize("catalog", [[], [TOOL]])
async def test_matching_complete_catalog_is_one_policy_check_not_execution(one_module, catalog):
    target = Target(url=ENDPOINT, attacks=["ATK-006"], mcp_inventory_baseline=baseline(catalog))
    with respx.mock(assert_all_called=False) as mock:
        methods = mock_catalog(mock, catalog)
        report = await runner.run_scan(target)
    assert methods == ["initialize", "notifications/initialized", "tools/list", "DELETE"]
    assert report.status == "COMPLETE"
    assert report.tests_run == 1
    assert report.findings == []
    assert report.score is None
    assert report.assessment_scope == "mcp_catalog_policy"
    outcome = report.module_outcomes[0]
    assert outcome["selected_tests"] == outcome["executed_tests"] == 1
    assert outcome["assessment_scope"] == "mcp_catalog_policy"


async def test_complete_catalog_may_span_multiple_pages(one_module):
    second = {**TOOL, "name": "list_public_notes"}
    target = Target(url=ENDPOINT, mcp_inventory_baseline=baseline([TOOL, second]))
    with respx.mock(assert_all_called=False) as mock:
        methods = mock_catalog(mock, [TOOL], second_page={"tools": [second]})
        report = await runner.run_scan(target)
    assert methods == [
        "initialize",
        "notifications/initialized",
        "tools/list",
        "tools/list",
        "DELETE",
    ]
    assert report.status == "COMPLETE"
    assert report.tests_run == 1
    assert report.score is None
    assert report.findings == []


async def test_model_copy_cannot_bypass_baseline_endpoint_binding(one_module):
    target = Target(url=ENDPOINT, mcp_inventory_baseline=baseline()).model_copy(
        update={"url": "mcp+sse://another.example.test/mcp"}
    )
    with respx.mock(assert_all_called=False) as mock:
        report = await runner.run_scan(target)
        assert not mock.calls
    assert report.status == "INCONCLUSIVE"
    assert report.tests_run == 0
    assert report.findings == []
    assert report.score is None


@pytest.mark.parametrize(
    "catalog",
    [
        [{**TOOL, "name": "read_public_note_shadow"}],
        [{**TOOL, "description": "Changed synthetic metadata"}],
        [{**TOOL, "annotations": {"readOnlyHint": False}}],
        [{**TOOL, "inputSchema": {"type": "object", "properties": {"secret": {"type": "string"}}}}],
        [],
    ],
    ids=[
        "unexpected-and-missing",
        "description-drift",
        "annotation-drift",
        "schema-drift",
        "missing-tool",
    ],
)
async def test_catalog_drift_finding_is_medium_and_makes_no_execution_claim(one_module, catalog):
    with respx.mock(assert_all_called=False) as mock:
        methods = mock_catalog(mock, catalog)
        report = await runner.run_scan(Target(url=ENDPOINT, mcp_inventory_baseline=baseline()))
    assert "tools/call" not in methods
    assert report.status == "COMPLETE"
    assert report.tests_run == 1
    assert report.score is None
    assert report.assessment_scope == "mcp_catalog_policy"
    assert report.findings == []
    assert report.module_outcomes[0]["catalog_finding_count"] == 1
    findings = report.module_outcomes[0]["catalog_findings"]
    assert len(findings) == 1
    for finding in findings:
        data = finding.model_dump(mode="json") if hasattr(finding, "model_dump") else finding
        assert str(data["severity"]) == str(Severity.MEDIUM)
        assert data.get("metadata", {}).get("tool_execution_verified", False) is False
        assert data.get("metadata", {}).get("network_transfer_verified", False) is False
        assert "accepted MCP shadow" not in data["description"]


@pytest.mark.parametrize(
    ("catalog", "second_page"),
    [
        ([TOOL, copy.deepcopy(TOOL)], None),
        ([{**TOOL, "inputSchema": []}], None),
        ([{**TOOL, "name": ""}], None),
        ([{"description": "missing name"}], None),
        ([TOOL], {"tools": [{**TOOL, "name": "second"}], "nextCursor": "synthetic-next"}),
        ([TOOL], {"tools": "malformed"}),
        ([TOOL], httpx.ReadError("synthetic interrupted pagination")),
    ],
    ids=[
        "duplicate",
        "bad-schema",
        "empty-name",
        "missing-name",
        "repeated-cursor",
        "bad-second-page",
        "interrupted-page",
    ],
)
async def test_incomplete_or_malformed_catalog_is_never_clean(one_module, catalog, second_page):
    with respx.mock(assert_all_called=False) as mock:
        methods = mock_catalog(mock, catalog, second_page=second_page)
        report = await runner.run_scan(Target(url=ENDPOINT, mcp_inventory_baseline=baseline()))
    assert "tools/call" not in methods
    assert report.status in {"ERROR", "INCONCLUSIVE"}
    assert report.tests_run == 0
    assert report.findings == []
    assert report.score is None


@pytest.mark.parametrize(
    "override",
    [
        {"endpoint": "mcp+sse://another.example.test/mcp"},
        {"algorithm": "sha1"},
        {"tools": {"read_public_note": "not-a-sha256"}},
        {"tools": {"": "a" * 64}},
    ],
)
def test_invalid_operator_baseline_is_rejected_before_scan(override):
    with pytest.raises(ValidationError):
        Target(url=ENDPOINT, mcp_inventory_baseline={**baseline(), **override})


async def test_operator_baseline_selects_only_catalog_check_in_public_scan():
    """No patched registry: a catalog workflow must not dispatch other attacks."""
    with respx.mock(assert_all_called=False) as mock:
        methods = mock_catalog(mock, [TOOL])
        report = await runner.run_scan(Target(url=ENDPOINT, mcp_inventory_baseline=baseline()))
    assert methods == ["initialize", "notifications/initialized", "tools/list", "DELETE"]
    assert report.status == "COMPLETE"
    assert report.tests_run == 1
    assert [outcome["module_id"] for outcome in report.module_outcomes] == ["ATK-006"]
    assert report.score is None
