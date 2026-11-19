from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentscan.action.gateway import MockGateway
from agentscan.action.modules.act001 import UnauthorizedToolInvocation
from agentscan.action.receipts import verify_receipt_chain


def test_gateway_allow_and_deny_chain_and_action_findings(tmp_path: Path) -> None:
    gateway = MockGateway(tmp_path / "state.json")
    before = gateway.tool.state_hash()
    allowed = gateway.invoke(
        principal="principal:crm-operator",
        tool_name="delete_customer_record",
        arguments={"customer_id": "cust-1001"},
        trace_id="trace-allow",
    )
    after_allow = gateway.tool.state_hash()
    denied = gateway.invoke(
        principal="principal:untrusted-agent",
        tool_name="delete_customer_record",
        arguments={"customer_id": "cust-1001"},
        trace_id="trace-deny",
    )
    after_deny = gateway.tool.state_hash()

    assert before != after_allow
    assert after_allow == after_deny
    assert allowed.authorization.decision == "allow"
    assert allowed.result.status == "success"
    assert denied.authorization.decision == "deny"
    assert denied.result.status == "denied"
    assert denied.evidence.prev_hash == allowed.evidence.hash
    assert verify_receipt_chain(gateway.receipts)

    module = UnauthorizedToolInvocation()
    assert module.scan(gateway.receipts, "trace-allow").status == "PASS"
    denied_result = module.scan(gateway.receipts, "trace-deny")
    assert denied_result.status == "FINDING"
    assert len(denied_result.findings) == 1
    assert denied_result.findings[0].attack_id == "ACT-001"
    assert denied_result.findings[0].receipt_hash == denied.evidence.hash
    assert denied.evidence.hash in denied_result.findings[0].evidence


def test_direct_tool_mutation_without_gateway_capability_fails(tmp_path: Path) -> None:
    gateway = MockGateway(tmp_path / "state.json")
    before = gateway.tool.state_hash()
    with pytest.raises(PermissionError):
        gateway.tool.delete_customer_record("cust-1001")
    assert gateway.tool.state_hash() == before


def test_act001_missing_or_ambiguous_receipts_are_unverified(tmp_path: Path) -> None:
    gateway = MockGateway(tmp_path / "state.json")
    module = UnauthorizedToolInvocation()
    assert module.scan([], "missing").status == "UNVERIFIED"
    receipt = gateway.invoke(
        principal="principal:crm-operator",
        tool_name="delete_customer_record",
        arguments={"customer_id": "cust-1001"},
        trace_id="repeated",
    )
    second = gateway.invoke(
        principal="principal:untrusted-agent",
        tool_name="delete_customer_record",
        arguments={"customer_id": "cust-1001"},
        trace_id="repeated",
    )
    assert module.scan([receipt, second], "repeated").status == "UNVERIFIED"


def test_json_state_contains_success_and_denial_audit_events(tmp_path: Path) -> None:
    gateway = MockGateway(tmp_path / "state.json")
    gateway.invoke(
        principal="principal:crm-operator",
        tool_name="delete_customer_record",
        arguments={"customer_id": "cust-1001"},
    )
    gateway.invoke(
        principal="principal:untrusted-agent",
        tool_name="delete_customer_record",
        arguments={"customer_id": "cust-1001"},
    )
    events = json.loads((tmp_path / "state.json").read_text(encoding="utf-8"))["events"]
    assert [event["event"] for event in events] == ["success", "denied"]
