"""Tiny deterministic reference monitor for the spike's fake CRM tool."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

from agentscan.action.mock_tool import MockCustomerTool
from agentscan.action.models import (
    ActionReceipt,
    ActionResult,
    Authorization,
    ReceiptEvidence,
    ToolIdentity,
)
from agentscan.action.receipts import GENESIS_PREV_HASH, canonical_json, seal_receipt

ALLOW_POLICY_ID = "spike-allow-crm-operator-delete-cust-1001"
DENY_POLICY_ID = "spike-deny-untrusted-principal"


class _GatewayCapability:
    """Opaque, instance-specific proof minted only inside MockGateway."""


class MockGateway:
    """One hard-coded allow rule and one deny rule, both documented below."""

    def __init__(self, state_path: Path) -> None:
        self.__capability = _GatewayCapability()
        self.tool = MockCustomerTool(state_path, self._owns_capability)
        self.receipts: list[ActionReceipt] = []

    def _owns_capability(self, candidate: object) -> bool:
        return candidate is self.__capability

    @staticmethod
    def _tool_identity() -> ToolIdentity:
        schema_hash = (
            "sha256:" + hashlib.sha256(canonical_json(MockCustomerTool.schema)).hexdigest()
        )
        return ToolIdentity(
            name=MockCustomerTool.name,
            server=MockCustomerTool.server,
            schema_hash=schema_hash,
        )

    def invoke(
        self,
        *,
        principal: str,
        tool_name: str,
        arguments: dict[str, Any],
        trace_id: str | None = None,
    ) -> ActionReceipt:
        """Evaluate policy, then execute or deny and append a hash-chained receipt."""
        customer_id = arguments.get("customer_id")
        # ALLOW: principal:crm-operator may delete exactly cust-1001 with this tool.
        allowed = (
            principal == "principal:crm-operator"
            and tool_name == MockCustomerTool.name
            and arguments == {"customer_id": "cust-1001"}
        )
        # DENY: every request that misses the exact allow rule is denied. This
        # includes principal:untrusted-agent and all mismatched arguments.
        decision: Literal["allow", "deny"] = "allow" if allowed else "deny"
        policy_id = ALLOW_POLICY_ID if allowed else DENY_POLICY_ID

        if tool_name != MockCustomerTool.name:
            raise ValueError(f"Unsupported fake tool: {tool_name}")
        if not isinstance(customer_id, str):
            raise ValueError("customer_id must be a string")

        result_status: Literal["success", "denied", "error"]
        if allowed:
            summary = self.tool.delete_customer_record(customer_id, self.__capability)
            result_status = "success"
        else:
            # Unknown principals and mismatched arguments fail closed.
            self.tool.record_denial(principal, customer_id, policy_id)
            summary = "Gateway denied the requested tool call before mutation."
            result_status = "denied"

        previous_hash = self.receipts[-1].evidence.hash if self.receipts else GENESIS_PREV_HASH
        receipt = ActionReceipt(
            trace_id=trace_id or str(uuid4()),
            principal=principal,
            tool=self._tool_identity(),
            arguments=arguments,
            authorization=Authorization(decision=decision, policy_id=policy_id),
            result=ActionResult(status=result_status, summary=summary),
            evidence=ReceiptEvidence(hash="", prev_hash=previous_hash),
        )
        receipt = seal_receipt(receipt, previous_hash)
        self.receipts.append(receipt)
        return receipt
