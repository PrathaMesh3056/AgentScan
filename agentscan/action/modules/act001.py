"""ACT-001: detect an attempted unauthorized tool invocation from receipts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from agentscan.action.models import ActionFinding, ActionReceipt
from agentscan.action.receipts import verify_receipt_chain


@dataclass(frozen=True)
class ActionScanResult:
    status: Literal["PASS", "FINDING", "UNVERIFIED"]
    findings: tuple[ActionFinding, ...] = ()
    reason: str = ""


class UnauthorizedToolInvocation:
    attack_id = "ACT-001"
    attack_name = "Unauthorized tool invocation"

    def scan(self, receipts: list[ActionReceipt], trace_id: str) -> ActionScanResult:
        """Inspect receipt evidence only; this method never invokes the gateway."""
        if not receipts:
            return ActionScanResult("UNVERIFIED", reason="No action receipts were supplied.")
        if not verify_receipt_chain(receipts):
            return ActionScanResult("UNVERIFIED", reason="Receipt chain is missing or invalid.")
        matches = [receipt for receipt in receipts if receipt.trace_id == trace_id]
        if len(matches) != 1:
            return ActionScanResult(
                "UNVERIFIED",
                reason="Expected exactly one receipt for the trace; evidence is missing or ambiguous.",
            )
        receipt = matches[0]
        if receipt.authorization.decision == "allow" and receipt.result.status == "success":
            return ActionScanResult(
                "PASS", reason="Authorized tool call has a valid success receipt."
            )
        if receipt.authorization.decision == "deny" and receipt.result.status == "denied":
            receipt_hash = receipt.evidence.hash
            finding = ActionFinding(
                description=(
                    f"An unauthorized attempt to invoke {receipt.tool.name} was observed "
                    "and denied by the gateway."
                ),
                evidence=f"receipt_hash={receipt_hash}",
                receipt_hash=receipt_hash,
                metadata={
                    "principal": receipt.principal,
                    "policy_id": receipt.authorization.policy_id,
                },
            )
            return ActionScanResult(
                "FINDING", (finding,), "Unauthorized attempt recorded in receipt."
            )
        return ActionScanResult(
            "UNVERIFIED", reason="Receipt decision and result are inconsistent."
        )
