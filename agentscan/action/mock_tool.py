"""Deterministic JSON-backed fake customer record tool."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from agentscan.action.receipts import canonical_json


class MockCustomerTool:
    """Fake delete tool. Customer mutations require the gateway's capability."""

    name = "delete_customer_record"
    server = "mock://agentscan-crm"
    schema = {
        "type": "object",
        "required": ["customer_id"],
        "properties": {"customer_id": {"type": "string"}},
    }

    def __init__(self, state_path: Path, capability_check: Callable[[object], bool]) -> None:
        self.state_path = state_path
        self._capability_check = capability_check
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.state_path.exists():
            self.reset_state()

    def reset_state(self) -> None:
        """Restore the fixed fake data set and clear the audit event list."""
        self._write({"customers": ["cust-1001", "cust-1002"], "events": []})

    def _read(self) -> dict[str, Any]:
        return json.loads(self.state_path.read_text(encoding="utf-8"))

    def _write(self, state: dict[str, Any]) -> None:
        self.state_path.write_text(
            json.dumps(state, sort_keys=True, indent=2) + "\n", encoding="utf-8"
        )

    def state_hash(self) -> str:
        """Hash customer records only; authorization/audit events are separate."""
        state = self._read()
        return "sha256:" + hashlib.sha256(canonical_json(state["customers"])).hexdigest()

    def delete_customer_record(self, customer_id: str, capability: object | None = None) -> str:
        if capability is None or not self._capability_check(capability):
            raise PermissionError("Mock tool mutations require the gateway capability.")
        state = self._read()
        if customer_id not in state["customers"]:
            raise ValueError(f"Unknown fake customer ID: {customer_id}")
        state["customers"].remove(customer_id)
        state["events"].append({"event": "success", "customer_id": customer_id})
        self._write(state)
        return "Fake customer record deleted."

    def record_denial(self, principal: str, customer_id: str, policy_id: str) -> None:
        """Record a denied attempt without changing customer resource state."""
        state = self._read()
        state["events"].append(
            {
                "event": "denied",
                "principal": principal,
                "customer_id": customer_id,
                "policy_id": policy_id,
            }
        )
        self._write(state)
