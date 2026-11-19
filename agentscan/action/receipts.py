"""Canonical JSON receipt hashing and independent chain verification."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from agentscan.action.models import ActionReceipt, ReceiptEvidence

GENESIS_PREV_HASH = "sha256:" + ("0" * 64)


def canonical_json(value: Any) -> bytes:
    """Encode JSON with stable key ordering and separators for hashing."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def _receipt_hash_payload(receipt: ActionReceipt) -> dict[str, Any]:
    data = receipt.model_dump(mode="json")
    data["evidence"]["hash"] = ""
    return data


def seal_receipt(receipt: ActionReceipt, prev_hash: str) -> ActionReceipt:
    """Return a receipt whose hash binds its contents and previous link."""
    unsealed = receipt.model_copy(
        update={"evidence": ReceiptEvidence(hash="", prev_hash=prev_hash)}
    )
    digest = "sha256:" + hashlib.sha256(canonical_json(_receipt_hash_payload(unsealed))).hexdigest()
    return unsealed.model_copy(
        update={"evidence": ReceiptEvidence(hash=digest, prev_hash=prev_hash)}
    )


def verify_receipt_chain(receipts: list[ActionReceipt]) -> bool:
    """Independently recompute every receipt hash and link from the genesis hash."""
    previous = GENESIS_PREV_HASH
    for receipt in receipts:
        if receipt.evidence.prev_hash != previous:
            return False
        expected = (
            "sha256:" + hashlib.sha256(canonical_json(_receipt_hash_payload(receipt))).hexdigest()
        )
        if receipt.evidence.hash != expected:
            return False
        previous = receipt.evidence.hash
    return True
