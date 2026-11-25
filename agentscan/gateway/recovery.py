"""Startup recovery and explicit, authenticated outcome reconciliation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agentscan.gateway.idempotency import (
    IdempotencyIndex,
    IdempotencyState,
    ReceiptPairingError,
    append_outcome,
    hash_key,
    pair_receipts,
)
from agentscan.gateway.receipts import (
    GatewayReceipt,
    ReceiptChainStore,
    ReceiptError,
    utc_timestamp,
)


class RecoveryError(RuntimeError):
    """Recovery cannot verify or safely advance the durable receipt state."""


class ReconciliationError(RecoveryError):
    """A supplied status confirmation cannot safely reconcile a decision."""


@dataclass(frozen=True, slots=True)
class RecoveryReport:
    chain_head: str
    receipt_count: int
    pending_before: int
    unknowns_appended: int
    pending_trace_ids: tuple[str, ...]
    index: IdempotencyIndex


def _check_store(
    store: ReceiptChainStore, error_type: type[RecoveryError]
) -> tuple[GatewayReceipt, ...]:
    if not store.lease_held:
        raise error_type("writer lease is required")
    try:
        verified = store.verify()
    except (ReceiptError, OSError) as exc:
        raise error_type("durable receipt chain does not verify") from exc
    if (
        verified.head_hash != store.head_hash
        or len(verified.receipts) != len(store.receipts)
        or verified.receipts != store.receipts
    ):
        raise error_type("durable receipt chain does not match the store cache")
    return verified.receipts


def recover(store: ReceiptChainStore, *, now: datetime | None = None) -> RecoveryReport:
    """Close pending decisions as unknown without querying or retrying upstream."""
    receipts = _check_store(store, RecoveryError)
    try:
        pairs = pair_receipts(receipts)
    except ReceiptPairingError as exc:
        raise RecoveryError("receipt decisions and outcomes cannot be paired") from exc
    pending = tuple(pair for pair in pairs if pair.state == IdempotencyState.PENDING)
    unknowns_appended = 0
    recovered_at = utc_timestamp(now)
    for pair in pending:
        note = {
            "source": "startup_recovery",
            "reason": "outcome_not_recorded",
            "recovered_at": recovered_at,
        }
        try:
            append_outcome(
                store,
                pair.decision,
                status="unknown",
                summary="crash recovery: outcome not recorded",
                response_hash=None,
                reconciliation=note,
                now=now,
            )
        except Exception as exc:
            raise RecoveryError("could not durably close pending decision") from exc
        unknowns_appended += 1

    final_receipts = _check_store(store, RecoveryError)
    try:
        pair_receipts(final_receipts)
        index = IdempotencyIndex(store.retention_index.retention_days)
        index.rebuild(final_receipts, now=now)
    except (ReceiptPairingError, ValueError) as exc:
        raise RecoveryError("recovered receipt state is invalid") from exc
    return RecoveryReport(
        chain_head=store.head_hash,
        receipt_count=len(final_receipts),
        pending_before=len(pending),
        unknowns_appended=unknowns_appended,
        pending_trace_ids=tuple(pair.decision.trace_id for pair in pending),
        index=index,
    )


def _normalize_observed_at(value: str) -> str:
    try:
        candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
        parsed = datetime.fromisoformat(candidate)
    except (TypeError, ValueError) as exc:
        raise ValueError("observed_at must be timezone-aware ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("observed_at must be timezone-aware ISO-8601")
    return utc_timestamp(parsed.astimezone(UTC))


class UpstreamConfirmation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal["no_effect", "applied", "unknown"]
    key_hash: str
    request_hash: str
    confirmation_id: str
    observed_at: str
    authenticated: bool = Field(strict=True)
    source: Literal["upstream:check_effect"] = "upstream:check_effect"

    @field_validator("key_hash", "request_hash")
    @classmethod
    def validate_hashes(cls, value: str) -> str:
        if (
            len(value) != 71
            or not value.startswith("sha256:")
            or any(char not in "0123456789abcdef" for char in value[7:])
        ):
            raise ValueError("confirmation hashes must use sha256:<64 lowercase hex>")
        return value

    @field_validator("confirmation_id")
    @classmethod
    def validate_confirmation_id(cls, value: str) -> str:
        if not value.strip() or len(value.encode("utf-8")) > 256:
            raise ValueError("confirmation_id must contain 1 to 256 UTF-8 bytes")
        return value

    @field_validator("observed_at")
    @classmethod
    def normalize_observed_at(cls, value: str) -> str:
        return _normalize_observed_at(value)

    @model_validator(mode="after")
    def require_authentication(self) -> UpstreamConfirmation:
        if not self.authenticated:
            raise ValueError("upstream confirmation must be authenticated")
        return self


class ReconciliationStatus(StrEnum):
    NO_EFFECT_RECORDED = "NO_EFFECT_RECORDED"
    ALREADY_NO_EFFECT = "ALREADY_NO_EFFECT"
    APPLIED = "APPLIED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class ReconciliationResult:
    status: ReconciliationStatus
    key_hash: str
    request_hash: str
    appended: GatewayReceipt | None


def reconcile(
    store: ReceiptChainStore,
    *,
    idempotency_key: str,
    confirmation: UpstreamConfirmation,
    max_key_bytes: int,
    now: datetime | None = None,
) -> ReconciliationResult:
    """Apply one explicit status confirmation; never infer that no effect occurred."""
    if not isinstance(confirmation, UpstreamConfirmation):
        raise ReconciliationError("confirmation must be a validated UpstreamConfirmation")
    receipts = _check_store(store, ReconciliationError)
    if not confirmation.authenticated:
        raise ReconciliationError("upstream confirmation is not authenticated")
    try:
        key_hash = hash_key(idempotency_key, max_bytes=max_key_bytes)
        pairs = pair_receipts(receipts)
    except (ValueError, ReceiptPairingError) as exc:
        raise ReconciliationError("reconciliation input or receipt state is invalid") from exc
    if confirmation.key_hash != key_hash:
        raise ReconciliationError("confirmation key hash does not match the supplied key")
    matching = [
        pair
        for pair in pairs
        if pair.decision.idempotency_key == key_hash
        and pair.decision.request_hash == confirmation.request_hash
    ]
    if len(matching) != 1:
        raise ReconciliationError("confirmation does not identify exactly one stored decision")
    pair = matching[0]
    if pair.state == IdempotencyState.DENIED:
        raise ReconciliationError("denied decisions cannot be reconciled")
    if pair.state == IdempotencyState.NO_EFFECT:
        return ReconciliationResult(
            ReconciliationStatus.ALREADY_NO_EFFECT,
            key_hash,
            confirmation.request_hash,
            None,
        )
    if pair.state in {
        IdempotencyState.SUCCESS,
        IdempotencyState.ERROR,
        IdempotencyState.TIMEOUT,
    }:
        raise ReconciliationError("completed outcomes cannot be reconciled")
    if pair.state not in {IdempotencyState.PENDING, IdempotencyState.UNKNOWN}:
        raise ReconciliationError("decision state cannot be reconciled")

    if pair.state == IdempotencyState.UNKNOWN and confirmation.status in {"applied", "unknown"}:
        status = (
            ReconciliationStatus.APPLIED
            if confirmation.status == "applied"
            else ReconciliationStatus.UNKNOWN
        )
        return ReconciliationResult(status, key_hash, confirmation.request_hash, None)

    reconciled_at = utc_timestamp(now)
    note: dict[str, Any] = {
        "source": confirmation.source,
        "confirmation_id": confirmation.confirmation_id,
        "observed_at": confirmation.observed_at,
        "confirmed_status": confirmation.status,
        "reconciled_at": reconciled_at,
    }
    if confirmation.status == "no_effect":
        outcome_status: Literal["no_effect", "unknown"] = "no_effect"
        summary = "reconciled: upstream confirmed no effect"
        result_status = ReconciliationStatus.NO_EFFECT_RECORDED
    elif pair.state == IdempotencyState.PENDING:
        outcome_status = "unknown"
        if confirmation.status == "applied":
            summary = "reconciled: upstream confirmed the effect was applied"
            result_status = ReconciliationStatus.APPLIED
        else:
            summary = "reconciled: upstream could not confirm the effect status"
            result_status = ReconciliationStatus.UNKNOWN
    else:
        raise ReconciliationError("confirmation cannot advance this decision state")

    try:
        appended = append_outcome(
            store,
            pair.decision,
            status=outcome_status,
            summary=summary,
            response_hash=None,
            reconciliation=note,
            now=now,
        )
    except Exception as exc:
        raise ReconciliationError("could not append reconciliation outcome") from exc
    return ReconciliationResult(result_status, key_hash, confirmation.request_hash, appended)
