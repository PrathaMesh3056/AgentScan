"""Retry-safe idempotency state built from the durable gateway receipt chain."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from agentscan.gateway.canonical import canonical_json
from agentscan.gateway.models import ErrorCode
from agentscan.gateway.receipts import (
    GENESIS_HASH,
    GatewayReceipt,
    ReceiptChainStore,
    RetentionDedupeIndex,
    utc_timestamp,
)

_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class IdempotencyError(ValueError):
    """Base failure for an idempotency request; messages never include inputs."""

    def __init__(self, code: ErrorCode, message: str) -> None:
        self.code = code
        super().__init__(message)


class IdempotencyRequiredError(IdempotencyError):
    def __init__(self, message: str = "a valid idempotency key is required") -> None:
        super().__init__(ErrorCode.IDEMPOTENCY_REQUIRED, message)


class IdempotencyConflictError(IdempotencyError):
    def __init__(self, message: str = "idempotency key conflicts with the request") -> None:
        super().__init__(ErrorCode.IDEMPOTENCY_CONFLICT, message)


class IdempotencyStateError(IdempotencyError):
    def __init__(self, message: str = "idempotency state is invalid or unknown") -> None:
        super().__init__(ErrorCode.OUTCOME_UNKNOWN, message)


class ReceiptPairingError(IdempotencyStateError):
    """Receipt decisions and outcomes cannot be paired as a valid state history."""


class IdempotencyState(StrEnum):
    NEW = "NEW"
    PENDING = "PENDING"
    UNKNOWN = "UNKNOWN"
    SUCCESS = "SUCCESS"
    ERROR = "ERROR"
    TIMEOUT = "TIMEOUT"
    NO_EFFECT = "NO_EFFECT"
    DENIED = "DENIED"


class IdempotencyAction(StrEnum):
    PROCEED = "PROCEED"
    REPLAY = "REPLAY"
    OUTCOME_UNKNOWN = "OUTCOME_UNKNOWN"
    CONFLICT = "CONFLICT"


@dataclass(frozen=True, slots=True)
class ReceiptPair:
    decision: GatewayReceipt
    outcomes: tuple[GatewayReceipt, ...]

    @property
    def state(self) -> IdempotencyState:
        if self.decision.result.status == "denied":
            return IdempotencyState.DENIED
        if not self.outcomes:
            return IdempotencyState.PENDING
        return IdempotencyState(self.outcomes[-1].result.status.upper())

    @property
    def outcome(self) -> GatewayReceipt | None:
        return self.outcomes[-1] if self.outcomes else None


def _valid_hash(value: object) -> bool:
    return isinstance(value, str) and _HASH_RE.fullmatch(value) is not None


def _check_max_bytes(max_bytes: int) -> None:
    if type(max_bytes) is not int or not 1 <= max_bytes <= 1024:
        raise IdempotencyRequiredError("max idempotency key bytes must be between 1 and 1024")


def hash_key(raw_key: object, *, max_bytes: int) -> str:
    """Hash exact UTF-8 key bytes; never normalize or expose the raw key."""
    _check_max_bytes(max_bytes)
    if not isinstance(raw_key, str) or not raw_key:
        raise IdempotencyRequiredError()
    try:
        encoded = raw_key.encode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise IdempotencyRequiredError() from exc
    if len(encoded) > max_bytes:
        raise IdempotencyRequiredError()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def optional_key_hash(raw_key: object | None, *, max_bytes: int) -> str | None:
    _check_max_bytes(max_bytes)
    if raw_key is None:
        return None
    return hash_key(raw_key, max_bytes=max_bytes)


def compute_request_hash(
    *,
    tenant: str,
    principal: str,
    agent: str,
    tool_identity_hash: str,
    arguments: Mapping[str, Any],
) -> str:
    """Hash the canonical request identity and arguments, excluding retry metadata."""
    if not isinstance(arguments, Mapping):
        raise IdempotencyError(
            ErrorCode.GATEWAY_UNAVAILABLE, "request arguments are not canonical JSON"
        )
    payload = {
        "tenant": tenant,
        "principal": principal,
        "agent": agent,
        "tool_identity": tool_identity_hash,
        "arguments": arguments,
    }
    try:
        data = canonical_json(payload)
    except (TypeError, ValueError) as exc:
        raise IdempotencyError(
            ErrorCode.GATEWAY_UNAVAILABLE, "request cannot be represented as canonical JSON"
        ) from exc
    return "sha256:" + hashlib.sha256(data).hexdigest()


_PAIR_FIELDS = (
    "tenant_id",
    "gateway_id",
    "chain_id",
    "trace_id",
    "idempotency_key",
    "principal",
    "agent",
    "arguments_hash",
    "request_hash",
    "policy_hash",
    "policy_key_id",
    "policy_decision",
    "enforcement_mode",
    "effective_action",
    "would_deny",
)
_TOOL_FIELDS = ("name", "server", "identity_hash")
_AUTHORIZATION_FIELDS = (
    "decision",
    "policy_id",
    "rule_id",
    "resource_tenant_enforced",
    "reason",
)


def _receipt_value(receipt: GatewayReceipt, field: str) -> Any:
    return getattr(receipt, field)


def _validate_response_hash(receipt: GatewayReceipt) -> None:
    status = receipt.result.status
    if receipt.phase == "decision":
        if receipt.response_hash is not None:
            raise ReceiptPairingError("decision receipt has a response hash")
    elif status in {"unknown", "no_effect"}:
        if receipt.response_hash is not None:
            raise ReceiptPairingError("unknown/no_effect outcome has a response hash")
    elif status in {"success", "error", "timeout"} and not _valid_hash(receipt.response_hash):
        raise ReceiptPairingError("completed outcome is missing a valid response hash")


def _validate_no_effect_note(receipt: GatewayReceipt) -> None:
    note = receipt.reconciliation
    required = {"source", "confirmation_id", "observed_at", "confirmed_status", "reconciled_at"}
    if not isinstance(note, dict) or not required.issubset(note):
        raise ReceiptPairingError("no_effect outcome is missing its reconciliation note")
    if note.get("confirmed_status") != "no_effect":
        raise ReceiptPairingError("no_effect outcome lacks a no_effect confirmation")
    if any(
        not isinstance(note.get(key), str) or not note[key].strip()
        for key in required - {"confirmed_status"}
    ):
        raise ReceiptPairingError("no_effect reconciliation note is incomplete")


def _validate_pair(decision: GatewayReceipt, outcomes: tuple[GatewayReceipt, ...]) -> ReceiptPair:
    if decision.phase != "decision":
        raise ReceiptPairingError("pair does not start with a decision")
    _validate_response_hash(decision)
    if decision.result.status == "denied" and outcomes:
        raise ReceiptPairingError("denied decision cannot have an outcome")
    for outcome in outcomes:
        if outcome.phase != "outcome":
            raise ReceiptPairingError("paired receipt is not an outcome")
        for field in _PAIR_FIELDS:
            if _receipt_value(decision, field) != _receipt_value(outcome, field):
                raise ReceiptPairingError("outcome does not match its decision")
        for field in _TOOL_FIELDS:
            if getattr(decision.tool, field) != getattr(outcome.tool, field):
                raise ReceiptPairingError("outcome tool does not match its decision")
        for field in _AUTHORIZATION_FIELDS:
            if getattr(decision.authorization, field) != getattr(outcome.authorization, field):
                raise ReceiptPairingError("outcome authorization does not match its decision")
        _validate_response_hash(outcome)
    if len(outcomes) > 1 and (
        len(outcomes) != 2
        or outcomes[0].result.status != "unknown"
        or outcomes[1].result.status != "no_effect"
    ):
        raise ReceiptPairingError("invalid outcome transition")
    if outcomes and outcomes[0].result.status == "no_effect":
        _validate_no_effect_note(outcomes[0])
    if len(outcomes) == 2:
        _validate_no_effect_note(outcomes[1])
    return ReceiptPair(decision=decision, outcomes=outcomes)


def pair_receipts(receipts: Iterable[GatewayReceipt]) -> tuple[ReceiptPair, ...]:
    """Pair ordered decisions and outcomes, rejecting any invalid state history."""
    decisions: dict[str, GatewayReceipt] = {}
    outcomes: dict[str, list[GatewayReceipt]] = {}
    order: list[str] = []
    for receipt in receipts:
        if receipt.phase == "handoff":
            continue
        _validate_response_hash(receipt)
        if receipt.phase == "decision":
            if receipt.trace_id in decisions:
                raise ReceiptPairingError("duplicate decision trace id")
            decisions[receipt.trace_id] = receipt
            outcomes[receipt.trace_id] = []
            order.append(receipt.trace_id)
            continue
        if receipt.phase != "outcome":
            raise ReceiptPairingError("unsupported receipt phase")
        decision = decisions.get(receipt.trace_id)
        if decision is None:
            raise ReceiptPairingError("outcome has no preceding decision")
        candidate = (*outcomes[receipt.trace_id], receipt)
        _validate_pair(decision, candidate)
        outcomes[receipt.trace_id].append(receipt)
    return tuple(
        _validate_pair(decisions[trace_id], tuple(outcomes[trace_id])) for trace_id in order
    )


@dataclass(frozen=True, slots=True)
class IdempotencyDecision:
    action: IdempotencyAction
    state: IdempotencyState
    key_hash: str
    request_hash: str
    prior: GatewayReceipt | None = None
    outcome: GatewayReceipt | None = None


_KeyScope = tuple[str, str, str, str]
_ContentScope = tuple[str, str, str, str]


class IdempotencyIndex:
    """In-memory retry index rebuilt from and incrementally updated by receipts."""

    def __init__(self, retention_days: int = 30) -> None:
        self._retention = RetentionDedupeIndex(retention_days=retention_days)
        self.retention_days = retention_days
        self._receipts: list[GatewayReceipt] = []
        self._pairs: dict[str, ReceiptPair] = {}
        self._by_key: dict[_KeyScope, ReceiptPair] = {}
        self._by_content: dict[_ContentScope, list[ReceiptPair]] = {}

    @staticmethod
    def _key_scope(decision: GatewayReceipt) -> _KeyScope | None:
        if decision.idempotency_key is None:
            return None
        return (
            decision.tenant_id,
            decision.principal,
            decision.tool.identity_hash,
            decision.idempotency_key,
        )

    @staticmethod
    def _content_scope(decision: GatewayReceipt) -> _ContentScope:
        return (
            decision.tenant_id,
            decision.principal,
            decision.tool.identity_hash,
            decision.request_hash,
        )

    def _build_indexes(
        self, pairs: Iterable[ReceiptPair], now: datetime | None
    ) -> tuple[dict[_KeyScope, ReceiptPair], dict[_ContentScope, list[ReceiptPair]]]:
        by_key: dict[_KeyScope, ReceiptPair] = {}
        by_content: dict[_ContentScope, list[ReceiptPair]] = {}
        for pair in pairs:
            decision = pair.decision
            if pair.state == IdempotencyState.DENIED:
                continue
            key_scope = self._key_scope(decision)
            if key_scope is None:
                continue
            if self._retention.is_expired(decision.timestamp, now):
                continue
            if key_scope in by_key:
                raise ReceiptPairingError(
                    "multiple active decisions share an idempotency key scope"
                )
            by_key[key_scope] = pair
            by_content.setdefault(self._content_scope(decision), []).append(pair)
        return by_key, by_content

    def rebuild(self, receipts: Iterable[GatewayReceipt], *, now: datetime | None = None) -> None:
        receipt_list = list(receipts)
        pairs = pair_receipts(receipt_list)
        pair_map = {pair.decision.trace_id: pair for pair in pairs}
        by_key, by_content = self._build_indexes(pairs, now)
        self._receipts = receipt_list
        self._pairs = pair_map
        self._by_key = by_key
        self._by_content = by_content

    def record(self, receipt: GatewayReceipt, *, now: datetime | None = None) -> None:
        if receipt.phase == "handoff":
            self._receipts.append(receipt)
            return
        if receipt.phase == "decision":
            if receipt.trace_id in self._pairs:
                raise ReceiptPairingError("duplicate decision trace id")
            pair = _validate_pair(receipt, ())
            key_scope = None if pair.state == IdempotencyState.DENIED else self._key_scope(receipt)
            if key_scope is not None:
                prior = self._by_key.get(key_scope)
                if prior is not None and not self._retention.is_expired(
                    prior.decision.timestamp, now
                ):
                    raise ReceiptPairingError(
                        "multiple active decisions share an idempotency key scope"
                    )
            self._pairs[receipt.trace_id] = pair
            self._receipts.append(receipt)
            if key_scope is None or self._retention.is_expired(receipt.timestamp, now):
                return
            self._by_key[key_scope] = pair
            self._by_content.setdefault(self._content_scope(receipt), []).append(pair)
            return
        if receipt.phase != "outcome":
            raise ReceiptPairingError("unsupported receipt phase")
        prior_pair = self._pairs.get(receipt.trace_id)
        if prior_pair is None:
            raise ReceiptPairingError("outcome has no preceding decision")
        pair = _validate_pair(prior_pair.decision, (*prior_pair.outcomes, receipt))
        key_scope = (
            None
            if prior_pair.state == IdempotencyState.DENIED
            else self._key_scope(prior_pair.decision)
        )
        self._pairs[receipt.trace_id] = pair
        self._receipts.append(receipt)
        if key_scope is None:
            return
        if self._by_key.get(key_scope) is prior_pair:
            if self._retention.is_expired(pair.decision.timestamp, now):
                del self._by_key[key_scope]
            else:
                self._by_key[key_scope] = pair
        content_scope = self._content_scope(prior_pair.decision)
        entries = self._by_content.get(content_scope)
        if entries is not None:
            for index, item in enumerate(entries):
                if item.decision.trace_id == receipt.trace_id:
                    if self._retention.is_expired(pair.decision.timestamp, now):
                        entries.pop(index)
                    else:
                        entries[index] = pair
                    break

    def check(
        self,
        *,
        tenant: str,
        principal: str,
        tool_identity_hash: str,
        key_hash: str,
        request_hash: str,
        now: datetime | None = None,
    ) -> IdempotencyDecision:
        if not _valid_hash(key_hash):
            raise IdempotencyRequiredError()
        if not _valid_hash(request_hash):
            raise IdempotencyStateError("request hash is invalid")
        key_scope = (tenant, principal, tool_identity_hash, key_hash)
        prior_pair = self._by_key.get(key_scope)
        if prior_pair is not None and self._retention.is_expired(
            prior_pair.decision.timestamp, now
        ):
            prior_pair = None
        if prior_pair is not None:
            state = prior_pair.state
            if prior_pair.decision.request_hash != request_hash:
                return IdempotencyDecision(
                    IdempotencyAction.CONFLICT,
                    state,
                    key_hash,
                    request_hash,
                    prior_pair.decision,
                    prior_pair.outcome,
                )
            if state in {IdempotencyState.PENDING, IdempotencyState.UNKNOWN}:
                return IdempotencyDecision(
                    IdempotencyAction.OUTCOME_UNKNOWN,
                    state,
                    key_hash,
                    request_hash,
                    prior_pair.decision,
                    prior_pair.outcome,
                )
            return IdempotencyDecision(
                IdempotencyAction.REPLAY,
                state,
                key_hash,
                request_hash,
                prior_pair.decision,
                prior_pair.outcome,
            )

        content_scope = (tenant, principal, tool_identity_hash, request_hash)
        for pair in self._by_content.get(content_scope, ()):
            if self._retention.is_expired(pair.decision.timestamp, now):
                continue
            if pair.state in {IdempotencyState.PENDING, IdempotencyState.UNKNOWN}:
                return IdempotencyDecision(
                    IdempotencyAction.OUTCOME_UNKNOWN,
                    pair.state,
                    key_hash,
                    request_hash,
                    pair.decision,
                    pair.outcome,
                )
        return IdempotencyDecision(
            IdempotencyAction.PROCEED, IdempotencyState.NEW, key_hash, request_hash
        )


def _validate_note(
    note: Mapping[str, Any] | None, *, confirmed_status: str | None = None
) -> dict[str, Any]:
    if note is None:
        raise IdempotencyStateError("no_effect requires an explicit reconciliation note")
    result = dict(note)
    required = {"source", "confirmation_id", "observed_at", "confirmed_status", "reconciled_at"}
    if not required.issubset(result):
        raise IdempotencyStateError("reconciliation note is incomplete")
    if confirmed_status is not None and result.get("confirmed_status") != confirmed_status:
        raise IdempotencyStateError("reconciliation status does not match the outcome")
    if any(
        not isinstance(result.get(key), str) or not result[key].strip()
        for key in required - {"confirmed_status"}
    ):
        raise IdempotencyStateError("reconciliation note is incomplete")
    return result


def append_outcome(
    store: ReceiptChainStore,
    decision: GatewayReceipt,
    *,
    status: Literal["success", "error", "timeout", "unknown", "no_effect"],
    summary: str,
    response_hash: str | None,
    reconciliation: Mapping[str, Any] | None = None,
    now: datetime | None = None,
) -> GatewayReceipt:
    """Append one legal outcome for a durable decision under the held writer lease."""
    if not store.lease_held:
        raise IdempotencyStateError("writer lease is required to append an outcome")
    if decision.phase != "decision":
        raise IdempotencyStateError("outcome requires a decision receipt")
    trace_receipts = store.receipts_for_trace(decision.trace_id)
    stored = [receipt for receipt in trace_receipts if receipt.phase == "decision"]
    if len(stored) != 1 or stored[0] != decision:
        raise IdempotencyStateError("decision is not present in the receipt store")
    ordered = tuple(receipt for receipt in trace_receipts if receipt.phase != "handoff")
    if not ordered or ordered[0] != decision:
        raise IdempotencyStateError("receipt state is invalid")
    try:
        pair = _validate_pair(decision, ordered[1:])
    except ReceiptPairingError as exc:
        raise IdempotencyStateError("receipt state is invalid") from exc
    if pair.state not in {IdempotencyState.PENDING, IdempotencyState.UNKNOWN}:
        raise IdempotencyStateError("decision is already terminal")
    if pair.state == IdempotencyState.UNKNOWN and status != "no_effect":
        raise IdempotencyStateError("unknown decisions may only transition to no_effect")
    if status in {"success", "error", "timeout"}:
        if not _valid_hash(response_hash):
            raise IdempotencyStateError("completed outcome requires a valid response hash")
    elif response_hash is not None:
        raise IdempotencyStateError("unknown/no_effect outcomes require a null response hash")
    note: dict[str, Any] | None = None
    if status == "no_effect":
        note = _validate_note(reconciliation, confirmed_status="no_effect")
    elif reconciliation is not None:
        note = dict(reconciliation)

    payload = decision.model_dump(mode="python")
    payload["phase"] = "outcome"
    payload["result"] = {"status": status, "summary": summary}
    payload["response_hash"] = response_hash
    payload["reconciliation"] = note
    payload["timestamp"] = utc_timestamp(now)
    payload["evidence"] = {
        "hash": GENESIS_HASH,
        "prev_hash": decision.evidence.hash,
    }
    try:
        candidate = GatewayReceipt.model_validate(payload)
        _validate_pair(decision, (*pair.outcomes, candidate))
    except (ValueError, TypeError) as exc:
        if isinstance(exc, IdempotencyError):
            raise
        raise IdempotencyStateError("outcome receipt is invalid") from exc
    return store.append(candidate)
