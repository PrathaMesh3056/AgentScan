from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

import pytest

from agentscan.gateway.canonical import canonical_json
from agentscan.gateway.idempotency import (
    IdempotencyAction,
    IdempotencyIndex,
    IdempotencyRequiredError,
    IdempotencyState,
    IdempotencyStateError,
    ReceiptPairingError,
    append_outcome,
    compute_request_hash,
    hash_key,
    optional_key_hash,
    pair_receipts,
)
from agentscan.gateway.models import ErrorCode
from agentscan.gateway.receipts import (
    GENESIS_HASH,
    GatewayReceipt,
    ReceiptAuthorization,
    ReceiptChainStore,
    ReceiptEvidence,
    ReceiptResult,
    ReceiptTool,
    seal_receipt,
    utc_timestamp,
    verify_jsonl_file,
)

NOW = datetime(2026, 11, 10, 12, 0, tzinfo=UTC)
RAW_KEY = "operator-private-idempotency-key"
KEY_HASH = hash_key(RAW_KEY, max_bytes=128)
OTHER_KEY_HASH = "sha256:" + "2" * 64
REQUEST_HASH = "sha256:" + "3" * 64
OTHER_REQUEST_HASH = "sha256:" + "4" * 64
IDENTITY_HASH = "sha256:" + "5" * 64
SCHEMA_HASH = "sha256:" + "6" * 64
POLICY_HASH = "sha256:" + "7" * 64
RESPONSE_HASH = "sha256:" + "8" * 64
POLICY_KEY_ID = "ed25519:" + "9" * 64


def make_receipt(
    *,
    phase: str = "decision",
    status: str = "pending",
    trace_id: str = "trace-1",
    tenant: str = "tenant-demo",
    principal: str = "user:123",
    tool_identity_hash: str = IDENTITY_HASH,
    key_hash: str | None = KEY_HASH,
    request_hash: str = REQUEST_HASH,
    timestamp: str | None = None,
    response_hash: str | None = None,
    reconciliation: dict[str, object] | None = None,
) -> GatewayReceipt:
    denied = status == "denied"
    return GatewayReceipt(
        trace_id=trace_id,
        phase=phase,
        tenant_id=tenant,
        gateway_id="gw-1",
        chain_id="tenant-demo/gw-1",
        writer_epoch=1,
        writer_id="writer-1",
        idempotency_key=key_hash,
        principal=principal,
        agent="agent:support",
        tool=ReceiptTool(
            name="delete_record",
            server="crm-mcp",
            schema_hash=SCHEMA_HASH,
            identity_hash=tool_identity_hash,
        ),
        arguments={"record_id": "fake-1"},
        arguments_hash=OTHER_REQUEST_HASH,
        authorization=ReceiptAuthorization(
            decision="deny" if denied else "allow",
            policy_id="policy-1",
            rule_id="deny-rule" if denied else "allow-rule",
            resource_tenant_enforced="upstream",
            reason="denied" if denied else "allowed",
        ),
        policy_decision="deny" if denied else "allow",
        enforcement_mode="inline",
        effective_action="blocked" if denied else "forwarded",
        would_deny=denied,
        result=ReceiptResult(status=status, summary="fake receipt"),
        evidence=ReceiptEvidence(hash=GENESIS_HASH, prev_hash=GENESIS_HASH),
        timestamp=timestamp or utc_timestamp(NOW),
        request_hash=request_hash,
        response_hash=response_hash,
        policy_hash=POLICY_HASH,
        policy_key_id=POLICY_KEY_ID,
        decision_latency_ms=1.0,
        mcp_request_id="request-1",
        reconciliation=reconciliation,
    )


def make_outcome(
    decision: GatewayReceipt,
    status: str,
    *,
    response_hash: str | None = None,
    reconciliation: dict[str, object] | None = None,
    previous: GatewayReceipt | None = None,
) -> GatewayReceipt:
    payload = decision.model_dump(mode="python")
    payload["phase"] = "outcome"
    payload["result"] = {"status": status, "summary": f"{status} result"}
    payload["response_hash"] = response_hash
    payload["reconciliation"] = reconciliation
    payload["timestamp"] = utc_timestamp(NOW + timedelta(seconds=1))
    payload["evidence"] = {"hash": GENESIS_HASH, "prev_hash": GENESIS_HASH}
    unsigned = GatewayReceipt.model_validate(payload)
    prior = previous or decision
    return seal_receipt(unsigned, prior.evidence.hash)


def no_effect_note() -> dict[str, object]:
    return {
        "source": "upstream:check_effect",
        "confirmation_id": "confirmation-1",
        "observed_at": "2026-11-10T12:00:00.000Z",
        "confirmed_status": "no_effect",
        "reconciled_at": "2026-11-10T12:01:00.000Z",
    }


def make_store(tmp_path) -> ReceiptChainStore:
    store = ReceiptChainStore(
        tmp_path,
        tenant="tenant-demo",
        gateway_id="gw-1",
        chain_id="tenant-demo/gw-1",
        writer_id="writer-1",
    )
    store.acquire_writer_lease()
    return store


def test_hash_key_validation_exact_utf8_limit_and_no_secret_leak(tmp_path) -> None:
    raw = "caller-secret-key"
    expected = "sha256:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()
    assert hash_key(raw, max_bytes=1024) == expected
    assert hash_key("é", max_bytes=2) == "sha256:" + hashlib.sha256("é".encode()).hexdigest()
    assert hash_key("a" * 32, max_bytes=32) == "sha256:" + hashlib.sha256(b"a" * 32).hexdigest()
    assert optional_key_hash(None, max_bytes=1) is None
    assert optional_key_hash(raw, max_bytes=1024) == expected

    invalid: list[object] = [None, "", 42, object(), "a" * 33, "\ud800"]
    for value in invalid:
        with pytest.raises(IdempotencyRequiredError) as exc:
            hash_key(value, max_bytes=32)
        assert raw not in str(exc.value)
        assert exc.value.code == ErrorCode.IDEMPOTENCY_REQUIRED
    with pytest.raises(IdempotencyRequiredError):
        hash_key("x", max_bytes=0)
    with pytest.raises(IdempotencyRequiredError):
        hash_key("x", max_bytes=True)
    with pytest.raises(IdempotencyRequiredError):
        optional_key_hash("", max_bytes=32)

    store = make_store(tmp_path)
    decision = make_receipt(key_hash=expected)
    store.append(decision)
    store.close()
    serialized = store.chain_path.read_bytes() + store.wal_path.read_bytes()
    assert raw.encode() not in serialized


def test_compute_request_hash_golden_stability_and_argument_change() -> None:
    left = compute_request_hash(
        tenant="tenant-demo",
        principal="user:123",
        agent="agent:support",
        tool_identity_hash=IDENTITY_HASH,
        arguments={"name": "Mia", "count": 2},
    )
    assert left == "sha256:56d7d701e4407a2eb7c96fe6bec2c9eb75701d3a497aff8a854c072742665f18"
    assert left == compute_request_hash(
        tenant="tenant-demo",
        principal="user:123",
        agent="agent:support",
        tool_identity_hash=IDENTITY_HASH,
        arguments={"count": 2, "name": "Mia"},
    )
    assert left != compute_request_hash(
        tenant="tenant-demo",
        principal="user:123",
        agent="agent:support",
        tool_identity_hash=IDENTITY_HASH,
        arguments={"name": "Mia", "count": 3},
    )
    unicode_hash = compute_request_hash(
        tenant="tenant-demo",
        principal="user:123",
        agent="agent:support",
        tool_identity_hash=IDENTITY_HASH,
        arguments={"name": "Zoë 🦊"},
    )
    assert (
        unicode_hash
        == "sha256:"
        + hashlib.sha256(
            canonical_json(
                {
                    "tenant": "tenant-demo",
                    "principal": "user:123",
                    "agent": "agent:support",
                    "tool_identity": IDENTITY_HASH,
                    "arguments": {"name": "Zoë 🦊"},
                }
            )
        ).hexdigest()
    )
    with pytest.raises(ValueError, match="canonical JSON"):
        compute_request_hash(
            tenant="tenant-demo",
            principal="user:123",
            agent="agent:support",
            tool_identity_hash=IDENTITY_HASH,
            arguments={"not_finite": float("nan")},
        )


def test_index_scope_conflict_and_same_content_guard() -> None:
    decision = seal_receipt(make_receipt())
    index = IdempotencyIndex()
    index.rebuild((decision,), now=NOW)
    same_scope = index.check(
        tenant="tenant-demo",
        principal="user:123",
        tool_identity_hash=IDENTITY_HASH,
        key_hash=KEY_HASH,
        request_hash=OTHER_REQUEST_HASH,
        now=NOW,
    )
    assert same_scope.action == IdempotencyAction.CONFLICT
    assert same_scope.state == IdempotencyState.PENDING
    assert same_scope.prior == decision

    new_key_same_content = index.check(
        tenant="tenant-demo",
        principal="user:123",
        tool_identity_hash=IDENTITY_HASH,
        key_hash=OTHER_KEY_HASH,
        request_hash=REQUEST_HASH,
        now=NOW,
    )
    assert new_key_same_content.action == IdempotencyAction.OUTCOME_UNKNOWN
    assert new_key_same_content.prior == decision

    for scope in (
        {"tenant": "tenant-other", "principal": "user:123", "tool_identity_hash": IDENTITY_HASH},
        {"tenant": "tenant-demo", "principal": "user:other", "tool_identity_hash": IDENTITY_HASH},
        {
            "tenant": "tenant-demo",
            "principal": "user:123",
            "tool_identity_hash": OTHER_REQUEST_HASH,
        },
    ):
        isolated = index.check(
            **scope,
            key_hash=OTHER_KEY_HASH,
            request_hash=REQUEST_HASH,
            now=NOW,
        )
        assert isolated.action == IdempotencyAction.PROCEED
        assert isolated.state == IdempotencyState.NEW

    with pytest.raises(IdempotencyRequiredError):
        index.check(
            tenant="tenant-demo",
            principal="user:123",
            tool_identity_hash=IDENTITY_HASH,
            key_hash="",
            request_hash=REQUEST_HASH,
            now=NOW,
        )


def test_index_states_replay_denied_skip_expiry_and_no_effect_guard_clear() -> None:
    for status, expected_state in (
        ("pending", IdempotencyState.PENDING),
        ("unknown", IdempotencyState.UNKNOWN),
        ("success", IdempotencyState.SUCCESS),
        ("error", IdempotencyState.ERROR),
        ("timeout", IdempotencyState.TIMEOUT),
        ("no_effect", IdempotencyState.NO_EFFECT),
    ):
        decision = seal_receipt(make_receipt())
        if status == "pending":
            history = (decision,)
        elif status == "no_effect":
            unknown = make_outcome(decision, "unknown")
            outcome = make_outcome(
                decision,
                status,
                reconciliation=no_effect_note(),
                previous=unknown,
            )
            history = (decision, unknown, outcome)
        else:
            outcome = make_outcome(
                decision,
                status,
                response_hash=RESPONSE_HASH if status in {"success", "error", "timeout"} else None,
            )
            history = (decision, outcome)
        index = IdempotencyIndex()
        index.rebuild(history, now=NOW)
        same = index.check(
            tenant="tenant-demo",
            principal="user:123",
            tool_identity_hash=IDENTITY_HASH,
            key_hash=KEY_HASH,
            request_hash=REQUEST_HASH,
            now=NOW,
        )
        assert same.state == expected_state
        if status == "pending" or status == "unknown":
            assert same.action == IdempotencyAction.OUTCOME_UNKNOWN
        else:
            assert same.action == IdempotencyAction.REPLAY
            assert same.outcome == history[-1]
        new_key = index.check(
            tenant="tenant-demo",
            principal="user:123",
            tool_identity_hash=IDENTITY_HASH,
            key_hash=OTHER_KEY_HASH,
            request_hash=REQUEST_HASH,
            now=NOW,
        )
        assert new_key.action == (
            IdempotencyAction.OUTCOME_UNKNOWN
            if status in {"pending", "unknown"}
            else IdempotencyAction.PROCEED
        )

    denied = seal_receipt(make_receipt(status="denied"))
    denied_index = IdempotencyIndex()
    denied_index.rebuild((denied,), now=NOW)
    assert (
        denied_index.check(
            tenant="tenant-demo",
            principal="user:123",
            tool_identity_hash=IDENTITY_HASH,
            key_hash=KEY_HASH,
            request_hash=REQUEST_HASH,
            now=NOW,
        ).action
        == IdempotencyAction.PROCEED
    )

    expired_decision = seal_receipt(make_receipt(timestamp=utc_timestamp(NOW - timedelta(days=31))))
    expired_index = IdempotencyIndex()
    expired_index.rebuild((expired_decision,), now=NOW)
    assert (
        expired_index.check(
            tenant="tenant-demo",
            principal="user:123",
            tool_identity_hash=IDENTITY_HASH,
            key_hash=KEY_HASH,
            request_hash=REQUEST_HASH,
            now=NOW,
        ).action
        == IdempotencyAction.PROCEED
    )


def test_expired_pending_decision_no_longer_triggers_content_guard() -> None:
    old_pending = seal_receipt(make_receipt(timestamp=utc_timestamp(NOW - timedelta(days=29))))
    index = IdempotencyIndex()
    index.rebuild((old_pending,), now=NOW)
    assert (
        index.check(
            tenant="tenant-demo",
            principal="user:123",
            tool_identity_hash=IDENTITY_HASH,
            key_hash=OTHER_KEY_HASH,
            request_hash=REQUEST_HASH,
            now=NOW,
        ).action
        == IdempotencyAction.OUTCOME_UNKNOWN
    )
    assert (
        index.check(
            tenant="tenant-demo",
            principal="user:123",
            tool_identity_hash=IDENTITY_HASH,
            key_hash=OTHER_KEY_HASH,
            request_hash=REQUEST_HASH,
            now=NOW + timedelta(days=2),
        ).action
        == IdempotencyAction.PROCEED
    )


def test_pairing_rejects_orphans_duplicates_mismatches_and_bad_transitions() -> None:
    decision = seal_receipt(make_receipt())
    success = make_outcome(decision, "success", response_hash=RESPONSE_HASH)
    with pytest.raises(ReceiptPairingError, match="preceding decision"):
        pair_receipts((success,))
    with pytest.raises(ReceiptPairingError, match="duplicate decision"):
        pair_receipts((decision, decision))

    mismatch_payload = decision.model_dump(mode="python")
    mismatch_payload.update(
        {
            "phase": "outcome",
            "result": {"status": "success", "summary": "done"},
            "response_hash": RESPONSE_HASH,
            "timestamp": utc_timestamp(NOW + timedelta(seconds=1)),
            "evidence": {"hash": GENESIS_HASH, "prev_hash": decision.evidence.hash},
            "principal": "user:other",
        }
    )
    mismatch = seal_receipt(GatewayReceipt.model_validate(mismatch_payload), decision.evidence.hash)
    with pytest.raises(ReceiptPairingError, match="does not match"):
        pair_receipts((decision, mismatch))

    bad_hash = success.model_copy(update={"response_hash": None})
    with pytest.raises(ReceiptPairingError, match="missing a valid response hash"):
        pair_receipts((decision, bad_hash))
    bad_decision = decision.model_copy(update={"response_hash": RESPONSE_HASH})
    with pytest.raises(ReceiptPairingError, match="decision receipt"):
        pair_receipts((bad_decision,))

    denied = seal_receipt(make_receipt(status="denied"))
    denied_outcome = make_outcome(denied, "unknown")
    with pytest.raises(ReceiptPairingError, match="denied decision"):
        pair_receipts((denied, denied_outcome))

    error_after_success = make_outcome(
        decision, "error", response_hash=RESPONSE_HASH, previous=success
    )
    with pytest.raises(ReceiptPairingError, match="transition"):
        pair_receipts((decision, success, error_after_success))
    unknown = make_outcome(decision, "unknown")
    success_after_unknown = make_outcome(
        decision, "success", response_hash=RESPONSE_HASH, previous=unknown
    )
    with pytest.raises(ReceiptPairingError, match="transition"):
        pair_receipts((decision, unknown, success_after_unknown))
    no_note = make_outcome(decision, "no_effect")
    with pytest.raises(ReceiptPairingError, match="reconciliation note"):
        pair_receipts((decision, no_note))


def test_append_outcome_state_machine_response_hash_and_chain(tmp_path) -> None:
    store = make_store(tmp_path)
    decision = store.append(make_receipt())
    assert verify_jsonl_file(store.chain_path).head_hash == decision.evidence.hash

    with pytest.raises(IdempotencyStateError, match="valid response hash"):
        append_outcome(store, decision, status="success", summary="done", response_hash=None)
    success = append_outcome(
        store,
        decision,
        status="success",
        summary="done",
        response_hash=RESPONSE_HASH,
        now=NOW + timedelta(seconds=1),
    )
    assert success.phase == "outcome"
    assert success.response_hash == RESPONSE_HASH
    assert verify_jsonl_file(store.chain_path).head_hash == success.evidence.hash
    with pytest.raises(IdempotencyStateError, match="terminal"):
        append_outcome(store, decision, status="unknown", summary="again", response_hash=None)
    store.close()


def test_unknown_can_only_be_closed_with_no_effect(tmp_path) -> None:
    store = make_store(tmp_path)
    decision = store.append(make_receipt())
    unknown = append_outcome(
        store, decision, status="unknown", summary="unknown", response_hash=None
    )
    with pytest.raises(IdempotencyStateError, match="only transition"):
        append_outcome(
            store,
            decision,
            status="success",
            summary="late success",
            response_hash=RESPONSE_HASH,
        )
    no_effect = append_outcome(
        store,
        decision,
        status="no_effect",
        summary="confirmed no effect",
        response_hash=None,
        reconciliation=no_effect_note(),
        now=NOW + timedelta(minutes=2),
    )
    assert no_effect.evidence.prev_hash == unknown.evidence.hash
    assert pair_receipts(store.receipts)[0].state == IdempotencyState.NO_EFFECT
    assert verify_jsonl_file(store.chain_path).receipts == store.receipts
    store.close()


def test_append_outcome_requires_stored_decision_and_writer_lease(tmp_path) -> None:
    store = make_store(tmp_path)
    unstored = seal_receipt(make_receipt(trace_id="not-stored"))
    with pytest.raises(IdempotencyStateError, match="not present"):
        append_outcome(store, unstored, status="unknown", summary="x", response_hash=None)
    store.close()
    with pytest.raises(IdempotencyStateError, match="lease"):
        append_outcome(store, unstored, status="unknown", summary="x", response_hash=None)


def test_record_and_rebuild_indexes_produce_same_checks(tmp_path) -> None:
    store = make_store(tmp_path)
    incremental = IdempotencyIndex()
    decision = store.append(make_receipt())
    incremental.record(decision, now=NOW)
    outcome = append_outcome(
        store,
        decision,
        status="unknown",
        summary="unknown",
        response_hash=None,
        now=NOW + timedelta(seconds=1),
    )
    incremental.record(outcome, now=NOW + timedelta(seconds=1))
    rebuilt = IdempotencyIndex()
    rebuilt.rebuild(store.receipts, now=NOW + timedelta(seconds=1))
    checks = {
        "same": (KEY_HASH, REQUEST_HASH),
        "same-key-conflict": (KEY_HASH, OTHER_REQUEST_HASH),
        "content-guard": (OTHER_KEY_HASH, REQUEST_HASH),
        "other-content": (OTHER_KEY_HASH, OTHER_REQUEST_HASH),
    }
    for key, (key_hash, request_hash) in checks.items():
        query = dict(
            tenant="tenant-demo",
            principal="user:123",
            tool_identity_hash=IDENTITY_HASH,
            key_hash=key_hash,
            request_hash=request_hash,
            now=NOW + timedelta(seconds=1),
        )
        assert incremental.check(**query) == rebuilt.check(**query), key
    store.close()


def test_record_rejects_invalid_outcome_without_mutating_index() -> None:
    decision = seal_receipt(make_receipt())
    index = IdempotencyIndex()
    index.record(decision, now=NOW)
    invalid_success = make_outcome(decision, "success", response_hash=None)
    with pytest.raises(ReceiptPairingError, match="valid response hash"):
        index.record(invalid_success, now=NOW)
    state = index.check(
        tenant="tenant-demo",
        principal="user:123",
        tool_identity_hash=IDENTITY_HASH,
        key_hash=KEY_HASH,
        request_hash=REQUEST_HASH,
        now=NOW,
    )
    assert state.action == IdempotencyAction.OUTCOME_UNKNOWN
    assert state.state == IdempotencyState.PENDING


def test_index_rejects_two_active_decisions_with_same_key_scope() -> None:
    first = seal_receipt(make_receipt(trace_id="trace-1"))
    second = seal_receipt(make_receipt(trace_id="trace-2"), first.evidence.hash)
    with pytest.raises(ReceiptPairingError, match="multiple active decisions"):
        IdempotencyIndex().rebuild((first, second), now=NOW)


def test_hash_error_messages_never_include_raw_key() -> None:
    raw = "very-sensitive-key-value"
    with pytest.raises(IdempotencyRequiredError) as exc:
        optional_key_hash(raw, max_bytes=1)
    assert raw not in str(exc.value)
    assert exc.value.code == ErrorCode.IDEMPOTENCY_REQUIRED
