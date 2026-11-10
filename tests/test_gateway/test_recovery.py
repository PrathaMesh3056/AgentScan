from __future__ import annotations

import inspect
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from agentscan.gateway.idempotency import (
    IdempotencyAction,
    IdempotencyIndex,
    IdempotencyState,
    append_outcome,
    hash_key,
    pair_receipts,
)
from agentscan.gateway.receipts import (
    GENESIS_HASH,
    GatewayReceipt,
    ReceiptAuthorization,
    ReceiptChainStore,
    ReceiptEvidence,
    ReceiptResult,
    ReceiptTool,
    utc_timestamp,
    verify_jsonl_file,
)
from agentscan.gateway.recovery import (
    ReconciliationError,
    ReconciliationStatus,
    RecoveryError,
    UpstreamConfirmation,
    reconcile,
    recover,
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
    key_hash: str | None = KEY_HASH,
    request_hash: str = REQUEST_HASH,
    response_hash: str | None = None,
    reconciliation: dict[str, object] | None = None,
    timestamp: str | None = None,
    principal: str = "user:123",
) -> GatewayReceipt:
    denied = status == "denied"
    return GatewayReceipt(
        trace_id=trace_id,
        phase=phase,
        tenant_id="tenant-demo",
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
            identity_hash=IDENTITY_HASH,
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


def add_decision(
    store: ReceiptChainStore,
    *,
    trace_id: str = "trace-1",
    key_hash: str | None = KEY_HASH,
    request_hash: str = REQUEST_HASH,
    status: str = "pending",
    principal: str = "user:123",
) -> GatewayReceipt:
    return store.append(
        make_receipt(
            trace_id=trace_id,
            key_hash=key_hash,
            request_hash=request_hash,
            status=status,
            principal=principal,
        )
    )


def confirmation(
    *,
    status: str = "no_effect",
    key_hash: str = KEY_HASH,
    request_hash: str = REQUEST_HASH,
    authenticated: bool = True,
    confirmation_id: str = "confirmation-1",
    observed_at: str = "2026-11-10T12:00:00+00:00",
) -> UpstreamConfirmation:
    return UpstreamConfirmation(
        status=status,
        key_hash=key_hash,
        request_hash=request_hash,
        confirmation_id=confirmation_id,
        observed_at=observed_at,
        authenticated=authenticated,
    )


def test_recovery_empty_completed_denied_and_unknown_chains_append_nothing(tmp_path) -> None:
    empty = make_store(tmp_path / "empty")
    empty_report = recover(empty, now=NOW)
    assert (empty_report.pending_before, empty_report.unknowns_appended) == (0, 0)
    assert empty_report.receipt_count == 0
    empty.close()

    completed = make_store(tmp_path / "completed")
    decision = add_decision(completed)
    append_outcome(
        completed,
        decision,
        status="success",
        summary="done",
        response_hash=RESPONSE_HASH,
        now=NOW + timedelta(seconds=1),
    )
    denied = add_decision(completed, trace_id="denied", status="denied", key_hash=OTHER_KEY_HASH)
    assert denied.result.status == "denied"
    completed_count = len(completed.receipts)
    completed_report = recover(completed, now=NOW)
    assert completed_report.unknowns_appended == 0
    assert len(completed.receipts) == completed_count
    completed.close()

    unknown_store = make_store(tmp_path / "unknown")
    unknown_decision = add_decision(unknown_store)
    append_outcome(
        unknown_store,
        unknown_decision,
        status="unknown",
        summary="unknown already recorded",
        response_hash=None,
        now=NOW + timedelta(seconds=1),
    )
    count = len(unknown_store.receipts)
    assert recover(unknown_store, now=NOW).unknowns_appended == 0
    assert len(unknown_store.receipts) == count
    unknown_store.close()


def test_recovery_closes_each_pending_once_with_required_note(tmp_path) -> None:
    store = make_store(tmp_path)
    first = add_decision(store, trace_id="trace-1")
    second = add_decision(store, trace_id="trace-2", key_hash=OTHER_KEY_HASH)
    report = recover(store, now=NOW)
    assert report.pending_before == 2
    assert report.unknowns_appended == 2
    assert report.pending_trace_ids == ("trace-1", "trace-2")
    assert report.receipt_count == 4
    assert report.chain_head == store.head_hash
    pairs = pair_receipts(store.receipts)
    for pair in pairs:
        assert pair.state == IdempotencyState.UNKNOWN
        outcome = pair.outcome
        assert outcome is not None
        assert outcome.result.status == "unknown"
        assert outcome.result.summary == "crash recovery: outcome not recorded"
        assert outcome.response_hash is None
        assert outcome.reconciliation == {
            "source": "startup_recovery",
            "reason": "outcome_not_recorded",
            "recovered_at": utc_timestamp(NOW),
        }
    assert verify_jsonl_file(store.chain_path).receipts == store.receipts
    again = recover(store, now=NOW + timedelta(minutes=1))
    assert again.pending_before == 0
    assert again.unknowns_appended == 0
    assert len(store.receipts) == 4
    assert (
        report.index.check(
            tenant="tenant-demo",
            principal="user:123",
            tool_identity_hash=IDENTITY_HASH,
            key_hash=KEY_HASH,
            request_hash=REQUEST_HASH,
            now=NOW,
        ).action
        == IdempotencyAction.OUTCOME_UNKNOWN
    )
    assert first.trace_id != second.trace_id
    store.close()


def test_recovery_requires_lease_and_verified_cache_match(tmp_path) -> None:
    store = make_store(tmp_path)
    add_decision(store)
    store.close()
    before = store.chain_path.read_bytes()
    with pytest.raises(RecoveryError, match="writer lease"):
        recover(store, now=NOW)
    assert store.chain_path.read_bytes() == before

    store.acquire_writer_lease()
    store._head_hash = OTHER_REQUEST_HASH
    with pytest.raises(RecoveryError, match="cache"):
        recover(store, now=NOW)
    assert len(store.receipts) == 1
    store.close()


def test_invalid_pairing_fails_recovery_without_append(tmp_path) -> None:
    store = make_store(tmp_path)
    decision = add_decision(store)
    payload = decision.model_dump(mode="python")
    payload.update(
        {
            "phase": "outcome",
            "principal": "user:other",
            "result": {"status": "success", "summary": "bad pair"},
            "response_hash": RESPONSE_HASH,
            "timestamp": utc_timestamp(NOW + timedelta(seconds=1)),
            "evidence": {"hash": GENESIS_HASH, "prev_hash": decision.evidence.hash},
        }
    )
    store.append(GatewayReceipt.model_validate(payload))
    count = len(store.receipts)
    with pytest.raises(RecoveryError, match="cannot be paired"):
        recover(store, now=NOW)
    assert len(store.receipts) == count
    store.close()


def test_append_failure_leaves_durable_progress_for_next_recovery(tmp_path, monkeypatch) -> None:
    store = make_store(tmp_path)
    add_decision(store, trace_id="trace-1")
    add_decision(store, trace_id="trace-2", key_hash=OTHER_KEY_HASH)
    original_append = store.append
    calls = 0

    def fail_second(receipt: GatewayReceipt) -> GatewayReceipt:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("simulated append failure")
        return original_append(receipt)

    monkeypatch.setattr(store, "append", fail_second)
    with pytest.raises(RecoveryError, match="could not durably close"):
        recover(store, now=NOW)
    assert [pair.state for pair in pair_receipts(store.receipts)] == [
        IdempotencyState.UNKNOWN,
        IdempotencyState.PENDING,
    ]
    monkeypatch.setattr(store, "append", original_append)
    report = recover(store, now=NOW + timedelta(minutes=1))
    assert report.pending_before == 1
    assert report.unknowns_appended == 1
    assert [pair.state for pair in pair_receipts(store.receipts)] == [
        IdempotencyState.UNKNOWN,
        IdempotencyState.UNKNOWN,
    ]
    store.close()


def test_recovery_module_has_no_upstream_client_dependency(tmp_path) -> None:
    import agentscan.gateway.recovery as recovery_module

    assert "upstream" not in recovery_module.__dict__
    store = make_store(tmp_path)
    add_decision(store)
    assert recover(store, now=NOW).unknowns_appended == 1
    store.close()


def test_confirmation_validates_authentication_hashes_time_and_extra_fields() -> None:
    canonical = confirmation(observed_at="2026-11-10T15:00:00+03:00")
    assert canonical.observed_at == "2026-11-10T12:00:00.000Z"
    with pytest.raises(ValidationError, match="authenticated"):
        confirmation(authenticated=False)
    with pytest.raises(ValidationError, match="hashes"):
        UpstreamConfirmation(
            status="no_effect",
            key_hash="bad",
            request_hash=REQUEST_HASH,
            confirmation_id="confirmation-1",
            observed_at="2026-11-10T12:00:00Z",
            authenticated=True,
        )
    with pytest.raises(ValidationError, match="timezone-aware"):
        UpstreamConfirmation(
            status="no_effect",
            key_hash=KEY_HASH,
            request_hash=REQUEST_HASH,
            confirmation_id="confirmation-1",
            observed_at="2026-11-10T12:00:00",
            authenticated=True,
        )
    with pytest.raises(ValidationError, match="256"):
        UpstreamConfirmation(
            status="no_effect",
            key_hash=KEY_HASH,
            request_hash=REQUEST_HASH,
            confirmation_id="x" * 257,
            observed_at="2026-11-10T12:00:00Z",
            authenticated=True,
        )
    with pytest.raises(ValidationError):
        UpstreamConfirmation(
            status="no_effect",
            key_hash=KEY_HASH,
            request_hash=REQUEST_HASH,
            confirmation_id="confirmation-1",
            observed_at="2026-11-10T12:00:00Z",
            authenticated=True,
            unexpected="value",
        )


def test_reconcile_no_effect_pending_and_unknown_is_terminal_and_idempotent(tmp_path) -> None:
    pending_store = make_store(tmp_path / "pending")
    add_decision(pending_store)
    result = reconcile(
        pending_store,
        idempotency_key=RAW_KEY,
        confirmation=confirmation(),
        max_key_bytes=128,
        now=NOW,
    )
    assert result.status == ReconciliationStatus.NO_EFFECT_RECORDED
    assert result.appended is not None and result.appended.result.status == "no_effect"
    assert result.appended.response_hash is None
    assert result.appended.reconciliation == {
        "source": "upstream:check_effect",
        "confirmation_id": "confirmation-1",
        "observed_at": "2026-11-10T12:00:00.000Z",
        "confirmed_status": "no_effect",
        "reconciled_at": utc_timestamp(NOW),
    }
    count = len(pending_store.receipts)
    repeated = reconcile(
        pending_store,
        idempotency_key=RAW_KEY,
        confirmation=confirmation(),
        max_key_bytes=128,
        now=NOW,
    )
    assert repeated.status == ReconciliationStatus.ALREADY_NO_EFFECT
    assert repeated.appended is None
    assert len(pending_store.receipts) == count
    index = IdempotencyIndex()
    index.rebuild(pending_store.receipts, now=NOW)
    same_key = index.check(
        tenant="tenant-demo",
        principal="user:123",
        tool_identity_hash=IDENTITY_HASH,
        key_hash=hash_key(RAW_KEY, max_bytes=128),
        request_hash=REQUEST_HASH,
        now=NOW,
    )
    assert same_key.action == IdempotencyAction.REPLAY
    assert same_key.state == IdempotencyState.NO_EFFECT
    assert (
        index.check(
            tenant="tenant-demo",
            principal="user:123",
            tool_identity_hash=IDENTITY_HASH,
            key_hash=OTHER_KEY_HASH,
            request_hash=REQUEST_HASH,
            now=NOW,
        ).action
        == IdempotencyAction.PROCEED
    )
    pending_store.close()

    unknown_store = make_store(tmp_path / "unknown")
    unknown_decision = add_decision(unknown_store)
    append_outcome(
        unknown_store,
        unknown_decision,
        status="unknown",
        summary="unknown",
        response_hash=None,
        now=NOW + timedelta(seconds=1),
    )
    reconciled = reconcile(
        unknown_store,
        idempotency_key=RAW_KEY,
        confirmation=confirmation(confirmation_id="confirmation-2"),
        max_key_bytes=128,
        now=NOW + timedelta(minutes=1),
    )
    assert reconciled.status == ReconciliationStatus.NO_EFFECT_RECORDED
    assert [pair.state for pair in pair_receipts(unknown_store.receipts)] == [
        IdempotencyState.NO_EFFECT
    ]
    unknown_store.close()


def test_applied_or_unknown_confirmation_never_records_no_effect(tmp_path) -> None:
    for status, expected in (
        ("applied", ReconciliationStatus.APPLIED),
        ("unknown", ReconciliationStatus.UNKNOWN),
    ):
        store = make_store(tmp_path / status)
        add_decision(store)
        result = reconcile(
            store,
            idempotency_key=RAW_KEY,
            confirmation=confirmation(status=status),
            max_key_bytes=128,
            now=NOW,
        )
        assert result.status == expected
        assert result.appended is not None
        assert result.appended.result.status == "unknown"
        assert result.appended.response_hash is None
        assert result.appended.reconciliation["confirmed_status"] == status
        count = len(store.receipts)
        again = reconcile(
            store,
            idempotency_key=RAW_KEY,
            confirmation=confirmation(status=status, confirmation_id="confirmation-2"),
            max_key_bytes=128,
            now=NOW + timedelta(minutes=1),
        )
        assert again.status == expected
        assert again.appended is None
        assert len(store.receipts) == count
        index = IdempotencyIndex()
        index.rebuild(store.receipts, now=NOW)
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
        store.close()


def test_applied_unknown_confirmation_on_existing_unknown_does_not_append(tmp_path) -> None:
    for status, expected in (
        ("applied", ReconciliationStatus.APPLIED),
        ("unknown", ReconciliationStatus.UNKNOWN),
    ):
        store = make_store(tmp_path / status)
        decision = add_decision(store)
        append_outcome(store, decision, status="unknown", summary="unknown", response_hash=None)
        before = len(store.receipts)
        result = reconcile(
            store,
            idempotency_key=RAW_KEY,
            confirmation=confirmation(status=status),
            max_key_bytes=128,
            now=NOW,
        )
        assert result.status == expected
        assert result.appended is None
        assert len(store.receipts) == before
        store.close()


def test_reconciliation_mismatches_denials_and_completed_states_fail_without_append(
    tmp_path,
) -> None:
    for label, status, confirm_key, confirm_request in (
        ("unknown-key", "pending", OTHER_KEY_HASH, REQUEST_HASH),
        ("wrong-request", "pending", KEY_HASH, OTHER_REQUEST_HASH),
        ("denied", "denied", KEY_HASH, REQUEST_HASH),
        ("success", "success", KEY_HASH, REQUEST_HASH),
    ):
        store = make_store(tmp_path / label)
        decision = add_decision(store, status="denied" if status == "denied" else "pending")
        if status == "success":
            # Replace the pending decision with a valid decision/outcome history.
            store.close()
            store = make_store(tmp_path / f"{label}-complete")
            decision = add_decision(store)
            append_outcome(
                store,
                decision,
                status="success",
                summary="done",
                response_hash=RESPONSE_HASH,
            )
        before = len(store.receipts)
        try:
            reconcile(
                store,
                idempotency_key=RAW_KEY,
                confirmation=confirmation(key_hash=confirm_key, request_hash=confirm_request),
                max_key_bytes=128,
                now=NOW,
            )
        except ReconciliationError:
            pass
        else:
            pytest.fail(f"reconciliation accepted {label}")
        assert len(store.receipts) == before
        store.close()


def test_reconciliation_rejects_plain_dict_ambiguous_match_and_raw_key_leaks(tmp_path) -> None:
    store = make_store(tmp_path / "plain")
    add_decision(store)
    with pytest.raises(ReconciliationError, match="validated UpstreamConfirmation"):
        reconcile(
            store,
            idempotency_key=RAW_KEY,
            confirmation={
                "status": "no_effect",
                "key_hash": KEY_HASH,
                "request_hash": REQUEST_HASH,
                "confirmation_id": "plain-dict",
                "observed_at": "2026-11-10T12:00:00Z",
                "authenticated": True,
            },
            max_key_bytes=128,
            now=NOW,
        )  # type: ignore[arg-type]
    with pytest.raises(ReconciliationError) as exc:
        reconcile(
            store,
            idempotency_key="raw-key-that-is-not-in-receipts",
            confirmation=confirmation(),
            max_key_bytes=128,
            now=NOW,
        )
    assert "raw-key-that-is-not-in-receipts" not in str(exc.value)
    store.close()

    ambiguous = make_store(tmp_path / "ambiguous")
    add_decision(ambiguous, trace_id="trace-1")
    add_decision(ambiguous, trace_id="trace-2")
    before = len(ambiguous.receipts)
    with pytest.raises(ReconciliationError, match="exactly one"):
        reconcile(
            ambiguous,
            idempotency_key=RAW_KEY,
            confirmation=confirmation(),
            max_key_bytes=128,
            now=NOW,
        )
    assert len(ambiguous.receipts) == before
    assert RAW_KEY.encode() not in ambiguous.chain_path.read_bytes()
    ambiguous.close()


def test_reconciliation_requires_lease_and_no_force_parameter(tmp_path) -> None:
    store = make_store(tmp_path)
    add_decision(store)
    store.close()
    with pytest.raises(ReconciliationError, match="writer lease"):
        reconcile(
            store,
            idempotency_key=RAW_KEY,
            confirmation=confirmation(),
            max_key_bytes=128,
            now=NOW,
        )
    assert "force" not in inspect.signature(reconcile).parameters
    assert "assume_no_effect" not in inspect.signature(reconcile).parameters
    with pytest.raises(TypeError):
        reconcile(
            store,
            idempotency_key=RAW_KEY,
            confirmation=confirmation(),
            max_key_bytes=128,
            force=True,
        )
