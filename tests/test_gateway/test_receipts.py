from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from agentscan.gateway.canonical import canonical_json, loads_json
from agentscan.gateway.policy import RedactionConfig
from agentscan.gateway.receipts import (
    GENESIS_HASH,
    GatewayReceipt,
    ReceiptAuthorization,
    ReceiptChainError,
    ReceiptChainStore,
    ReceiptError,
    ReceiptEvidence,
    ReceiptResult,
    ReceiptTool,
    RetentionDedupeIndex,
    WriterLeaseError,
    prepare_arguments,
    seal_receipt,
    utc_timestamp,
    verify_jsonl_chain,
    verify_jsonl_file,
    verify_receipt_chain,
    verify_receipt_hash,
)

NOW = datetime(2026, 11, 10, 12, 0, tzinfo=UTC)
POLICY_HASH = "sha256:" + "a" * 64
KEY_ID = "ed25519:" + "b" * 64
SCHEMA_HASH = "sha256:" + "c" * 64
IDENTITY_HASH = "sha256:" + "d" * 64
REQUEST_HASH = "sha256:" + "e" * 64
KEY_HASH = "sha256:" + "f" * 64


def receipt(
    *,
    phase: str = "decision",
    status: str = "pending",
    timestamp: str | None = None,
    writer_epoch: int = 1,
    writer_id: str = "gw-1",
    chain_id: str = "tenant-demo/gw-1",
    tenant_id: str = "tenant-demo",
    idempotency_key: str | None = KEY_HASH,
    arguments: dict[str, object] | None = None,
    summary: str = "pending",
    decision_latency_ms: float = 1.25,
) -> GatewayReceipt:
    raw_arguments = arguments or {"customer_id": "cust-1001"}
    redacted_arguments, arguments_hash = prepare_arguments(
        raw_arguments, RedactionConfig(max_value_length=256)
    )
    return GatewayReceipt(
        trace_id="trace-1",
        phase=phase,
        tenant_id=tenant_id,
        gateway_id="gw-1",
        chain_id=chain_id,
        writer_epoch=writer_epoch,
        writer_id=writer_id,
        idempotency_key=idempotency_key,
        principal="user:123",
        agent="agent:support",
        tool=ReceiptTool(
            name="delete_customer_record",
            server="crm-mcp",
            schema_hash=SCHEMA_HASH,
            identity_hash=IDENTITY_HASH,
        ),
        arguments=redacted_arguments,
        arguments_hash=arguments_hash,
        authorization=ReceiptAuthorization(
            decision="deny" if status == "denied" else "allow",
            policy_id="policy-1",
            rule_id=None,
            resource_tenant_enforced="upstream",
            reason="default_deny" if status == "denied" else "allow_rule",
        ),
        policy_decision="deny" if status == "denied" else "allow",
        enforcement_mode="inline",
        effective_action="blocked" if status == "denied" else "forwarded",
        would_deny=status == "denied",
        result=ReceiptResult(status=status, summary=summary),
        evidence=ReceiptEvidence(hash="", prev_hash=GENESIS_HASH),
        timestamp=timestamp or utc_timestamp(NOW),
        request_hash=REQUEST_HASH,
        response_hash=None,
        policy_hash=POLICY_HASH,
        policy_key_id=KEY_ID,
        decision_latency_ms=decision_latency_ms,
        mcp_request_id="request-1",
        approval_id=None,
        reconciliation=None,
    )


def store(tmp_path: Path, writer_id: str = "gw-1", **kwargs) -> ReceiptChainStore:
    return ReceiptChainStore(
        tmp_path,
        tenant="tenant-demo",
        gateway_id="gw-1",
        chain_id="tenant-demo/gw-1",
        writer_id=writer_id,
        **kwargs,
    )


def test_empty_chain_uses_fixed_genesis() -> None:
    verified = verify_receipt_chain(())
    assert verified.receipts == ()
    assert verified.head_hash == GENESIS_HASH
    assert GENESIS_HASH == "sha256:" + "0" * 64


def test_receipt_hash_uses_canonical_model_dump_with_empty_hash() -> None:
    unsealed = receipt()
    expected_payload = unsealed.model_dump(mode="json")
    expected_payload["evidence"]["hash"] = ""
    expected = "sha256:" + hashlib.sha256(canonical_json(expected_payload)).hexdigest()
    sealed = seal_receipt(unsealed)
    assert sealed.evidence.hash == expected
    assert sealed.evidence.prev_hash == GENESIS_HASH
    assert verify_receipt_hash(sealed)


def test_receipt_seal_binds_previous_receipt_and_chain_links() -> None:
    first = seal_receipt(receipt())
    second = seal_receipt(receipt(phase="outcome", status="success"), first.evidence.hash)
    verified = verify_receipt_chain((first, second))
    assert verified.head_hash == second.evidence.hash
    assert second.evidence.prev_hash == first.evidence.hash


@pytest.mark.parametrize(
    ("field", "value"),
    [("tenant_id", "tenant-other"), ("gateway_id", "gw-other"), ("chain_id", "other-chain")],
)
def test_receipt_chain_rejects_mixed_identity(field: str, value: str) -> None:
    first = seal_receipt(receipt())
    payload = receipt(phase="outcome", status="success").model_dump(mode="python")
    payload[field] = value
    second = seal_receipt(GatewayReceipt.model_validate(payload), first.evidence.hash)
    with pytest.raises(ReceiptChainError, match="tenant, gateway, or chain"):
        verify_receipt_chain((first, second))


def test_receipt_rejects_invalid_hash_timestamp_phase_and_latency() -> None:
    with pytest.raises(ValidationError, match="sha256"):
        ReceiptTool(name="tool", server="server", schema_hash="bad", identity_hash=IDENTITY_HASH)
    with pytest.raises(ValidationError, match="canonical UTC"):
        receipt(timestamp="2026-11-10T12:00:00Z")
    with pytest.raises(ValidationError, match="invalid for decision"):
        receipt(phase="decision", status="success")
    invalid_latency = receipt().model_dump(mode="python")
    invalid_latency["decision_latency_ms"] = float("nan")
    with pytest.raises(ValidationError, match="finite and non-negative"):
        GatewayReceipt.model_validate(invalid_latency)


def test_require_approval_is_denied_blocked_and_terminal() -> None:
    allowed = receipt().model_dump(mode="python")
    allowed["policy_decision"] = "require_approval"
    with pytest.raises(ValidationError, match="require_approval"):
        GatewayReceipt.model_validate(allowed)

    pending = receipt().model_dump(mode="python")
    pending["policy_decision"] = "require_approval"
    pending["authorization"]["decision"] = "deny"
    pending["effective_action"] = "blocked"
    with pytest.raises(ValidationError, match="require_approval"):
        GatewayReceipt.model_validate(pending)

    forwarded = receipt(status="denied").model_dump(mode="python")
    forwarded["policy_decision"] = "require_approval"
    forwarded["effective_action"] = "forwarded"
    with pytest.raises(ValidationError, match="require_approval"):
        GatewayReceipt.model_validate(forwarded)

    denied = receipt(status="denied").model_dump(mode="python")
    denied["policy_decision"] = "require_approval"
    assert GatewayReceipt.model_validate(denied).result.status == "denied"


def test_receipt_redacts_credentials_and_bounds_summary() -> None:
    raw = {"customer_id": "cust-1001", "api_key": "test-secret", "nested": {"password": "pw"}}
    redacted, original_hash = prepare_arguments(raw)
    value = receipt(arguments=raw)
    assert value.arguments == redacted
    assert value.arguments["api_key"] == "[REDACTED]"
    assert value.arguments["nested"]["password"] == "[REDACTED]"
    assert original_hash == value.arguments_hash
    long_receipt = receipt(summary="é" * 400)
    assert len(long_receipt.result.summary.encode("utf-8")) <= 512


def test_prepare_arguments_hashes_before_redaction_and_uses_config() -> None:
    args = {"account_name": "Alice", "comment": "123456"}
    redacted, args_hash = prepare_arguments(
        args, RedactionConfig(redact_arguments=("account_name",), max_value_length=4)
    )
    assert redacted == {"account_name": "[REDACTED]", "comment": "1234"}
    assert args_hash == "sha256:" + hashlib.sha256(canonical_json(args)).hexdigest()


def test_verify_jsonl_empty_and_appended_chain(tmp_path: Path) -> None:
    instance = store(tmp_path)
    assert verify_jsonl_file(instance.chain_path).head_hash == GENESIS_HASH
    assert instance.acquire_writer_lease() == 1
    first, second = instance.append_many((receipt(), receipt(phase="outcome", status="success")))
    instance.close()
    verified = verify_jsonl_file(instance.chain_path)
    assert len(verified.receipts) == 2
    assert verified.receipts == (first, second)
    lines = instance.chain_path.read_bytes().splitlines()
    assert all(canonical_json(loads_json(line)) == line for line in lines)


def test_chain_tampering_reordering_and_missing_line_fail(tmp_path: Path) -> None:
    instance = store(tmp_path)
    instance.acquire_writer_lease()
    instance.append_many((receipt(), receipt(phase="outcome", status="success")))
    instance.close()
    original = instance.chain_path.read_bytes()
    assert original.count(b"\n") == 2

    tampered = original.replace(b"cust-1001", b"cust-9999", 1)
    with pytest.raises(ReceiptChainError):
        verify_jsonl_chain(tampered)
    lines = original.splitlines(keepends=True)
    with pytest.raises(ReceiptChainError):
        verify_jsonl_chain(lines[1] + lines[0])
    with pytest.raises(ReceiptChainError, match="link"):
        verify_jsonl_chain(lines[1])


def test_partial_jsonl_line_fails_verification(tmp_path: Path) -> None:
    instance = store(tmp_path)
    instance.acquire_writer_lease()
    instance.append(receipt())
    instance.close()
    partial = instance.chain_path.read_bytes()[:-3]
    with pytest.raises(ReceiptChainError, match="partial JSONL line"):
        verify_jsonl_chain(partial)


def test_restart_replays_wal_record_missing_from_jsonl(tmp_path: Path) -> None:
    first_store = store(tmp_path)
    assert first_store.acquire_writer_lease() == 1
    first_store.append(receipt())
    first_store.close()
    first_store.chain_path.write_bytes(b"")

    restarted = store(tmp_path)
    assert restarted.acquire_writer_lease() == 2
    assert len(restarted.receipts) == 1
    assert restarted.receipts[0].writer_epoch == 1
    assert verify_jsonl_file(restarted.chain_path).head_hash == restarted.head_hash
    restarted.close()


def test_foreign_wal_record_is_rejected_without_extending_authoritative_chain(
    tmp_path: Path,
) -> None:
    import agentscan.gateway.receipts as receipts_module

    first_store = store(tmp_path)
    first_store.acquire_writer_lease()
    first = first_store.append(receipt())
    first_store.close()
    before = first_store.chain_path.read_bytes()
    foreign = seal_receipt(
        receipt(tenant_id="tenant-other", chain_id="tenant-other/gw-1"),
        first.evidence.hash,
    )
    with first_store.wal_path.open("ab") as stream:
        stream.write(receipts_module._wal_line(foreign))

    restarted = store(tmp_path)
    with pytest.raises(ReceiptChainError, match="does not match this store"):
        restarted.acquire_writer_lease()
    assert first_store.chain_path.read_bytes() == before
    assert not restarted.lease_held


def test_invalid_full_wal_proposal_is_rejected_before_any_jsonl_write(tmp_path: Path) -> None:
    import agentscan.gateway.receipts as receipts_module

    instance = store(tmp_path)
    first = seal_receipt(receipt())
    orphan = seal_receipt(receipt(phase="outcome", status="success"))
    instance.directory.mkdir(parents=True)
    instance.wal_path.write_bytes(
        receipts_module._wal_line(first) + receipts_module._wal_line(orphan)
    )

    with pytest.raises(ReceiptChainError, match="does not extend"):
        instance.acquire_writer_lease()
    assert not instance.chain_path.exists()
    assert not instance.lease_held


def test_foreign_writer_wal_is_rejected_before_jsonl_replay(tmp_path: Path) -> None:
    import agentscan.gateway.receipts as receipts_module

    instance = store(tmp_path, writer_id="writer-a")
    foreign_writer = seal_receipt(receipt(writer_id="writer-b"))
    instance.directory.mkdir(parents=True)
    instance.wal_path.write_bytes(receipts_module._wal_line(foreign_writer))

    with pytest.raises(WriterLeaseError, match="handoff"):
        instance.acquire_writer_lease()
    assert not instance.chain_path.exists()
    assert not instance.lease_held


def test_recoverable_partial_jsonl_line_requires_matching_durable_wal(tmp_path: Path) -> None:
    first_store = store(tmp_path)
    first_store.acquire_writer_lease()
    expected = first_store.append(receipt())
    first_store.close()
    complete = first_store.chain_path.read_bytes()
    first_store.chain_path.write_bytes(complete[:-8])

    restarted = store(tmp_path)
    restarted.acquire_writer_lease()
    assert restarted.receipts == (expected,)
    assert restarted.chain_path.read_bytes() == complete
    restarted.close()


def test_unrecoverable_partial_line_fails_closed_without_repair(tmp_path: Path) -> None:
    first_store = store(tmp_path)
    first_store.acquire_writer_lease()
    first_store.append(receipt())
    first_store.close()
    first_store.wal_path.unlink()
    first_store.chain_path.write_bytes(first_store.chain_path.read_bytes()[:-5])
    partial_before = first_store.chain_path.read_bytes()

    restarted = store(tmp_path)
    with pytest.raises(ReceiptChainError, match="partial JSONL line"):
        restarted.acquire_writer_lease()
    assert first_store.chain_path.read_bytes() == partial_before
    assert not restarted.lease_held


def test_partial_wal_record_fails_closed(tmp_path: Path) -> None:
    instance = store(tmp_path)
    instance.acquire_writer_lease()
    instance.append(receipt())
    instance.close()
    instance.wal_path.write_bytes(instance.wal_path.read_bytes()[:-2])
    with pytest.raises(ReceiptChainError, match="partial WAL"):
        store(tmp_path).acquire_writer_lease()


def test_wal_group_append_is_fsynced_before_authoritative_jsonl(
    tmp_path: Path, monkeypatch
) -> None:
    import agentscan.gateway.receipts as receipts_module

    instance = store(tmp_path)
    instance.acquire_writer_lease()
    calls: list[Path] = []
    original_append = receipts_module._append_fsynced

    def record_append(path: Path, data: bytes) -> None:
        calls.append(path)
        original_append(path, data)

    monkeypatch.setattr(receipts_module, "_append_fsynced", record_append)
    instance.append_many((receipt(), receipt(phase="outcome", status="success")))
    assert calls == [instance.wal_path, instance.chain_path]
    assert len(instance.wal_path.read_bytes().splitlines()) == 2
    assert len(instance.chain_path.read_bytes().splitlines()) == 2
    instance.close()


def test_new_wal_and_jsonl_files_fsync_parent_directory(tmp_path: Path, monkeypatch) -> None:
    import agentscan.gateway.receipts as receipts_module

    synced: list[Path] = []
    monkeypatch.setattr(receipts_module, "_fsync_directory", synced.append)
    wal = tmp_path / "chain.wal"
    chain = tmp_path / "chain.jsonl"
    receipts_module._append_fsynced(wal, b"wal\n")
    receipts_module._append_fsynced(chain, b"jsonl\n")
    assert synced == [tmp_path, tmp_path]

    receipts_module._append_fsynced(wal, b"more\n")
    assert synced == [tmp_path, tmp_path]


def test_epoch_replace_fsyncs_parent_directory_after_replace(tmp_path: Path, monkeypatch) -> None:
    import agentscan.gateway.receipts as receipts_module

    events: list[str | Path] = []
    original_replace = receipts_module.os.replace

    def record_replace(source: str | Path, destination: str | Path) -> None:
        original_replace(source, destination)
        events.append("replace")

    monkeypatch.setattr(receipts_module.os, "replace", record_replace)
    monkeypatch.setattr(receipts_module, "_fsync_directory", events.append)
    epoch_path = tmp_path / "chain.epoch"
    receipts_module._write_epoch_atomic(epoch_path, 3)
    assert events == ["replace", tmp_path]
    assert epoch_path.read_text(encoding="ascii") == "3\n"


def test_writer_lease_excludes_second_writer_and_epoch_increments_on_restart(
    tmp_path: Path,
) -> None:
    first = store(tmp_path)
    second = store(tmp_path)
    assert first.acquire_writer_lease() == 1
    with pytest.raises(WriterLeaseError, match="another writer"):
        second.acquire_writer_lease()
    first.append(receipt())
    first.close()
    assert second.acquire_writer_lease() == 2
    second.append(receipt(phase="outcome", status="success"))
    second.close()
    verified = verify_jsonl_file(first.chain_path)
    assert [item.writer_epoch for item in verified.receipts] == [1, 2]


def test_different_writer_fails_without_handoff(tmp_path: Path) -> None:
    first = store(tmp_path, writer_id="writer-a")
    first.acquire_writer_lease()
    first.append(receipt(writer_id="ignored"))
    first.close()
    next_writer = store(tmp_path, writer_id="writer-b")
    with pytest.raises(WriterLeaseError, match="handoff"):
        next_writer.acquire_writer_lease()
    assert not next_writer.lease_held


def test_epoch_file_is_atomic_and_never_moves_backwards(tmp_path: Path) -> None:
    instance = store(tmp_path)
    assert instance.acquire_writer_lease() == 1
    instance.append(receipt())
    instance.close()
    instance.epoch_path.write_text("1\n", encoding="ascii")
    restarted = store(tmp_path)
    assert restarted.acquire_writer_lease() == 2
    assert restarted.epoch_path.read_text(encoding="ascii") == "2\n"
    assert list(restarted.directory.glob("*.tmp")) == []
    restarted.close()


def test_writer_epoch_decrease_and_same_epoch_identity_change_fail() -> None:
    first = seal_receipt(receipt(writer_epoch=2, writer_id="gw-1"))
    stale = seal_receipt(receipt(writer_epoch=1, writer_id="gw-1"), first.evidence.hash)
    with pytest.raises(ReceiptChainError, match="backwards"):
        verify_receipt_chain((first, stale))
    changed = seal_receipt(receipt(writer_epoch=2, writer_id="gw-2"), first.evidence.hash)
    with pytest.raises(ReceiptChainError, match="identity changed"):
        verify_receipt_chain((first, changed))


def test_retention_defaults_to_30_days_and_dedupe_window_must_match() -> None:
    index = RetentionDedupeIndex()
    assert index.retention_days == index.dedupe_window_days == 30
    with pytest.raises(ReceiptError, match="equal"):
        RetentionDedupeIndex(retention_days=30, dedupe_window_days=29)
    with pytest.raises(ReceiptError, match="equal"):
        RetentionDedupeIndex(retention_days=30, dedupe_window_days=31)
    with pytest.raises(ReceiptError, match="positive"):
        RetentionDedupeIndex(retention_days=0)


def test_retention_index_expires_entries_by_receipt_timestamp() -> None:
    index = RetentionDedupeIndex(retention_days=30)
    recent = seal_receipt(receipt(timestamp=utc_timestamp(NOW - timedelta(days=29))))
    expired = seal_receipt(
        receipt(
            timestamp=utc_timestamp(NOW - timedelta(days=31)),
            idempotency_key="sha256:" + "1" * 64,
        )
    )
    index.rebuild((recent, expired), now=NOW)
    assert len(index) == 1
    assert index.lookup("tenant-demo", "user:123", IDENTITY_HASH, KEY_HASH, now=NOW) == (recent,)
    assert (
        index.lookup("tenant-demo", "user:123", IDENTITY_HASH, expired.idempotency_key, now=NOW)
        == ()
    )


def test_retention_lookup_expires_entries_that_age_out_after_rebuild() -> None:
    index = RetentionDedupeIndex(retention_days=30)
    receipt_at_rebuild = seal_receipt(receipt(timestamp=utc_timestamp(NOW - timedelta(days=29))))
    index.add(receipt_at_rebuild, now=NOW)
    assert index.lookup("tenant-demo", "user:123", IDENTITY_HASH, KEY_HASH, now=NOW)
    assert (
        index.lookup(
            "tenant-demo", "user:123", IDENTITY_HASH, KEY_HASH, now=NOW + timedelta(days=2)
        )
        == ()
    )
    assert len(index) == 0


def test_retention_index_ignores_receipts_without_idempotency_keys() -> None:
    index = RetentionDedupeIndex()
    no_key = seal_receipt(receipt(idempotency_key=None))
    index.rebuild((no_key,), now=NOW)
    assert len(index) == 0


def test_store_append_updates_retention_index_without_a_full_rebuild(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    chain = store(tmp_path)
    chain.acquire_writer_lease()
    try:
        now = datetime.now(UTC)
        recent = receipt(timestamp=utc_timestamp(now - timedelta(days=1)))
        expired = receipt(
            timestamp=utc_timestamp(now - timedelta(days=31)),
            idempotency_key="sha256:" + "1" * 64,
        )

        def fail_rebuild(*args: object, **kwargs: object) -> None:
            raise AssertionError("append must not rebuild the retention index")

        with monkeypatch.context() as patch:
            patch.setattr(RetentionDedupeIndex, "rebuild", fail_rebuild)
            chain.append(recent)
            chain.append(expired)

        rebuilt = RetentionDedupeIndex()
        rebuilt.rebuild(chain.receipts, now=now)
        assert len(chain.retention_index) == len(rebuilt) == 1
        assert chain.retention_index.lookup(
            "tenant-demo", "user:123", IDENTITY_HASH, KEY_HASH, now=now
        ) == rebuilt.lookup("tenant-demo", "user:123", IDENTITY_HASH, KEY_HASH, now=now)
        assert (
            chain.retention_index.lookup(
                "tenant-demo",
                "user:123",
                IDENTITY_HASH,
                expired.idempotency_key or "",
                now=now,
            )
            == ()
        )
    finally:
        chain.close()


def test_store_trace_index_tracks_appends_and_reopen(tmp_path: Path) -> None:
    chain = store(tmp_path)
    chain.acquire_writer_lease()
    decision = chain.append(receipt())
    outcome = chain.append(receipt(phase="outcome", status="success"))
    assert chain.receipts_for_trace("trace-1") == (decision, outcome)
    assert chain.receipts_for_trace("missing") == ()
    chain.close()

    reopened = store(tmp_path)
    reopened.acquire_writer_lease()
    try:
        assert reopened.receipts_for_trace("trace-1") == (decision, outcome)
    finally:
        reopened.close()


@pytest.mark.parametrize(
    ("tenant", "chain_id"),
    [
        ("tenant/demo", "chain"),
        ("tenant..demo", "chain"),
        ("tenant-demo", "../escape"),
        ("tenant-demo", "chain?bad"),
    ],
)
def test_store_rejects_unsafe_receipt_paths(tmp_path: Path, tenant: str, chain_id: str) -> None:
    with pytest.raises(ReceiptError):
        ReceiptChainStore(
            tmp_path,
            tenant=tenant,
            gateway_id="gw-1",
            chain_id=chain_id,
            writer_id="writer-1",
        )


def test_store_sanitizes_chain_slashes_and_requires_lease(tmp_path: Path) -> None:
    instance = ReceiptChainStore(
        tmp_path,
        tenant="tenant-demo",
        gateway_id="gw-1",
        chain_id="tenant-demo/gateway-1",
        writer_id="writer-1",
    )
    assert instance.chain_path.name == "tenant-demo__gateway-1.jsonl"
    with pytest.raises(WriterLeaseError, match="not held"):
        instance.append(receipt())
