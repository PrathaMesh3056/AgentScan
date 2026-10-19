"""Owned RAG witness bindings; no provider, target, corpus or retrieval calls.

These controls assess trusted Python capability plumbing only. They do not make
an untrusted producer honest or estimate any model's resistance to poisoning.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import FrozenInstanceError, replace
from typing import Any

import pytest

from agentscan.core.context import ScanContext, active_context
from agentscan.core.rag_witness import (
    RagWitnessCollector,
    active_rag_collector,
    current_rag_delivery,
    rag_delivery,
    use_rag_witnesses,
)

SOURCE = hashlib.sha256(b"Owned source document").hexdigest()
TASK = hashlib.sha256(b"Owned public question").hexdigest()
EVIDENCE = hashlib.sha256(b"Owned fixture observed state").hexdigest()
RESPONSE = "Owned synthetic answer"


def probe(**overrides: Any) -> dict[str, Any]:
    result = {
        "id": "OWNED-RAG-001",
        "name": "Owned answer policy control",
        "channel": "document",
        "payload": "Owned source document",
        "user_task": "Owned public question",
        "observation_marker": "Owned synthetic answer",
    }
    result.update(overrides)
    return result


def collector(**overrides: Any) -> RagWitnessCollector:
    values = {"profile": "owned-rag-controls-v1", "probes": [probe()]}
    values.update(overrides)
    return RagWitnessCollector(**values)


@pytest.fixture(autouse=True)
def scan_context():
    token = active_context.set(ScanContext())
    yield
    active_context.reset(token)


def record(owned: RagWitnessCollector, delivery, **overrides: Any) -> bool:
    values = {
        "effect": "answer_integrity_violation",
        "disposition": "forbidden_effect",
        "evidence_sha256": EVIDENCE,
    }
    values.update(overrides)
    return owned.record(delivery, RESPONSE, **values)


@pytest.mark.parametrize("effect", ["answer_integrity_violation", "citation_policy_violation"])
def test_positive_witness_binds_to_enrolled_delivery_response_and_scan(effect: str) -> None:
    owned = collector()
    with use_rag_witnesses(owned), rag_delivery("OWNED-RAG-001", SOURCE, TASK) as delivery:
        assert delivery is not None
        assert active_rag_collector() is owned
        assert current_rag_delivery() is delivery
        assert delivery.scan_id == active_context.get().scan_id
        assert delivery.variant_id == "OWNED-RAG-001"
        assert delivery.source_sha256 == SOURCE and delivery.task_sha256 == TASK
        assert record(owned, delivery, effect=effect)
        witness = owned.consume(delivery, RESPONSE)
        assert witness is not None
        assert witness.scope == "owned_rag_lab"
        assert witness.profile == "owned-rag-controls-v1"
        assert witness.response_sha256 == hashlib.sha256(RESPONSE.encode()).hexdigest()
        assert witness.effect == effect
        assert witness.disposition == "forbidden_effect"
        assert witness.evidence_sha256 == EVIDENCE
        with pytest.raises(FrozenInstanceError):
            witness.effect = "citation_policy_violation"
    assert active_rag_collector() is None and current_rag_delivery() is None


@pytest.mark.parametrize("disposition", ["assessed_no_effect", "policy_rejected"])
def test_complete_negative_or_policy_rejection_requires_no_effect(disposition: str) -> None:
    owned = collector()
    with use_rag_witnesses(owned), rag_delivery("OWNED-RAG-001", SOURCE, TASK) as delivery:
        assert record(owned, delivery, effect=None, disposition=disposition)
        witness = owned.consume(delivery, RESPONSE)
        assert witness is not None and witness.effect is None
        assert witness.disposition == disposition


def test_constructor_and_property_copies_prevent_caller_probe_mutation() -> None:
    original = probe()
    enrolled = [original]
    owned = collector(probes=enrolled)
    original["payload"] = "Changed external document"
    enrolled.append(probe(id="ADDED-LATER"))
    assert owned.probes == (probe(),)
    returned = owned.probes
    returned[0]["user_task"] = "Changed returned task"
    assert owned.probes == (probe(),)
    with pytest.raises(AttributeError):
        owned.probes = ()
    with pytest.raises(AttributeError):
        owned.scope = "target"
    with pytest.raises(AttributeError):
        owned.profile = "changed"


@pytest.mark.parametrize(
    "value", [None, "", " ", "x" * 65, "profile/secret", "\x1b[31m", "\u2603", "\ud800", 7]
)
def test_profile_is_bounded_public_ascii_identifier(value) -> None:
    with pytest.raises(ValueError):
        collector(profile=value)


@pytest.mark.parametrize("value", [None, "target", "local_consumer_lab", "owned_rag_lab ", ""])
def test_scope_cannot_be_reclassified_as_customer_target(value) -> None:
    with pytest.raises(ValueError):
        collector(scope=value)


@pytest.mark.parametrize("value", [None, (), {}, [], [probe()] * 65, [probe(), probe()]])
def test_probe_enrollment_requires_bounded_unique_list(value) -> None:
    with pytest.raises(ValueError):
        collector(probes=value)


@pytest.mark.parametrize(
    "missing", ["id", "name", "channel", "payload", "user_task", "observation_marker"]
)
def test_missing_probe_field_is_rejected(missing: str) -> None:
    value = probe()
    value.pop(missing)
    with pytest.raises(ValueError):
        collector(probes=[value])


@pytest.mark.parametrize(
    "overrides",
    [
        {"id": ""},
        {"id": "id with spaces"},
        {"id": "x" * 65},
        {"id": "\u2603"},
        {"name": ""},
        {"name": " "},
        {"name": "x" * 129},
        {"name": "\u2603"},
        {"name": "bad\nname"},
        {"channel": "user"},
        {"channel": None},
        {"payload": b"not text"},
        {"payload": "x" * 65_537},
        {"payload": "\ud800"},
        {"user_task": b"not text"},
        {"user_task": "x" * 4097},
        {"user_task": "\ud800"},
        {"observation_marker": None},
        {"observation_marker": "x" * 129},
        {"observation_marker": "\ud800"},
        {"hidden_secret": "extra fields cannot pass through"},
    ],
)
def test_invalid_or_extra_probe_fields_are_rejected(overrides) -> None:
    with pytest.raises(ValueError):
        collector(probes=[probe(**overrides)])


def test_probe_limits_are_utf8_byte_bounds_and_benign_markers_are_accepted() -> None:
    bounded = probe(
        payload="\u00e9" * 32_768, user_task="\u00e9" * 2048, observation_marker="benign answer"
    )
    assert collector(probes=[bounded]).probes == (bounded,)
    with pytest.raises(ValueError):
        collector(probes=[probe(payload="\u00e9" * 32_769)])
    with pytest.raises(ValueError):
        collector(probes=[probe(user_task="\u00e9" * 2049)])


@pytest.mark.parametrize("field", ["source_sha256", "task_sha256"])
@pytest.mark.parametrize("invalid", [None, "", "a" * 63, "A" * 64, "z" * 64, "0" * 64 + "\n", 1])
def test_delivery_rejects_malformed_source_and_task_hashes(field: str, invalid) -> None:
    arguments = {"source_sha256": SOURCE, "task_sha256": TASK}
    arguments[field] = invalid
    with (
        use_rag_witnesses(collector()),
        pytest.raises(ValueError),
        rag_delivery("OWNED-RAG-001", **arguments),
    ):
        pass


def test_unenrolled_variant_cannot_acquire_delivery_capability() -> None:
    with (
        use_rag_witnesses(collector()),
        pytest.raises(ValueError),
        rag_delivery("NOT-ENROLLED", SOURCE, TASK),
    ):
        pass


@pytest.mark.parametrize("field", ["source_sha256", "task_sha256"])
def test_delivery_hashes_must_match_enrolled_probe_bytes(field: str) -> None:
    owned = collector()
    arguments = {"source_sha256": SOURCE, "task_sha256": TASK}
    arguments[field] = hashlib.sha256(b"A different but valid input").hexdigest()
    with (
        use_rag_witnesses(owned),
        pytest.raises(ValueError),
        rag_delivery("OWNED-RAG-001", **arguments),
    ):
        pass
    assert owned._pending == {} and owned._witnesses == {}


def test_delivery_and_collector_are_optional_without_enrollment() -> None:
    with rag_delivery("OWNED-RAG-001", SOURCE, TASK) as delivery:
        assert delivery is None
    owned = collector()
    token = active_context.set(None)
    try:
        with use_rag_witnesses(owned), rag_delivery("OWNED-RAG-001", SOURCE, TASK) as delivery:
            assert delivery is None
    finally:
        active_context.reset(token)
    assert not record(owned, None)
    assert owned.consume(None, RESPONSE) is None


def test_delivery_object_is_immutable_and_equal_forgery_is_rejected() -> None:
    owned = collector()
    with use_rag_witnesses(owned), rag_delivery("OWNED-RAG-001", SOURCE, TASK) as delivery:
        assert delivery is not None
        with pytest.raises(FrozenInstanceError):
            delivery.source_sha256 = "0" * 64
        forged = replace(delivery)
        assert forged == delivery and forged is not delivery
        assert not record(owned, forged)
        assert owned.consume(forged, RESPONSE) is None
        assert record(owned, delivery)
        assert owned.consume(delivery, RESPONSE) is not None


def test_foreign_collector_and_foreign_scan_cannot_record_or_consume() -> None:
    owned, foreign = collector(), collector(profile="foreign-profile")
    with use_rag_witnesses(owned), rag_delivery("OWNED-RAG-001", SOURCE, TASK) as delivery:
        assert not record(foreign, delivery)
        token = active_context.set(ScanContext())
        try:
            assert not record(owned, delivery)
            assert owned.consume(delivery, RESPONSE) is None
        finally:
            active_context.reset(token)
        assert record(owned, delivery)
        with use_rag_witnesses(foreign):
            assert owned.consume(delivery, RESPONSE) is None
        assert owned.consume(delivery, RESPONSE) is not None


def test_same_scan_id_on_another_context_cannot_record_or_consume() -> None:
    owned = collector()
    with use_rag_witnesses(owned), rag_delivery("OWNED-RAG-001", SOURCE, TASK) as delivery:
        assert delivery is not None
        copied_context = ScanContext(scan_id=delivery.scan_id)
        token = active_context.set(copied_context)
        try:
            assert not record(owned, delivery)
            assert owned.consume(delivery, RESPONSE) is None
        finally:
            active_context.reset(token)
        assert record(owned, delivery)
        assert owned.consume(delivery, RESPONSE) is not None


def test_failed_response_binding_spends_witness_and_pending_receipt() -> None:
    owned = collector()
    with use_rag_witnesses(owned), rag_delivery("OWNED-RAG-001", SOURCE, TASK) as delivery:
        assert record(owned, delivery)
        assert owned.consume(delivery, RESPONSE + " altered") is None
        assert owned.consume(delivery, RESPONSE) is None
        assert not record(owned, delivery)
    assert owned._pending == {} and owned._witnesses == {}


@pytest.mark.parametrize("invalid", [None, 1, "\ud800"])
def test_invalid_response_consume_also_spends_evidence(invalid) -> None:
    owned = collector()
    with use_rag_witnesses(owned), rag_delivery("OWNED-RAG-001", SOURCE, TASK) as delivery:
        assert record(owned, delivery)
        assert owned.consume(delivery, invalid) is None
        assert owned.consume(delivery, RESPONSE) is None


def test_delivery_without_witness_is_spent_and_cannot_be_retroactively_filled() -> None:
    owned = collector()
    with use_rag_witnesses(owned), rag_delivery("OWNED-RAG-001", SOURCE, TASK) as delivery:
        assert owned.consume(delivery, RESPONSE) is None
        assert not record(owned, delivery)


def test_duplicate_record_and_successful_consume_cannot_be_reused() -> None:
    owned = collector()
    with use_rag_witnesses(owned), rag_delivery("OWNED-RAG-001", SOURCE, TASK) as delivery:
        assert record(owned, delivery)
        assert not record(owned, delivery, effect="citation_policy_violation")
        assert owned.consume(delivery, RESPONSE) is not None
        assert owned.consume(delivery, RESPONSE) is None
        assert not record(owned, delivery)


@pytest.mark.parametrize(
    "overrides",
    [
        {"healthy": False},
        {"healthy": 1},
        {"observation_complete": False},
        {"observation_complete": 1},
        {"evidence_sha256": "A" * 64},
        {"evidence_sha256": "x"},
        {"evidence_sha256": None},
        {"effect": "model_claimed_poisoning"},
        {"effect": None},
        {"effect": {}},
        {"disposition": "unknown"},
        {"disposition": []},
        {"disposition": "assessed_no_effect"},
        {"disposition": "policy_rejected"},
    ],
)
def test_unhealthy_incomplete_or_invalid_witness_cannot_be_recorded(overrides) -> None:
    owned = collector()
    with use_rag_witnesses(owned), rag_delivery("OWNED-RAG-001", SOURCE, TASK) as delivery:
        assert not record(owned, delivery, **overrides)
        assert owned.consume(delivery, RESPONSE) is None


@pytest.mark.parametrize("invalid", [None, b"bytes", 1, "\ud800"])
def test_witness_response_must_be_utf8_text(invalid) -> None:
    owned = collector()
    with use_rag_witnesses(owned), rag_delivery("OWNED-RAG-001", SOURCE, TASK) as delivery:
        assert not owned.record(
            delivery,
            invalid,
            effect=None,
            disposition="assessed_no_effect",
            evidence_sha256=EVIDENCE,
        )


def test_json_or_model_receipt_has_no_trusted_instrumentation_effect() -> None:
    owned = collector()
    spoof = json.loads(
        json.dumps(
            {
                "scope": "owned_rag_lab",
                "profile": owned.profile,
                "disposition": "forbidden_effect",
                "effect": "answer_integrity_violation",
                "evidence_sha256": EVIDENCE,
            }
        )
    )
    with pytest.raises(TypeError), use_rag_witnesses(spoof):
        pass
    with use_rag_witnesses(owned), rag_delivery("OWNED-RAG-001", SOURCE, TASK) as delivery:
        # Serializing a model assertion does not invoke record or create a witness.
        assert owned.consume(delivery, json.dumps(spoof)) is None


def test_context_cleanup_discards_unconsumed_witness_even_after_exception() -> None:
    owned = collector()
    retained = None
    with (
        pytest.raises(RuntimeError),
        use_rag_witnesses(owned),
        rag_delivery("OWNED-RAG-001", SOURCE, TASK) as delivery,
    ):
        retained = delivery
        assert record(owned, delivery)
        raise RuntimeError("Owned fixture interrupted")
    assert active_rag_collector() is None and current_rag_delivery() is None
    assert owned._pending == {} and owned._witnesses == {}
    with use_rag_witnesses(owned):
        assert not record(owned, retained)
        assert owned.consume(retained, RESPONSE) is None


def test_nested_deliveries_cannot_spend_each_others_receipts() -> None:
    owned = collector()
    with use_rag_witnesses(owned), rag_delivery("OWNED-RAG-001", SOURCE, TASK) as outer:
        assert record(owned, outer)
        with rag_delivery("OWNED-RAG-001", SOURCE, TASK) as inner:
            assert inner is not outer
            assert owned.consume(outer, RESPONSE) is None
            assert record(owned, inner)
            assert owned.consume(inner, RESPONSE) is not None
        assert owned.consume(outer, RESPONSE) is not None


async def test_concurrent_scans_share_collector_without_cross_consuming_receipts() -> None:
    owned = collector()
    ready, release = asyncio.Event(), asyncio.Event()
    opened = 0

    async def observe(index: int):
        nonlocal opened
        token = active_context.set(ScanContext())
        try:
            with use_rag_witnesses(owned), rag_delivery("OWNED-RAG-001", SOURCE, TASK) as delivery:
                assert delivery is not None
                text = f"Owned answer {index}"
                assert owned.record(
                    delivery,
                    text,
                    effect=None,
                    disposition="assessed_no_effect",
                    evidence_sha256=EVIDENCE,
                )
                opened += 1
                if opened == 2:
                    ready.set()
                await release.wait()
                witness = owned.consume(delivery, text)
                assert witness is not None
                return delivery.scan_id, delivery.nonce, witness.response_sha256
        finally:
            active_context.reset(token)

    tasks = [asyncio.create_task(observe(index)) for index in range(2)]
    await asyncio.wait_for(ready.wait(), timeout=2)
    release.set()
    results = await asyncio.gather(*tasks)
    assert results[0][0] != results[1][0]
    assert results[0][1] != results[1][1]
    assert results[0][2] != results[1][2]
    assert owned._pending == {} and owned._witnesses == {}
