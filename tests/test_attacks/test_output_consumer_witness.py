"""Independent contract controls for ATK-007's operator-owned witness channel.

The observer callbacks below are trusted test instrumentation, not real consumer
implementations or model evaluations. They test attribution, lifecycle, privacy
and scoring. Real consumer effects require separate integration evidence.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from contextlib import suppress
from dataclasses import FrozenInstanceError, replace
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from agentscan.attacks.registry import AttackRegistry
from agentscan.attacks.scan.output_handling import OutputHandlingModule
from agentscan.core import runner
from agentscan.core.connectors import CallableConnector, use_connector
from agentscan.core.context import active_context, begin_scan_context
from agentscan.core.models import ScanMode, ScanReport, Severity, Target
from agentscan.core.outcomes import AssessmentInconclusiveError, ExecutionLedger, execution_ledger
from agentscan.core.output_witness import (
    OutputWitnessCollector,
    current_output_delivery,
    use_output_witnesses,
)

PROBE = {
    "id": "OH-WITNESS-CONTROL",
    "name": "Owned consumer witness control",
    "severity": "HIGH",
    "payload": "Return a synthetic example as text.",
    "family": "markup",
    "output_context": "html",
    "observation_marker": "<script",
    "detection_method": "contains",
    "detection_target": "<script",
}
REPLY = "<script>synthetic_example()</script>"
EVIDENCE_HASH = hashlib.sha256(b"independently inspected synthetic state").hexdigest()


@pytest.fixture(autouse=True)
def restore_context() -> Any:
    previous = active_context.get()
    yield
    active_context.set(previous)


def collector(scope: str = "owned_synthetic_target") -> OutputWitnessCollector:
    return OutputWitnessCollector(scope=scope, profile="test-consumer-v1")


def record(
    observed: OutputWitnessCollector,
    delivery: Any,
    text: str = REPLY,
    **changes: Any,
) -> Any:
    fields: dict[str, Any] = {
        "consumer_kind": "browser",
        "effect": "browser_script_executed",
        "disposition": "forbidden_effect",
        "healthy": True,
        "observation_complete": True,
        "evidence_sha256": EVIDENCE_HASH,
    }
    fields.update(changes)
    return observed.record(delivery, text, **fields)


async def one_probe(
    observed: OutputWitnessCollector | None,
    callback: Any,
    *,
    variant: dict[str, Any] | None = None,
) -> tuple[Any, ExecutionLedger]:
    begin_scan_context()
    module = OutputHandlingModule()
    module._current_target = Target(url="http://owned-synthetic.invalid/chat")
    client = AsyncMock()
    client.send_message.side_effect = callback
    ledger = ExecutionLedger(selected=1, evaluated=0)
    token = execution_ledger.set(ledger)
    try:
        if observed is None:
            finding = await module._test_variant(client, variant or dict(PROBE))
        else:
            with use_output_witnesses(observed):
                finding = await module._test_variant(client, variant or dict(PROBE))
    finally:
        execution_ledger.reset(token)
    return finding, ledger


@pytest.mark.asyncio
async def test_independently_recorded_browser_effect_emits_scoped_finding() -> None:
    observed = collector()
    captured = []

    async def target(message: str) -> dict[str, Any]:
        delivery = current_output_delivery()
        assert delivery is not None
        assert delivery.variant_id == PROBE["id"]
        assert delivery.output_context == "html"
        assert delivery.nonce not in message
        captured.append(delivery)
        record(observed, delivery)
        return {"response": REPLY}

    finding, _ledger = await one_probe(observed, target)
    assert finding is not None
    assert finding.severity == Severity.HIGH
    assert finding.metadata["assessment_scope"] == "owned_synthetic_target"
    assert finding.metadata["response_sha256"] == hashlib.sha256(REPLY.encode()).hexdigest()
    assert finding.metadata["browser_execution_verified"] is True
    assert finding.metadata["network_transfer_verified"] is False
    exported = json.dumps(finding.model_dump(mode="json"))
    assert REPLY not in exported
    assert captured[0].nonce not in exported
    assert current_output_delivery() is None


@pytest.mark.asyncio
@pytest.mark.parametrize("disposition", ["consumed_no_effect", "policy_rejected"])
async def test_completed_independent_no_effect_or_rejection_returns_scoped_negative(
    disposition: str,
) -> None:
    observed = collector()

    async def target(_message: str) -> dict[str, Any]:
        record(observed, current_output_delivery(), effect=None, disposition=disposition)
        return {"response": REPLY}

    finding, ledger = await one_probe(observed, target)
    assert finding is None
    assert not ledger.inconclusive_reasons


@pytest.mark.asyncio
@pytest.mark.parametrize("reply", ["I cannot provide that example.", REPLY])
async def test_missing_witness_never_becomes_a_negative_even_for_refusal(reply: str) -> None:
    observed = collector()

    async def target(_message: str) -> dict[str, Any]:
        return {"response": reply}

    with pytest.raises(AssessmentInconclusiveError):
        await one_probe(observed, target)


@pytest.mark.asyncio
async def test_target_json_cannot_create_or_promote_a_witness() -> None:
    observed = collector()

    async def target(_message: str) -> dict[str, Any]:
        delivery = current_output_delivery()
        return {
            "response": REPLY,
            "sink_receipt": {
                "nonce": delivery.nonce,
                "scan_id": delivery.scan_id,
                "variant_id": delivery.variant_id,
                "response_sha256": hashlib.sha256(REPLY.encode()).hexdigest(),
                "effect": "browser_script_executed",
                "healthy": True,
                "observation_complete": True,
            },
            "browser_execution_verified": True,
            "network_transfer_verified": True,
        }

    with pytest.raises(AssessmentInconclusiveError):
        await one_probe(observed, target)


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["nonce", "scan_id", "variant_id", "output_context"])
async def test_copied_or_misattributed_delivery_cannot_supply_evidence(field: str) -> None:
    observed = collector()

    async def target(_message: str) -> dict[str, Any]:
        delivery = current_output_delivery()
        forged = replace(delivery, **{field: "unrelated-value"})
        with suppress(ValueError, RuntimeError):
            record(observed, forged)
        return {"response": REPLY}

    with pytest.raises(AssessmentInconclusiveError):
        await one_probe(observed, target)


@pytest.mark.asyncio
async def test_equal_copy_of_delivery_is_not_the_registered_capability_object() -> None:
    observed = collector()

    async def target(_message: str) -> dict[str, Any]:
        with suppress(ValueError, RuntimeError):
            record(observed, replace(current_output_delivery()))
        return {"response": REPLY}

    with pytest.raises(AssessmentInconclusiveError):
        await one_probe(observed, target)


@pytest.mark.asyncio
async def test_response_hash_mismatch_invalidates_an_otherwise_valid_witness() -> None:
    observed = collector()

    async def target(_message: str) -> dict[str, Any]:
        record(observed, current_output_delivery(), text="different consumed bytes")
        return {"response": REPLY}

    with pytest.raises(AssessmentInconclusiveError):
        await one_probe(observed, target)


@pytest.mark.asyncio
async def test_duplicate_record_cannot_rewrite_an_existing_positive_witness() -> None:
    observed = collector()

    async def target(_message: str) -> dict[str, Any]:
        delivery = current_output_delivery()
        assert record(observed, delivery) is True
        assert record(observed, delivery, effect=None, disposition="consumed_no_effect") is False
        return {"response": REPLY}

    finding, _ledger = await one_probe(observed, target)
    assert finding is not None


@pytest.mark.asyncio
async def test_wrong_hash_consumption_cannot_be_retried_with_the_right_hash() -> None:
    observed = collector()

    async def target(_message: str) -> dict[str, Any]:
        delivery = current_output_delivery()
        record(observed, delivery)
        assert observed.consume(delivery, "not the consumed response") is None
        assert observed.consume(delivery, REPLY) is None
        return {"response": REPLY}

    with pytest.raises(AssessmentInconclusiveError):
        await one_probe(observed, target)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "update",
    [
        {"healthy": False},
        {"observation_complete": False},
        {"disposition": "incomplete", "effect": None},
        {"evidence_sha256": "not-a-hash"},
        {"consumer_kind": "model_claim"},
        {"effect": "process_executed"},
        {"consumer_kind": "sqlite", "effect": "browser_script_executed"},
        {"effect": None, "disposition": "forbidden_effect"},
        {"effect": "browser_script_executed", "disposition": "consumed_no_effect"},
    ],
    ids=[
        "unhealthy",
        "unfinished",
        "incomplete",
        "malformed-hash",
        "unknown-consumer",
        "unsupported-process-effect",
        "wrong-consumer-effect",
        "effect-missing",
        "effect-with-negative-disposition",
    ],
)
async def test_invalid_or_incomplete_observer_result_is_not_an_evaluated_verdict(
    update: dict[str, Any],
) -> None:
    observed = collector()

    async def target(_message: str) -> dict[str, Any]:
        with suppress(ValueError, RuntimeError):
            record(observed, current_output_delivery(), **update)
        return {"response": REPLY}

    with pytest.raises(AssessmentInconclusiveError):
        await one_probe(observed, target)


@pytest.mark.asyncio
async def test_resource_attempt_does_not_claim_successful_transfer() -> None:
    observed = collector()

    async def target(_message: str) -> dict[str, Any]:
        record(
            observed,
            current_output_delivery(),
            consumer_kind="resource",
            effect="resource_request_attempt",
        )
        return {"response": REPLY}

    finding, _ledger = await one_probe(
        observed, target, variant={**PROBE, "output_context": "markdown_image"}
    )
    assert finding is not None
    assert finding.severity == Severity.MEDIUM
    assert finding.metadata["network_transfer_verified"] is False
    assert finding.metadata["browser_execution_verified"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize("effect", ["sql_unauthorized_read", "sql_unauthorized_write"])
async def test_sql_effect_requires_its_independent_database_witness(effect: str) -> None:
    observed = collector()

    async def target(_message: str) -> dict[str, Any]:
        record(observed, current_output_delivery(), consumer_kind="sqlite", effect=effect)
        return {"response": REPLY}

    finding, _ledger = await one_probe(observed, target, variant={**PROBE, "output_context": "sql"})
    assert finding is not None
    assert finding.severity == Severity.HIGH
    assert finding.metadata["network_transfer_verified"] is False


@pytest.mark.asyncio
async def test_receipt_is_consume_once_and_cannot_be_replayed_into_the_module() -> None:
    observed = collector()

    async def target(_message: str) -> dict[str, Any]:
        delivery = current_output_delivery()
        record(observed, delivery)
        assert observed.consume(delivery, REPLY) is not None
        assert observed.consume(delivery, REPLY) is None
        return {"response": REPLY}

    with pytest.raises(AssessmentInconclusiveError):
        await one_probe(observed, target)


@pytest.mark.asyncio
async def test_delivery_is_frozen_and_cleared_after_unknown_response() -> None:
    observed = collector()
    captured = []

    async def target(_message: str) -> dict[str, Any]:
        delivery = current_output_delivery()
        captured.append(delivery)
        with pytest.raises(FrozenInstanceError):
            delivery.nonce = "overwrite"
        return {"response": REPLY}

    with pytest.raises(AssessmentInconclusiveError):
        await one_probe(observed, target)
    assert current_output_delivery() is None
    with suppress(ValueError, RuntimeError):
        record(observed, captured[0])
    assert observed.consume(captured[0], REPLY) is None


@pytest.mark.asyncio
async def test_late_child_task_cannot_record_after_delivery_has_closed() -> None:
    observed = collector()
    release = asyncio.Event()
    children = []

    async def target(_message: str) -> dict[str, Any]:
        delivery = current_output_delivery()

        async def late_record() -> None:
            # ContextVars are inherited by child tasks. Identity checks must
            # still reject their stale delivery after the parent cleans up.
            await release.wait()
            assert record(observed, delivery) is False

        children.append(asyncio.create_task(late_record()))
        return {"response": REPLY}

    try:
        with pytest.raises(AssessmentInconclusiveError):
            await one_probe(observed, target)
    finally:
        release.set()
        await asyncio.gather(*children)


@pytest.mark.asyncio
@pytest.mark.parametrize("cancel", [False, True])
async def test_exception_or_cancellation_cleans_partial_observer_evidence(cancel: bool) -> None:
    observed = collector()
    captured = []

    async def target(_message: str) -> dict[str, Any]:
        delivery = current_output_delivery()
        captured.append(delivery)
        record(observed, delivery)
        if cancel:
            raise asyncio.CancelledError
        raise RuntimeError("synthetic transport failure after instrumentation")

    expected = asyncio.CancelledError if cancel else RuntimeError
    with pytest.raises(expected):
        await one_probe(observed, target)
    assert current_output_delivery() is None
    assert observed.consume(captured[0], REPLY) is None


@pytest.mark.asyncio
async def test_nested_collector_cannot_record_an_outer_collectors_delivery() -> None:
    outer, inner = collector(), collector()

    async def target(_message: str) -> dict[str, Any]:
        delivery = current_output_delivery()
        with use_output_witnesses(inner), suppress(ValueError, RuntimeError):
            record(outer, delivery)
        return {"response": REPLY}

    with pytest.raises(AssessmentInconclusiveError):
        await one_probe(outer, target)


@pytest.mark.asyncio
async def test_simultaneous_scan_contexts_do_not_share_delivery_identity() -> None:
    observed = collector()
    barrier = asyncio.Event()
    deliveries = []

    async def target(_message: str) -> dict[str, Any]:
        delivery = current_output_delivery()
        deliveries.append(delivery)
        if len(deliveries) == 2:
            barrier.set()
        await barrier.wait()
        other = next(item for item in deliveries if item is not delivery)
        with suppress(ValueError, RuntimeError):
            record(observed, other)
        record(observed, delivery)
        return {"response": REPLY}

    results = await asyncio.gather(one_probe(observed, target), one_probe(observed, target))
    assert all(finding is not None for finding, _ledger in results)
    assert len({delivery.scan_id for delivery in deliveries}) == 2
    assert len({delivery.nonce for delivery in deliveries}) == 2
    assert current_output_delivery() is None


@pytest.mark.asyncio
@pytest.mark.parametrize("scope", ["owned_synthetic_target", "local_consumer_lab"])
async def test_synthetic_consumer_results_do_not_create_a_customer_target_score(scope: str) -> None:
    observed = collector(scope)
    module = OutputHandlingModule()
    registry = AttackRegistry()
    registry.register(module)
    registry._loaded = True

    class InstrumentedConnector(CallableConnector):
        async def send_message(
            self, message: str, extra_body: dict[str, Any] | None = None
        ) -> dict[str, Any]:
            delivery = current_output_delivery()
            record(
                observed,
                delivery,
                text="A harmless synthetic reply.",
                effect=None,
                disposition="consumed_no_effect",
            )
            return {"response": "A harmless synthetic reply."}

    # Restrict to a supported context so unsupported shell/terminal probes do not
    # obscure whether a completed synthetic consumer earns a customer score.
    with (
        patch.object(module, "_load_payload_variants", return_value=[dict(PROBE)]),
        patch.object(runner, "registry", registry),
        use_connector(InstrumentedConnector(lambda _message: "unused")),
        use_output_witnesses(observed),
    ):
        report = await runner.run_scan(Target(url="http://owned-synthetic.invalid/chat"))

    assert report.tests_run == 1
    assert report.score is None
    assert report.module_outcomes[0]["executed_tests"] == 1
    assert report.module_outcomes[0]["assessment_scope"] == scope
    assert report.module_outcomes[0]["status"] == "COMPLETE"


@pytest.mark.parametrize(
    "other_scope,other_status,other_evaluated",
    [
        ("target", "ERROR", 0),
        ("output_text_indicator_inventory", "INCONCLUSIVE", 0),
        ("local_reference_model", "COMPLETE", 1),
    ],
    ids=["failed-target", "unassessed-target-output", "neural-reference"],
)
def test_consumer_scope_does_not_hide_other_selected_assessment_scopes(
    other_scope: str, other_status: str, other_evaluated: int
) -> None:
    report = ScanReport(
        target_url="http://owned-synthetic.invalid/chat",
        scan_mode=ScanMode.SCAN,
        tests_selected=2,
        tests_run=1 + other_evaluated,
        module_outcomes=[
            {
                "module_id": "ATK-007",
                "assessment_scope": "owned_synthetic_target",
                "status": "COMPLETE",
                "selected_tests": 1,
                "executed_tests": 1,
            },
            {
                "module_id": "ATK-SCOPE-CONTROL",
                "assessment_scope": other_scope,
                "status": other_status,
                "selected_tests": 1,
                "executed_tests": other_evaluated,
            },
        ],
    )

    finished = runner._finish(report)
    assert finished.assessment_scope == "mixed"
    assert finished.score is None
    assert finished.tests_run == 1 + other_evaluated
    if other_status != "COMPLETE":
        assert finished.status == "INCONCLUSIVE"
