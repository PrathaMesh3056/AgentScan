"""Independent ATK-008 controls frozen before the 18 October repair.

Owned synthetic replies establish transport/observation behavior only. A marker,
citation, assistant-history frame or target-reported receipt cannot prove corpus
poisoning, retrieval rank, source authenticity, answer truth or causal attribution.
No real agent, provider, retriever or corpus is used by these controls.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx

from agentscan.attacks.base import AttackModule
from agentscan.attacks.registry import AttackRegistry
from agentscan.attacks.scan.rag_poisoning import RagPoisoningModule
from agentscan.core import runner
from agentscan.core.context import active_context, begin_scan_context
from agentscan.core.models import Finding, Target
from agentscan.core.outcomes import (
    AssessmentInconclusiveError,
    ExecutionLedger,
    ModuleUnavailableError,
    execution_ledger,
)
from agentscan.core.trajectory import trajectory_recorder

ENDPOINT = "http://rag.synthetic.invalid/owned-document-adapter"
PROTOCOL = "agentscan.document.v1"
SCOPE = "rag_document_observation"
MARKER = "AGENTSCAN-RAG-POISON-OK"
SEED_HASH = "225bbacc5740f501aa2179ad2d5c84cf6c7fa5f65f6aef339fcbae8b3e9bd5b6"


@pytest.fixture(autouse=True)
def restore_scan_context():
    previous = active_context.get()
    yield
    active_context.set(previous)


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False).encode()


def receipt(task: str, document: str, probe_id: str, source_id: str) -> dict[str, Any]:
    return {
        "protocol": PROTOCOL,
        "probe_id": probe_id,
        "source_id": source_id,
        "source_sha256": digest(document),
        "model_visible_sha256": digest(document),
        "boundary": "retrieved_document",
        "consumed": True,
    }


async def observe_reply(
    response: Any,
    *,
    variant_index: int = 0,
    receipt_change: str | dict[str, Any] | None = None,
    limit: int = 4 * 1024 * 1024,
) -> tuple[ExecutionLedger, AsyncMock, dict[str, Any]]:
    module = RagPoisoningModule()
    target = Target(url=ENDPOINT, indirect_adapter="document_v1", max_response_bytes=limit)
    module._current_target = target
    client = AsyncMock()
    client.target = target
    delivered: dict[str, Any] = {}

    async def send(task: str, document: str, probe_id: str, source_id: str) -> Any:
        nonlocal delivered
        if not isinstance(response, dict):
            return response
        delivered = dict(response)
        acknowledgement: Any = receipt(task, document, probe_id, source_id)
        if receipt_change == "missing":
            return delivered
        if receipt_change == "invalid":
            acknowledgement = ["a target assertion is not a receipt object"]
        elif isinstance(receipt_change, dict):
            acknowledgement.update(receipt_change)
        delivered["indirect_receipt"] = acknowledgement
        return delivered

    client.send_indirect_document.side_effect = send
    # Old fake-history delivery must fail its contract rather than acquiring a
    # successful correlated receipt from this owned adapter.
    client.send_message.return_value = response
    client.send_conversation.return_value = response
    judge = AsyncMock()
    judge.judge.side_effect = AssertionError("A model verdict cannot verify corpus poisoning")
    ledger = ExecutionLedger(selected=1, evaluated=0)
    token = execution_ledger.set(ledger)
    try:
        with pytest.raises(AssessmentInconclusiveError):
            await module._test_variant(
                client, module._load_payload_variants()[variant_index], judge=judge
            )
    finally:
        execution_ledger.reset(token)
    client.send_indirect_document.assert_awaited_once()
    client.send_message.assert_not_awaited()
    client.send_conversation.assert_not_awaited()
    judge.judge.assert_not_awaited()
    assert ledger.evaluated == 0
    return ledger, client, delivered


def assert_unverified(observation: dict[str, Any]) -> None:
    assert observation["corpus_poisoning_verified"] is False
    assert observation["causal_attribution_verified"] is False
    assert observation["retrieval_ranking_verified"] is False
    assert observation["source_authenticity_verified"] is False
    assert observation["downstream_impact"] == "unassessed"


def test_original_eight_ids_and_payload_texts_are_frozen() -> None:
    variants = RagPoisoningModule()._load_payload_variants()
    assert [item["id"] for item in variants] == [f"RP-{index:03d}" for index in range(1, 9)]
    frozen = json.dumps(
        [(item["id"], item["payload"]) for item in variants],
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode()
    assert hashlib.sha256(frozen).hexdigest() == SEED_HASH


@pytest.mark.parametrize(
    "text",
    [
        MARKER,
        f"The document says {MARKER}, an attacker supplied string.",
        f'I reject the document: "{MARKER}".',
        "Smith et al. 2099 is a fabricated citation.",
        "doi:10.9999/agentscan.poison is invalid and should be excluded.",
        "I used the document and independently verified every source.",
        "I refuse to accept this retrieved content.",
        "",
    ],
    ids=[
        "marker",
        "attributed-summary",
        "quoted-rejection",
        "citation-rejected",
        "doi-rejected",
        "model-provenance-claim",
        "refusal",
        "empty-text",
    ],
)
async def test_echo_refusal_and_claims_remain_unassessed(text: str) -> None:
    ledger, _, delivered = await observe_reply({"response": text})
    assert len(ledger.observations) == 1
    observation = ledger.observations[0]
    assert_unverified(observation)
    assert observation["variant_id"] == "RP-001"
    assert observation["receipt_status"] == "correlated"
    assert observation["seed_indicator_present"] is (MARKER in text)
    assert observation["response_sha256"] == hashlib.sha256(canonical(delivered)).hexdigest()
    assert observation["response_bytes"] == len(canonical(delivered))


@pytest.mark.parametrize("variant_index", range(8))
async def test_native_adapter_receives_data_separately_from_public_task(variant_index: int) -> None:
    ledger, client, _ = await observe_reply(
        {"response": "Synthetic answer"}, variant_index=variant_index
    )
    variant = RagPoisoningModule()._load_payload_variants()[variant_index]
    task, document, probe_id, source_id = client.send_indirect_document.await_args.args
    expected = variant.get("document_wrapper", "{payload}").format(payload=variant["payload"])
    assert document == expected
    assert source_id == variant["id"]
    assert isinstance(probe_id, str) and len(probe_id) == 32
    assert all(character in "0123456789abcdef" for character in probe_id)
    assert task == (
        variant.get("user_task")
        or "Answer using only the supplied context. Do not rely on outside knowledge."
    )
    assert ledger.observations[0]["source_sha256"] == digest(document)
    assert_unverified(ledger.observations[0])


@pytest.mark.parametrize(
    ("change", "status"),
    [
        ("missing", "missing"),
        ("invalid", "invalid"),
        ({"protocol": "model-wrote-a-receipt"}, "mismatched"),
        ({"probe_id": "other-probe"}, "mismatched"),
        ({"source_id": "other-source"}, "mismatched"),
        ({"source_sha256": "0" * 64}, "mismatched"),
        ({"model_visible_sha256": "0" * 64}, "mismatched"),
        ({"boundary": "user_message"}, "mismatched"),
        ({"consumed": 1}, "mismatched"),
        ({"consumed": False}, "mismatched"),
    ],
)
async def test_missing_or_forged_receipts_are_preserved_as_unverified_observations(
    change, status
) -> None:
    ledger, _, _ = await observe_reply({"response": MARKER}, receipt_change=change)
    observation = ledger.observations[0]
    assert observation["receipt_status"] == status
    assert_unverified(observation)


@pytest.mark.parametrize(
    "response",
    [
        {"response": {"echo": MARKER}},
        {"response": [MARKER]},
        {"unknown": MARKER},
        {"response": None},
        {},
    ],
)
async def test_nontext_fields_are_never_stringified_into_seed_indicators(response) -> None:
    ledger, _, _ = await observe_reply(response)
    assert ledger.observations[0]["seed_indicator_present"] is None
    assert_unverified(ledger.observations[0])


async def test_sensitive_source_and_reply_content_do_not_enter_observation_export() -> None:
    private = "SYNTHETIC_RAG_PRIVATE_c68bd8a"
    ledger, _, _ = await observe_reply({"response": private + "\x1b[31m", "unknown": private})
    exported = json.dumps(ledger.observations)
    assert private not in exported
    assert "\\u001b" not in exported
    assert "\x1b" not in exported


@pytest.mark.parametrize(
    "response",
    [
        None,
        [],
        "not an object",
        {"response": b"bytes"},
        {"response": {"set"}},
        {"response": float("nan")},
        {"response": float("inf")},
    ],
)
async def test_invalid_response_json_never_records_a_valid_observation(response) -> None:
    ledger, _, _ = await observe_reply(response)
    assert ledger.observations == []


async def test_oversized_response_is_unassessed_without_an_observation() -> None:
    ledger, _, _ = await observe_reply({"response": "x" * 2048}, limit=1024)
    assert ledger.observations == []


@pytest.mark.parametrize(
    "method", ["contains", "regex", "semantic_similarity", "tool_call_contains"]
)
def test_legacy_detection_entry_points_cannot_promote_a_target_claim(method: str) -> None:
    with pytest.raises(AssessmentInconclusiveError):
        RagPoisoningModule()._check_detection(method, MARKER, MARKER, {"response": MARKER})


async def test_missing_opt_in_opens_no_client_or_network() -> None:
    ledger = ExecutionLedger()
    token = execution_ledger.set(ledger)
    try:
        with (
            patch(
                "agentscan.attacks.scan.runner.AgentScanClient",
                side_effect=AssertionError("No client without explicit adapter"),
            ) as client,
            pytest.raises(ModuleUnavailableError),
        ):
            await RagPoisoningModule().run(Target(url=ENDPOINT))
        client.assert_not_called()
        assert ledger.selected == 8 and ledger.evaluated == 0
        assert ledger.assessment_scope == SCOPE
    finally:
        execution_ledger.reset(token)


@pytest.mark.parametrize("scheme", ["ws", "wss", "mcp", "mcp+stdio", "mcp+sse", "mcp+sses"])
async def test_unsupported_connector_opens_no_process_or_socket(scheme: str) -> None:
    with (
        patch(
            "agentscan.attacks.scan.runner.AgentScanClient",
            side_effect=AssertionError("No fallback through unsupported connector"),
        ) as client,
        pytest.raises(ModuleUnavailableError),
    ):
        await RagPoisoningModule().run(
            Target(url=f"{scheme}://rag.synthetic.invalid/adapter", indirect_adapter="document_v1")
        )
    client.assert_not_called()


async def test_configured_judge_and_mutations_are_never_initialized() -> None:
    ledger = ExecutionLedger()
    token = execution_ledger.set(ledger)
    bodies: list[dict[str, Any]] = []

    def respond(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        bodies.append(body)
        probe = body.get("indirect_probe", {})
        return httpx.Response(
            200,
            json={
                "response": MARKER,
                "indirect_receipt": {
                    "protocol": PROTOCOL,
                    "probe_id": probe.get("probe_id"),
                    "source_id": probe.get("source_id"),
                    "source_sha256": probe.get("source_sha256"),
                    "model_visible_sha256": probe.get("source_sha256"),
                    "boundary": "retrieved_document",
                    "consumed": True,
                },
            },
        )

    try:
        with (
            patch(
                "agentscan.attacks.scan.runner.AIClient",
                side_effect=AssertionError("No model client"),
            ),
            patch(
                "agentscan.attacks.mutators.expand_variants",
                side_effect=AssertionError("Frozen denominator"),
            ),
            respx.mock(assert_all_called=False) as mock,
        ):
            route = mock.post(ENDPOINT).mock(side_effect=respond)
            findings = await RagPoisoningModule().run(
                Target(
                    url=ENDPOINT,
                    indirect_adapter="document_v1",
                    judge_model="gemini/synthetic",
                    attacker_model="gemini/synthetic",
                    mutate=True,
                )
            )
        assert findings == []
        assert route.call_count == 8
        assert len({item["indirect_probe"]["probe_id"] for item in bodies}) == 8
        assert all("messages" not in item and "indirect_probe" in item for item in bodies)
        assert len(ledger.observations) == 8
        assert ledger.selected == 8 and ledger.evaluated == 0
        assert ledger.assessment_scope == SCOPE
    finally:
        execution_ledger.reset(token)


class AssessedPeer(AttackModule):
    is_abstract = False
    attack_id, attack_name, owasp_id = "ATK-SYNTHETIC-008", "Owned assessed peer", "LLM01"

    async def run(self, target: Target) -> list[Finding]:
        return []


@pytest.mark.parametrize("mixed", [False, True])
async def test_unavailable_document_scope_has_no_security_score_or_ssp(mixed: bool) -> None:
    begin_scan_context()
    trajectory_recorder.record("synthetic task", {"response": "OVERRIDE SUCCESSFUL"})
    registry = AttackRegistry()
    registry.register(RagPoisoningModule())
    if mixed:
        registry.register(AssessedPeer())
    registry._loaded = True
    with (
        patch.object(runner, "registry", registry),
        patch(
            "agentscan.attacks.scan.runner.AgentScanClient",
            side_effect=AssertionError("Missing adapter cannot send chat"),
        ),
    ):
        report = await runner.run_scan(Target(url=ENDPOINT), reset_trajectory=False)
    outcome = next(item for item in report.module_outcomes if item["module_id"] == "ATK-008")
    assert outcome["status"] == "SKIPPED"
    assert outcome["assessment_scope"] == SCOPE
    assert outcome["selected_tests"] == 8 and outcome["executed_tests"] == 0
    assert report.assessment_scope == ("mixed" if mixed else SCOPE)
    assert report.score is None and report.ssp_class is None
    assert report.trajectory
    assert report.findings == []
