"""Public ATK-008 adapter behavior through the production HTTP client."""

from __future__ import annotations

import json
from unittest.mock import patch

import httpx
import pytest
import respx

from agentscan.attacks.scan.rag_poisoning import RagPoisoningModule
from agentscan.core.models import Target
from agentscan.core.outcomes import ExecutionLedger, ModuleUnavailableError, execution_ledger

ENDPOINT = "http://rag.synthetic.invalid/document-v1"


def test_variant_count_matches_frozen_seed_set() -> None:
    assert RagPoisoningModule().variant_count() == 8


async def test_plain_chat_cannot_run_a_document_probe() -> None:
    with pytest.raises(ModuleUnavailableError):
        await RagPoisoningModule().run(Target(url=ENDPOINT))


async def test_document_adapter_retains_quoted_markers_as_observations() -> None:
    requests: list[dict] = []
    ledger = ExecutionLedger()
    token = execution_ledger.set(ledger)

    def answer(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        requests.append(body)
        return httpx.Response(
            200,
            json={
                "response": (
                    "The untrusted document says AGENTSCAN-RAG-POISON-OK; "
                    "I cannot verify that claim."
                )
            },
        )

    try:
        with respx.mock(assert_all_called=False) as mock:
            route = mock.post(ENDPOINT).mock(side_effect=answer)
            findings = await RagPoisoningModule().run(
                Target(url=ENDPOINT, indirect_adapter="document_v1")
            )
        assert route.call_count == 8
        assert findings == []
        assert ledger.evaluated == 0
        assert len(ledger.observations) == 8
        assert all(row["receipt_status"] == "missing" for row in ledger.observations)
        assert all("indirect_probe" in row and "messages" not in row for row in requests)
        assert all(row["message"] for row in requests)
    finally:
        execution_ledger.reset(token)


async def test_configured_judge_does_not_promote_a_document_reply() -> None:
    with (
        patch(
            "agentscan.attacks.scan.runner.AIClient",
            side_effect=AssertionError("No LLM judge for ATK-008"),
        ),
        respx.mock(assert_all_called=False) as mock,
    ):
        mock.post(ENDPOINT).mock(
            return_value=httpx.Response(200, json={"response": "Smith et al. 2099"})
        )
        ledger = ExecutionLedger()
        token = execution_ledger.set(ledger)
        try:
            findings = await RagPoisoningModule().run(
                Target(
                    url=ENDPOINT,
                    indirect_adapter="document_v1",
                    judge_model="gemini/synthetic",
                )
            )
        finally:
            execution_ledger.reset(token)
    assert findings == []
    assert ledger.evaluated == 0
