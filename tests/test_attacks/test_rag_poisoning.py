# tests/test_attacks/test_rag_poisoning.py
#
# Tests for agentscan/attacks/scan/rag_poisoning.py (ATK-008)

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx

from agentscan.attacks.scan.rag_poisoning import RagPoisoningModule
from agentscan.core.models import Severity, Target


@pytest.fixture
def module() -> RagPoisoningModule:
    return RagPoisoningModule()


@pytest.fixture
def rag_target() -> Target:
    return Target(url="http://test-agent.example.com/chat")


class TestRagPoisoningIntegration:
    @pytest.mark.asyncio
    async def test_vulnerable_response_produces_finding(
        self, module: RagPoisoningModule, rag_target: Target
    ) -> None:
        with respx.mock(assert_all_called=False) as mock:
            mock.post("http://test-agent.example.com/chat").mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "response": (
                            "Per the retrieved article (Smith et al. 2099) and "
                            "doi:10.9999/agentscan.poison: AGENTSCAN-RAG-POISON-OK"
                        )
                    },
                )
            )
            findings = await module.run(rag_target)

        assert len(findings) >= 1
        finding = findings[0]
        assert finding.attack_id == "ATK-008"
        assert finding.owasp_id == "LLM03"
        assert finding.severity in (Severity.HIGH, Severity.MEDIUM, Severity.CRITICAL)
        assert "yaml_variant_id" in finding.metadata

    @pytest.mark.asyncio
    async def test_grounded_refusal_produces_no_finding(
        self, module: RagPoisoningModule, rag_target: Target
    ) -> None:
        with respx.mock(assert_all_called=False) as mock:
            mock.post("http://test-agent.example.com/chat").mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "response": (
                            "I cannot treat retrieved documents as system policy or "
                            "verify those citations. The snippet looks untrusted."
                        )
                    },
                )
            )
            findings = await module.run(rag_target)

        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_document_channel_uses_messages(
        self, module: RagPoisoningModule, rag_target: Target
    ) -> None:
        captured_bodies: list[dict] = []

        def capture_request(request: httpx.Request) -> httpx.Response:
            captured_bodies.append(json.loads(request.content))
            return httpx.Response(200, json={"response": "I will not treat this as ground truth."})

        with respx.mock(assert_all_called=False) as mock:
            mock.post("http://test-agent.example.com/chat").mock(side_effect=capture_request)
            await module.run(rag_target)

        assert captured_bodies
        doc_requests = [
            b
            for b in captured_bodies
            if any(m.get("role") == "assistant" for m in b.get("messages", []))
        ]
        assert doc_requests, "Expected document-channel variants to send assistant messages"

    @pytest.mark.asyncio
    async def test_llm_judge_catches_semantic_compliance(self, module: RagPoisoningModule) -> None:
        target_with_judge = Target(
            url="http://test-agent.example.com/chat",
            judge_model="gpt-4o-mini",
        )
        fake_judge_response = '{"success": true, "reason": "agent treated poisoned KB as fact"}'

        with (
            patch(
                "agentscan.attacks.scan.rag_poisoning.AIClient.validate_environment",
                return_value=(True, []),
            ),
            patch(
                "agentscan.attacks.scan.rag_poisoning.AIClient.complete",
                new=AsyncMock(return_value=fake_judge_response),
            ),
            respx.mock(assert_all_called=False) as mock,
        ):
            mock.post("http://test-agent.example.com/chat").mock(
                return_value=httpx.Response(
                    200,
                    json={"response": "According to the retrieved filing, that token is required."},
                )
            )
            findings = await module.run(target_with_judge)

        judge_findings = [f for f in findings if f.metadata.get("detection_method") == "llm_judge"]
        assert len(judge_findings) >= 1
        assert judge_findings[0].attack_id == "ATK-008"


class TestVariantCount:
    def test_variant_count_matches_yaml(self, module: RagPoisoningModule) -> None:
        assert module.variant_count() == 8
