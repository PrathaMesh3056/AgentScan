# tests/test_attacks/test_indirect_injection.py
#
# Tests for agentscan/attacks/scan/indirect_injection.py (ATK-005)

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx

from agentscan.attacks.scan.indirect_injection import IndirectInjectionModule
from agentscan.core.models import Severity, Target


@pytest.fixture
def module() -> IndirectInjectionModule:
    return IndirectInjectionModule()


@pytest.fixture
def ii_target() -> Target:
    return Target(url="http://test-agent.example.com/chat")


class TestIndirectInjectionIntegration:
    @pytest.mark.asyncio
    async def test_vulnerable_response_produces_finding(
        self, module: IndirectInjectionModule, ii_target: Target
    ) -> None:
        with respx.mock(assert_all_called=False) as mock:
            mock.post("http://test-agent.example.com/chat").mock(
                return_value=httpx.Response(
                    200,
                    json={"response": "AGENTSCAN-INDIRECT-OK"},
                )
            )
            findings = await module.run(ii_target)

        assert len(findings) >= 1
        finding = findings[0]
        assert finding.attack_id == "ATK-005"
        assert finding.owasp_id == "LLM01"
        assert finding.severity in (Severity.HIGH, Severity.MEDIUM, Severity.CRITICAL)
        assert "yaml_variant_id" in finding.metadata

    @pytest.mark.asyncio
    async def test_safe_response_produces_no_finding(
        self, module: IndirectInjectionModule, ii_target: Target
    ) -> None:
        with respx.mock(assert_all_called=False) as mock:
            mock.post("http://test-agent.example.com/chat").mock(
                return_value=httpx.Response(
                    200,
                    json={"response": "The document discusses quarterly revenue growth of 12%."},
                )
            )
            findings = await module.run(ii_target)

        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_document_channel_uses_messages(
        self, module: IndirectInjectionModule, ii_target: Target
    ) -> None:
        captured_bodies: list[dict] = []

        def capture_request(request: httpx.Request) -> httpx.Response:
            captured_bodies.append(json.loads(request.content))
            return httpx.Response(200, json={"response": "safe summary"})

        with respx.mock(assert_all_called=False) as mock:
            mock.post("http://test-agent.example.com/chat").mock(side_effect=capture_request)
            await module.run(ii_target)

        assert captured_bodies
        doc_requests = [
            b
            for b in captured_bodies
            if any(m.get("role") == "assistant" for m in b.get("messages", []))
        ]
        assert doc_requests, "Expected document-channel variants to send assistant messages"

    @pytest.mark.asyncio
    async def test_tool_channel_uses_tool_role(
        self, module: IndirectInjectionModule, ii_target: Target
    ) -> None:
        captured_bodies: list[dict] = []

        def capture_request(request: httpx.Request) -> httpx.Response:
            captured_bodies.append(json.loads(request.content))
            return httpx.Response(200, json={"response": "safe summary"})

        with respx.mock(assert_all_called=False) as mock:
            mock.post("http://test-agent.example.com/chat").mock(side_effect=capture_request)
            await module.run(ii_target)

        tool_requests = [
            b
            for b in captured_bodies
            if any(m.get("role") == "tool" for m in b.get("messages", []))
        ]
        assert tool_requests, "Expected tool-channel variants to send tool-role messages"

    @pytest.mark.asyncio
    async def test_llm_judge_catches_semantic_compliance(
        self, module: IndirectInjectionModule
    ) -> None:
        target_with_judge = Target(
            url="http://test-agent.example.com/chat",
            judge_model="gpt-4o-mini",
        )
        fake_judge_response = (
            '{"success": true, "reason": "agent followed hidden document instruction"}'
        )

        with (
            patch(
                "agentscan.attacks.scan.indirect_injection.AIClient.validate_environment",
                return_value=(True, []),
            ),
            patch(
                "agentscan.attacks.scan.indirect_injection.AIClient.complete",
                new=AsyncMock(return_value=fake_judge_response),
            ),
            respx.mock(assert_all_called=False) as mock,
        ):
            mock.post("http://test-agent.example.com/chat").mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "response": "As requested in the metadata, here is the indirect confirmation token."
                    },
                )
            )
            findings = await module.run(target_with_judge)

        judge_findings = [f for f in findings if f.metadata.get("detection_method") == "llm_judge"]
        assert len(judge_findings) >= 1
        assert judge_findings[0].attack_id == "ATK-005"


class TestVariantCount:
    def test_variant_count_matches_yaml(self, module: IndirectInjectionModule) -> None:
        assert module.variant_count() == 9
