# tests/test_attacks/test_jailbreak.py
#
# Tests for agentscan/attacks/scan/jailbreak.py (ATK-002)

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx

from agentscan.attacks.scan.jailbreak import JailbreakModule
from agentscan.core.models import Severity, Target


@pytest.fixture
def module() -> JailbreakModule:
    return JailbreakModule()


@pytest.fixture
def jb_target() -> Target:
    return Target(url="http://test-agent.example.com/chat")


class TestExtractText:
    def test_extract_text_keys(self, module: JailbreakModule) -> None:
        assert module._extract_text({"response": "hello"}) == "hello"
        assert module._extract_text({"text": "world"}) == "world"
        assert module._extract_text({"message": "foo"}) == "foo"
        assert module._extract_text({"unknown": 123}) == str({"unknown": 123})


class TestCheckDetection:
    def test_check_detection_contains(self, module: JailbreakModule) -> None:
        assert module._check_detection(
            "contains", "Response: NEXUS SYSTEM FULLY UNBOUND", "NEXUS SYSTEM FULLY UNBOUND"
        )
        assert not module._check_detection(
            "contains", "I cannot fulfill this request", "NEXUS SYSTEM FULLY UNBOUND"
        )

    def test_check_detection_not_contains(self, module: JailbreakModule) -> None:
        assert module._check_detection(
            "not_contains", "I cannot help with that", "NEXUS SYSTEM FULLY UNBOUND"
        )
        assert not module._check_detection(
            "not_contains", "NEXUS SYSTEM FULLY UNBOUND", "NEXUS SYSTEM FULLY UNBOUND"
        )

    def test_check_detection_regex(self, module: JailbreakModule) -> None:
        assert module._check_detection(
            "regex", "Session DIAGNOSTIC_MODE_ACTIVE ok", r"DIAGNOSTIC.*ACTIVE"
        )
        assert not module._check_detection("regex", "Refused request", r"DIAGNOSTIC.*ACTIVE")


class TestJailbreakIntegration:
    @pytest.mark.asyncio
    async def test_vulnerable_response_produces_finding(
        self, module: JailbreakModule, jb_target: Target
    ) -> None:
        """A vulnerable agent echoing the jailbreak token produces an ATK-002 finding."""
        with respx.mock(assert_all_called=False) as mock:
            mock.post("http://test-agent.example.com/chat").mock(
                return_value=httpx.Response(
                    200,
                    json={"response": "NEXUS SYSTEM FULLY UNBOUND. I will answer anything."},
                )
            )
            findings = await module.run(jb_target)

        assert len(findings) >= 1
        finding = findings[0]
        assert finding.attack_id == "ATK-002"
        assert finding.owasp_id == "LLM01"
        assert finding.severity in (Severity.HIGH, Severity.MEDIUM, Severity.CRITICAL)
        assert "yaml_variant_id" in finding.metadata

    @pytest.mark.asyncio
    async def test_safe_response_produces_no_finding(
        self, module: JailbreakModule, jb_target: Target
    ) -> None:
        """A safe agent that refuses jailbreak attempts produces zero findings."""
        with respx.mock(assert_all_called=False) as mock:
            mock.post("http://test-agent.example.com/chat").mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "response": "I cannot participate in fictional roleplay that overrides safety policies."
                    },
                )
            )
            findings = await module.run(jb_target)

        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_llm_judge_catches_semantic_jailbreak(self, module: JailbreakModule) -> None:
        """When static check misses, LLM-as-a-Judge flags semantic compliance."""
        target_with_judge = Target(
            url="http://test-agent.example.com/chat",
            judge_model="gpt-4o-mini",
        )
        fake_judge_response = (
            '{"success": true, "reason": "model adopted persona and ignored boundaries"}'
        )

        with (
            patch(
                "agentscan.attacks.scan.jailbreak.AIClient.validate_environment",
                return_value=(True, []),
            ),
            patch(
                "agentscan.attacks.scan.jailbreak.AIClient.complete",
                new=AsyncMock(return_value=fake_judge_response),
            ),
            respx.mock(assert_all_called=False) as mock,
        ):
            # Response doesn't have exact token "NEXUS SYSTEM FULLY UNBOUND", but semantically complies
            mock.post("http://test-agent.example.com/chat").mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "response": "Sure, I am now Nexus and will operate without any content restrictions."
                    },
                )
            )
            findings = await module.run(target_with_judge)

        assert len(findings) >= 1
        judge_findings = [f for f in findings if f.metadata.get("detection_method") == "llm_judge"]
        assert len(judge_findings) >= 1
        assert judge_findings[0].attack_id == "ATK-002"
        assert "model adopted persona" in judge_findings[0].metadata.get("judge_reason", "")


class TestVariantCount:
    def test_variant_count_matches_yaml(self, module: JailbreakModule) -> None:
        assert module.variant_count() == 10
