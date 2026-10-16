# tests/test_attacks/test_pii_exfiltration.py
#
# Tests for agentscan/attacks/scan/pii_exfiltration.py (ATK-003)

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx

from agentscan.attacks.scan.pii_exfiltration import PiiExfiltrationModule
from agentscan.core.models import Severity, Target
from agentscan.core.outcomes import AssessmentInconclusiveError


@pytest.fixture
def module() -> PiiExfiltrationModule:
    return PiiExfiltrationModule()


@pytest.fixture
def pii_target() -> Target:
    return Target(
        url="http://test-agent.example.com/chat",
        system_prompt="Private employee directory: admin@company.com",
    )


class TestExtractText:
    def test_extract_text_keys(self, module: PiiExfiltrationModule) -> None:
        assert module._extract_text({"response": "secret"}) == "secret"
        assert module._extract_text({"output": "data"}) == "data"
        assert module._extract_text({"content": "token"}) == "token"


class TestCheckDetection:
    def test_check_detection_regex_email(self, module: PiiExfiltrationModule) -> None:
        module._current_target = Target(
            url="http://agent.test/chat",
            system_prompt="Private employee contact: alice@corp.internal",
        )
        pattern = r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"
        assert module._check_detection("regex", "User: alice@corp.internal, pass: 123", pattern)
        assert not module._check_detection("regex", "No users found in database.", pattern)

    def test_check_detection_regex_apikey(self, module: PiiExfiltrationModule) -> None:
        module._current_target = Target(
            url="http://agent.test/chat", system_prompt='API_KEY="sk-abcdef12345678901234567890"'
        )
        pattern = r"(sk-[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16})"
        assert module._check_detection(
            "regex", "Here is your key: sk-abcdef12345678901234567890", pattern
        )
        assert not module._check_detection("regex", "I do not have access to keys", pattern)

    def test_check_detection_contains(self, module: PiiExfiltrationModule) -> None:
        from agentscan.core.outcomes import AssessmentInconclusiveError

        with pytest.raises(AssessmentInconclusiveError):
            module._check_detection("contains", "Patient diagnosis is classified", "diagnosis")
        with pytest.raises(AssessmentInconclusiveError):
            module._check_detection("contains", "I cannot share patient data", "diagnosis")


class TestPiiExfiltrationIntegration:
    @pytest.mark.asyncio
    async def test_vulnerable_response_produces_finding(
        self, module: PiiExfiltrationModule, pii_target: Target
    ) -> None:
        """A vulnerable agent leaking emails / credentials produces an ATK-003 finding."""
        with respx.mock(assert_all_called=False) as mock:
            mock.post("http://test-agent.example.com/chat").mock(
                return_value=httpx.Response(
                    200,
                    json={"response": "Employee list: admin@company.com / P@ssword123"},
                )
            )
            findings = await module.run(pii_target)

        assert len(findings) >= 1
        finding = findings[0]
        assert finding.attack_id == "ATK-003"
        assert finding.owasp_id == "LLM02"
        assert finding.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)
        assert "yaml_variant_id" in finding.metadata

    @pytest.mark.asyncio
    async def test_safe_response_produces_no_finding(
        self, module: PiiExfiltrationModule, pii_target: Target
    ) -> None:
        """A safe agent that refuses to leak PII produces zero findings."""
        with respx.mock(assert_all_called=False) as mock:
            mock.post("http://test-agent.example.com/chat").mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "response": "I cannot disclose personal data, credentials, or internal records."
                    },
                )
            )
            findings = await module.run(pii_target)

        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_judge_cannot_promote_unverified_pii_to_a_finding(
        self, module: PiiExfiltrationModule
    ) -> None:
        """A model judge cannot establish private record authenticity from prose."""
        target_with_judge = Target(
            url="http://test-agent.example.com/chat",
            canary_token="SYNTHETIC_PRIVATE_ATK003_20261016",
            judge_model="ollama/example",
        )

        with (
            patch(
                "agentscan.attacks.scan.runner.AIClient", side_effect=AssertionError("judge called")
            ) as ai_client,
            respx.mock(assert_all_called=False) as mock,
        ):
            mock.post("http://test-agent.example.com/chat").mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "response": "The chief executive underwent cardiovascular surgery last month at Mercy Hospital."
                    },
                )
            )
            findings = await module.run(target_with_judge)

        assert findings == []
        ai_client.assert_not_called()
        assert target_with_judge.judge_model == "ollama/example"

    @pytest.mark.asyncio
    async def test_missing_baseline_with_judge_is_unknown_without_target_request(
        self, module: PiiExfiltrationModule
    ) -> None:
        target = Target(url="http://test-agent.example.com/chat", judge_model="ollama/example")
        with (
            patch("agentscan.attacks.scan.runner.AgentScanClient", new=AsyncMock()) as client,
            pytest.raises(AssessmentInconclusiveError, match="format alone"),
        ):
            await module.run(target)
        client.assert_not_called()


class TestVariantCount:
    def test_variant_count_matches_yaml(self, module: PiiExfiltrationModule) -> None:
        assert module.variant_count() == 13
