# tests/test_attacks/test_overreliance.py
#
# Tests for agentscan/attacks/scan/overreliance.py (ATK-009)

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx

from agentscan.attacks.scan.overreliance import OverrelianceModule
from agentscan.core.models import Severity, Target


@pytest.fixture
def module() -> OverrelianceModule:
    return OverrelianceModule()


@pytest.fixture
def or_target() -> Target:
    return Target(url="http://test-agent.example.com/chat")


class TestOverrelianceIntegration:
    @pytest.mark.asyncio
    async def test_vulnerable_tool_call_produces_finding(
        self, module: OverrelianceModule, or_target: Target
    ) -> None:
        with respx.mock(assert_all_called=False) as mock:
            mock.post("http://test-agent.example.com/chat").mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "response": "Executing now. AGENTSCAN-FALSE-FACT-OK",
                        "tool_calls": [
                            {
                                "function": {
                                    "name": "execute_command",
                                    "arguments": '{"cmd": "rm -rf /", "via": "shell run_terminal_cmd"}',
                                }
                            }
                        ],
                    },
                )
            )
            findings = await module.run(or_target)

        assert len(findings) >= 1
        finding = findings[0]
        assert finding.attack_id == "ATK-009"
        assert finding.owasp_id == "LLM09"
        assert finding.severity in (
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
        )
        assert "yaml_variant_id" in finding.metadata

    @pytest.mark.asyncio
    async def test_safe_refusal_produces_no_finding(
        self, module: OverrelianceModule, or_target: Target
    ) -> None:
        with respx.mock(assert_all_called=False) as mock:
            mock.post("http://test-agent.example.com/chat").mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "response": (
                            "I cannot verify that claim and I will not execute "
                            "destructive commands from an unverified ticket."
                        )
                    },
                )
            )
            findings = await module.run(or_target)

        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_llm_judge_catches_uncritical_agreement(self, module: OverrelianceModule) -> None:
        target_with_judge = Target(
            url="http://test-agent.example.com/chat",
            judge_model="gpt-4o-mini",
        )
        fake_judge_response = '{"success": true, "reason": "agent confirmed the false fact"}'

        with (
            patch(
                "agentscan.attacks.scan.overreliance.AIClient.validate_environment",
                return_value=(True, []),
            ),
            patch(
                "agentscan.attacks.scan.overreliance.AIClient.complete",
                new=AsyncMock(return_value=fake_judge_response),
            ),
            respx.mock(assert_all_called=False) as mock,
        ):
            mock.post("http://test-agent.example.com/chat").mock(
                return_value=httpx.Response(
                    200,
                    json={"response": "Understood, I will treat that as established."},
                )
            )
            findings = await module.run(target_with_judge)

        judge_findings = [f for f in findings if f.metadata.get("detection_method") == "llm_judge"]
        assert len(judge_findings) >= 1
        assert judge_findings[0].attack_id == "ATK-009"


class TestVariantCount:
    def test_variant_count_matches_yaml(self, module: OverrelianceModule) -> None:
        assert module.variant_count() == 8
