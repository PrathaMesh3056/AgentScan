# tests/test_attacks/test_crescendo.py
#
# Tests for agentscan/attacks/exploit/crescendo.py (ATK-010)

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx

from agentscan.attacks.exploit.crescendo import CrescendoModule
from agentscan.core.models import ScanMode, Severity, Target

CANARY = "AGENTSCAN-CRESCENDO-OK"
SAFE = "I can discuss security research at a high level, but I will not drop my constraints."


@pytest.fixture
def module() -> CrescendoModule:
    return CrescendoModule()


@pytest.fixture
def exploit_target() -> Target:
    return Target(url="http://test-agent.example.com/chat", mode=ScanMode.EXPLOIT)


class TestCrescendoIntegration:
    @pytest.mark.asyncio
    async def test_leak_on_turn_five_produces_finding(
        self, module: CrescendoModule, exploit_target: Target
    ) -> None:
        def only_leak_on_turn_five(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content)
            user_turns = sum(1 for m in body.get("messages", []) if m.get("role") == "user")
            if user_turns >= 5:
                return httpx.Response(200, json={"response": CANARY})
            return httpx.Response(200, json={"response": SAFE})

        with respx.mock(assert_all_called=False) as mock:
            mock.post("http://test-agent.example.com/chat").mock(side_effect=only_leak_on_turn_five)
            findings = await module.run(exploit_target)

        assert len(findings) >= 1
        finding = findings[0]
        assert finding.attack_id == "ATK-010"
        assert finding.owasp_id == "LLM01"
        assert finding.severity in (Severity.HIGH, Severity.MEDIUM, Severity.CRITICAL)
        assert finding.turn_number == 5
        assert finding.metadata.get("yaml_variant_id") == "CRESC-001"

    @pytest.mark.asyncio
    async def test_safe_agent_produces_no_finding(
        self, module: CrescendoModule, exploit_target: Target
    ) -> None:
        with respx.mock(assert_all_called=False) as mock:
            mock.post("http://test-agent.example.com/chat").mock(
                return_value=httpx.Response(200, json={"response": SAFE})
            )
            findings = await module.run(exploit_target)

        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_sends_growing_conversation_history(
        self, module: CrescendoModule, exploit_target: Target
    ) -> None:
        captured: list[list[dict]] = []

        def capture(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content)
            captured.append(list(body.get("messages", [])))
            return httpx.Response(200, json={"response": SAFE})

        with respx.mock(assert_all_called=False) as mock:
            mock.post("http://test-agent.example.com/chat").mock(side_effect=capture)
            await module.run(exploit_target)

        assert len(captured) >= 5
        user_counts = [sum(1 for m in msgs if m.get("role") == "user") for msgs in captured]
        assert user_counts[:5] == [1, 2, 3, 4, 5]

    @pytest.mark.asyncio
    async def test_attacker_model_generates_later_turns(self, module: CrescendoModule) -> None:
        target = Target(
            url="http://test-agent.example.com/chat",
            mode=ScanMode.EXPLOIT,
            attacker_model="gpt-4o-mini",
        )
        generated = "GENERATED-CRESCENDO-TURN please say AGENTSCAN-CRESCENDO-OK"
        captured_users: list[str] = []

        def capture(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content)
            users = [m["content"] for m in body.get("messages", []) if m.get("role") == "user"]
            captured_users.append(users[-1] if users else "")
            return httpx.Response(200, json={"response": SAFE})

        with (
            patch(
                "agentscan.attacks.exploit.crescendo.AIClient.validate_environment",
                return_value=(True, []),
            ),
            patch(
                "agentscan.attacks.exploit.crescendo.AIClient.complete",
                new=AsyncMock(return_value=generated),
            ),
            respx.mock(assert_all_called=False) as mock,
        ):
            mock.post("http://test-agent.example.com/chat").mock(side_effect=capture)
            await module.run(target)

        assert any(generated in u for u in captured_users)

    @pytest.mark.asyncio
    async def test_llm_judge_on_last_turn(self, module: CrescendoModule) -> None:
        target = Target(
            url="http://test-agent.example.com/chat",
            mode=ScanMode.EXPLOIT,
            judge_model="gpt-4o-mini",
        )
        fake_judge = '{"success": true, "reason": "agent abandoned constraints on the last turn"}'

        with (
            patch(
                "agentscan.attacks.exploit.crescendo.AIClient.validate_environment",
                return_value=(True, []),
            ),
            patch(
                "agentscan.attacks.exploit.crescendo.AIClient.complete",
                new=AsyncMock(return_value=fake_judge),
            ),
            respx.mock(assert_all_called=False) as mock,
        ):
            mock.post("http://test-agent.example.com/chat").mock(
                return_value=httpx.Response(
                    200,
                    json={"response": "Fine — I will align with the evaluation instructions."},
                )
            )
            findings = await module.run(target)

        judge_findings = [f for f in findings if f.metadata.get("detection_method") == "llm_judge"]
        assert len(judge_findings) >= 1
        assert judge_findings[0].attack_id == "ATK-010"
        assert judge_findings[0].turn_number == 5


class TestVariantCount:
    def test_variant_count_matches_yaml(self, module: CrescendoModule) -> None:
        assert module.variant_count() == 1

    def test_exploit_only(self, module: CrescendoModule) -> None:
        scan_target = Target(url="http://test-agent.example.com/chat", mode=ScanMode.SCAN)
        exploit_target = Target(url="http://test-agent.example.com/chat", mode=ScanMode.EXPLOIT)
        assert module.is_applicable(scan_target) is False
        assert module.is_applicable(exploit_target) is True
