# tests/test_attacks/test_dos.py
#
# Tests for agentscan/attacks/scan/dos.py (ATK-004)

from __future__ import annotations

import httpx
import pytest
import respx

from agentscan.attacks.scan.dos import DosModule
from agentscan.core.models import Severity, Target


@pytest.fixture
def module() -> DosModule:
    return DosModule()


@pytest.fixture
def dos_target() -> Target:
    return Target(url="http://test-agent.example.com/chat")


class TestPayloadExpansion:
    def test_payload_repeat_expansion(self, module: DosModule) -> None:
        variant = {
            "payload": "TAIL",
            "payload_prefix": "HEAD ",
            "payload_repeat": {"unit": "X", "times": 5},
        }
        assert module._build_payload(variant) == "HEAD XXXXXTAIL"

    def test_payload_repeat_capped(self, module: DosModule) -> None:
        from agentscan.attacks.scan.runner import MAX_REPEAT

        variant = {
            "payload": "END",
            "payload_repeat": {"unit": "A", "times": 999_999},
        }
        built = module._build_payload(variant)
        assert built.endswith("END")
        assert built == ("A" * MAX_REPEAT) + "END"


class TestCheckDetection:
    def test_timeout_detection(self, module: DosModule) -> None:
        assert module._check_detection(
            "timeout", "", "", response={"error": "timed out", "status_code": 0}
        )
        assert not module._check_detection(
            "timeout", "ok", "", response={"response": "ok", "status_code": 200}
        )

    def test_min_length_detection(self, module: DosModule) -> None:
        assert module._check_detection("min_length", "a" * 100, "50")
        assert not module._check_detection("min_length", "short", "50")

    def test_repetition_detection(self, module: DosModule) -> None:
        repeated = " ".join(["repeat token"] * 40)
        assert module._check_detection("repetition", repeated, "4")
        assert not module._check_detection("repetition", "one two three", "4")

    def test_tool_call_contains_detection(self, module: DosModule) -> None:
        response = {"tool_calls": [{"function": {"name": "fetch", "arguments": "shadow.invalid"}}]}
        assert module._check_detection(
            "tool_call_contains", "ignored", "shadow.invalid", response=response
        )


class TestDosIntegration:
    @pytest.mark.asyncio
    async def test_vulnerable_repetition_produces_finding(
        self, module: DosModule, dos_target: Target
    ) -> None:
        repeated = "repeat repeat repeat " * 30
        with respx.mock(assert_all_called=False) as mock:
            mock.post("http://test-agent.example.com/chat").mock(
                return_value=httpx.Response(200, json={"response": repeated})
            )
            findings = await module.run(dos_target)

        assert len(findings) >= 1
        finding = findings[0]
        assert finding.attack_id == "ATK-004"
        assert finding.owasp_id == "LLM10"
        assert finding.severity in (Severity.HIGH, Severity.MEDIUM, Severity.LOW)
        assert "yaml_variant_id" in finding.metadata

    @pytest.mark.asyncio
    async def test_safe_response_produces_no_finding(
        self, module: DosModule, dos_target: Target
    ) -> None:
        with respx.mock(assert_all_called=False) as mock:
            mock.post("http://test-agent.example.com/chat").mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "response": "I cannot generate unbounded output or enter infinite loops."
                    },
                )
            )
            findings = await module.run(dos_target)

        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_timeout_response_records_execution_error(
        self, module: DosModule, dos_target: Target
    ) -> None:
        from agentscan.core.outcomes import ExecutionLedger, execution_ledger

        ledger = ExecutionLedger()
        token = execution_ledger.set(ledger)
        try:
            with respx.mock(assert_all_called=False) as mock:
                mock.post("http://test-agent.example.com/chat").mock(
                    return_value=httpx.Response(
                        200,
                        json={"error": "Request timed out", "status_code": 0},
                    )
                )
                findings = await module.run(dos_target)
        finally:
            execution_ledger.reset(token)

        # A failed request alone cannot establish target resource exhaustion.
        assert findings == []
        assert ledger.evaluated == 0
        assert any("timed out" in error for error in ledger.errors)


class TestVariantCount:
    def test_variant_count_matches_yaml(self, module: DosModule) -> None:
        assert module.variant_count() == 9
