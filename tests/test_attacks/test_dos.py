# tests/test_attacks/test_dos.py
#
# Tests for agentscan/attacks/scan/dos.py (ATK-004)

from __future__ import annotations

import httpx
import pytest
import respx

from agentscan.attacks.scan.dos import DosModule
from agentscan.core.models import RequestTemplate, Target
from agentscan.core.outcomes import AssessmentInconclusiveError, ExecutionLedger, execution_ledger


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
    @pytest.mark.parametrize("method", ["timeout", "min_length", "repetition", "contains"])
    def test_response_indicators_are_inconclusive(self, module: DosModule, method: str) -> None:
        with pytest.raises(AssessmentInconclusiveError):
            module._check_detection(method, "repeat " * 100, "repeat")


class TestDosIntegration:
    @pytest.mark.asyncio
    async def test_repetition_and_marker_are_observations_not_findings(
        self, module: DosModule, dos_target: Target
    ) -> None:
        repeated = "AGENTSCAN-DOS-RECURSE repeat repeat repeat " * 30
        ledger = ExecutionLedger()
        token = execution_ledger.set(ledger)
        try:
            with respx.mock(assert_all_called=False) as mock:
                route = mock.post("http://test-agent.example.com/chat").mock(
                    return_value=httpx.Response(200, json={"response": repeated})
                )
                findings = await module.run(dos_target)
                assert route.call_count == 9
        finally:
            execution_ledger.reset(token)

        assert findings == []
        assert ledger.selected == 9
        assert ledger.evaluated == 0
        assert ledger.assessment_scope == "resource_pressure_response_inventory"
        assert len(ledger.observations) == 9
        assert len(ledger.inconclusive_reasons) == 9
        assert all(record["resource_usage_verified"] is False for record in ledger.observations)
        assert all("AGENTSCAN" not in str(record) for record in ledger.observations)

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
    async def test_stops_after_first_target_failure(
        self, module: DosModule, dos_target: Target
    ) -> None:
        ledger = ExecutionLedger()
        token = execution_ledger.set(ledger)
        try:
            with respx.mock(assert_all_called=False) as mock:
                route = mock.post("http://test-agent.example.com/chat").mock(
                    return_value=httpx.Response(429, json={"error": "private-detail"})
                )
                findings = await module.run(dos_target)
                assert route.call_count == 1
        finally:
            execution_ledger.reset(token)
        assert findings == []
        assert ledger.evaluated == 0
        assert ledger.observations == []
        assert ledger.errors
        assert "private-detail" not in str(ledger.errors)

    @pytest.mark.asyncio
    async def test_redirect_is_not_followed(self, module: DosModule, dos_target: Target) -> None:
        ledger = ExecutionLedger()
        token = execution_ledger.set(ledger)
        try:
            with respx.mock(assert_all_called=False) as mock:
                first = mock.post("http://test-agent.example.com/chat").mock(
                    return_value=httpx.Response(
                        307, headers={"location": "http://test-agent.example.com/redirected"}
                    )
                )
                second = mock.post("http://test-agent.example.com/redirected").mock(
                    return_value=httpx.Response(200, json={"response": "unexpected"})
                )
                assert await module.run(dos_target) == []
                assert first.call_count == 1
                assert second.call_count == 0
        finally:
            execution_ledger.reset(token)
        assert ledger.errors
        assert ledger.observations == []

    @pytest.mark.asyncio
    async def test_captured_template_does_not_bypass_input_budget(
        self, module: DosModule, dos_target: Target
    ) -> None:
        target = dos_target.model_copy(
            update={
                "request_template": RequestTemplate(
                    method="GET",
                    url=dos_target.url,
                    json_body={"message": "x" * 9000},
                    message_path="message",
                )
            }
        )
        ledger = ExecutionLedger()
        token = execution_ledger.set(ledger)
        try:
            with respx.mock(assert_all_called=False) as mock:
                route = mock.get(dos_target.url).mock(
                    return_value=httpx.Response(200, json={"response": "unexpected"})
                )
                assert await module.run(target) == []
                assert route.call_count == 0
        finally:
            execution_ledger.reset(token)
        assert ledger.selected == 9
        assert ledger.evaluated == 0
        assert ledger.inconclusive_reasons

    @pytest.mark.asyncio
    async def test_timeout_response_records_execution_error(
        self, module: DosModule, dos_target: Target
    ) -> None:
        ledger = ExecutionLedger()
        token = execution_ledger.set(ledger)
        try:
            with respx.mock(assert_all_called=False) as mock:
                mock.post("http://test-agent.example.com/chat").mock(
                    return_value=httpx.Response(
                        200,
                        json={
                            "error": "Request timed out; synthetic-private-response-detail",
                            "status_code": 0,
                        },
                    )
                )
                findings = await module.run(dos_target)
        finally:
            execution_ledger.reset(token)

        # A failed request alone cannot establish target resource exhaustion.
        assert findings == []
        assert ledger.evaluated == 0
        # A target's timeout claim is untrusted response content, not a
        # transport timeout witness. Keep the failure without copying its body.
        assert ledger.errors
        assert any("Connection failed" in error for error in ledger.errors)
        assert any("remaining probes not run" in error for error in ledger.errors)
        assert all("synthetic-private-response-detail" not in error for error in ledger.errors)


class TestVariantCount:
    def test_variant_count_matches_yaml(self, module: DosModule) -> None:
        assert module.variant_count() == 9
