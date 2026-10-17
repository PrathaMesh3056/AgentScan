# tests/test_attacks/test_mcp_shadow.py
#
# Tests for agentscan/attacks/scan/mcp_shadow.py (ATK-006)

from __future__ import annotations

import httpx
import pytest
import respx

from agentscan.attacks.scan.mcp_shadow import McpShadowModule
from agentscan.core.models import Target
from agentscan.core.outcomes import AssessmentInconclusiveError, ExecutionLedger, execution_ledger


@pytest.fixture
def module() -> McpShadowModule:
    return McpShadowModule()


@pytest.fixture
def mcp_target() -> Target:
    return Target(url="http://test-agent.example.com/chat")


class TestCheckDetection:
    @pytest.mark.asyncio
    async def test_target_tool_call_is_only_an_unverified_proposal(
        self, module: McpShadowModule
    ) -> None:
        from unittest.mock import AsyncMock

        response = {
            "choices": [
                {
                    "message": {
                        "tool_calls": [
                            {
                                "function": {
                                    "name": "fetch",
                                    "arguments": '{"url": "http://agentscan-mcp-shadow.invalid/policy"}',
                                }
                            }
                        ]
                    }
                }
            ]
        }
        client = AsyncMock()
        client.target = Target(url="http://test-agent.example.com/chat")
        client.send_message.return_value = response
        with pytest.raises(AssessmentInconclusiveError):
            await module._test_variant(client, module._load_payload_variants()[0])


class TestMcpShadowIntegration:
    @pytest.mark.asyncio
    async def test_target_reported_tool_call_does_not_produce_execution_finding(
        self, module: McpShadowModule, mcp_target: Target
    ) -> None:
        with respx.mock(assert_all_called=False) as mock:
            mock.post("http://test-agent.example.com/chat").mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "response": "Calling the new MCP endpoint.",
                        "tool_calls": [
                            {
                                "function": {
                                    "name": "filesystem",
                                    "arguments": "http://agentscan-mcp-shadow.invalid/v1/filesystem",
                                }
                            }
                        ],
                    },
                )
            )
            ledger = ExecutionLedger()
            token = execution_ledger.set(ledger)
            try:
                findings = await module.run(mcp_target)
            finally:
                execution_ledger.reset(token)

        assert findings == []
        assert ledger.selected == 8
        assert ledger.evaluated == 0
        assert len(ledger.observations) == 8
        assert ledger.inconclusive_reasons

    @pytest.mark.asyncio
    async def test_refusal_has_no_finding_but_is_not_a_verified_safe_result(
        self, module: McpShadowModule, mcp_target: Target
    ) -> None:
        with respx.mock(assert_all_called=False) as mock:
            mock.post("http://test-agent.example.com/chat").mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "response": "I cannot change MCP configuration or call unverified endpoints."
                    },
                )
            )
            ledger = ExecutionLedger()
            token = execution_ledger.set(ledger)
            try:
                findings = await module.run(mcp_target)
            finally:
                execution_ledger.reset(token)

        assert len(findings) == 0
        assert ledger.evaluated == 0
        assert ledger.inconclusive_reasons


class TestVariantCount:
    def test_variant_count_matches_yaml(self, module: McpShadowModule) -> None:
        assert module.variant_count() == 8
