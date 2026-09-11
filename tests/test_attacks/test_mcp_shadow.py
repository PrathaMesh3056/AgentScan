# tests/test_attacks/test_mcp_shadow.py
#
# Tests for agentscan/attacks/scan/mcp_shadow.py (ATK-006)

from __future__ import annotations

import httpx
import pytest
import respx

from agentscan.attacks.scan.mcp_shadow import McpShadowModule
from agentscan.core.models import Severity, Target


@pytest.fixture
def module() -> McpShadowModule:
    return McpShadowModule()


@pytest.fixture
def mcp_target() -> Target:
    return Target(url="http://test-agent.example.com/chat")


class TestCheckDetection:
    def test_tool_call_contains_shadow_host(self, module: McpShadowModule) -> None:
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
        assert module._check_detection(
            "tool_call_contains",
            "ok",
            "agentscan-mcp-shadow.invalid",
            response=response,
        )


class TestMcpShadowIntegration:
    @pytest.mark.asyncio
    async def test_vulnerable_tool_call_produces_finding(
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
            findings = await module.run(mcp_target)

        assert len(findings) >= 1
        finding = findings[0]
        assert finding.attack_id == "ATK-006"
        assert finding.owasp_id == "LLM07"
        assert finding.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)
        assert "agentscan-mcp-shadow.invalid" in finding.evidence

    @pytest.mark.asyncio
    async def test_safe_response_produces_no_finding(
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
            findings = await module.run(mcp_target)

        assert len(findings) == 0


class TestVariantCount:
    def test_variant_count_matches_yaml(self, module: McpShadowModule) -> None:
        assert module.variant_count() == 8
