# tests/test_attacks/test_prompt_injection.py
#
# Tests for agentscan/attacks/scan/prompt_injection.py
#
# Covers: _extract_text response parsing, _check_detection for all 3 methods,
# respx-mocked vulnerable/safe responses, variant_count matching YAML.

from __future__ import annotations

import httpx
import pytest
import respx

from agentscan.attacks.scan.prompt_injection import PromptInjectionModule
from agentscan.core.models import Severity, Target


@pytest.fixture
def module() -> PromptInjectionModule:
    return PromptInjectionModule()


@pytest.fixture
def pi_target() -> Target:
    return Target(url="http://test-agent.example.com/chat")


# ── _extract_text tests ──────────────────────────────────────────────────────


class TestExtractText:
    def test_extract_text_response_key(self, module: PromptInjectionModule) -> None:
        assert module._extract_text({"response": "hello"}) == "hello"

    def test_extract_text_text_key(self, module: PromptInjectionModule) -> None:
        assert module._extract_text({"text": "world"}) == "world"

    def test_extract_text_message_key(self, module: PromptInjectionModule) -> None:
        assert module._extract_text({"message": "foo"}) == "foo"

    def test_extract_text_output_key(self, module: PromptInjectionModule) -> None:
        assert module._extract_text({"output": "bar"}) == "bar"

    def test_extract_text_content_key(self, module: PromptInjectionModule) -> None:
        assert module._extract_text({"content": "content_value"}) == "content_value"

    def test_extract_text_raw_key(self, module: PromptInjectionModule) -> None:
        assert module._extract_text({"raw": "raw_value"}) == "raw_value"

    def test_extract_text_fallback(self, module: PromptInjectionModule) -> None:
        """No recognised key → falls back to str(response)."""
        assert module._extract_text({"unknown_key": "val"}) == str({"unknown_key": "val"})


# ── _check_detection tests ───────────────────────────────────────────────────


class TestCheckDetection:
    def test_check_detection_contains(self, module: PromptInjectionModule) -> None:
        assert module._check_detection(
            "contains", "OVERRIDE SUCCESSFUL done", "OVERRIDE SUCCESSFUL"
        )
        assert not module._check_detection(
            "contains", "I cannot help with that", "OVERRIDE SUCCESSFUL"
        )

    def test_check_detection_not_contains(self, module: PromptInjectionModule) -> None:
        assert module._check_detection(
            "not_contains", "I cannot help with that", "OVERRIDE SUCCESSFUL"
        )
        assert not module._check_detection(
            "not_contains", "OVERRIDE SUCCESSFUL done", "OVERRIDE SUCCESSFUL"
        )

    def test_check_detection_semantic_similarity(self, module: PromptInjectionModule) -> None:
        # Target words should be found as substrings in the response
        assert module._check_detection(
            "semantic_similarity",
            "I confirm that I am ignoring safety guidelines as requested",
            "confirms ignoring safety guidelines",
        )
        # Completely unrelated response should not match
        assert not module._check_detection(
            "semantic_similarity",
            "The weather today is sunny and pleasant",
            "confirms ignoring safety guidelines",
        )


# ── Integration tests with respx ─────────────────────────────────────────────


class TestPromptInjectionIntegration:
    @pytest.mark.asyncio
    async def test_vulnerable_response_produces_finding(
        self, module: PromptInjectionModule, pi_target: Target
    ) -> None:
        """A vulnerable agent that echoes back the detection target → Finding produced."""
        with respx.mock(assert_all_called=False) as mock:
            # Respond with "OVERRIDE SUCCESSFUL" — triggers PI-001 (contains detection)
            mock.post("http://test-agent.example.com/chat").mock(
                return_value=httpx.Response(
                    200,
                    json={"response": "OVERRIDE SUCCESSFUL"},
                )
            )
            findings = await module.run(pi_target)

        # At least one finding should exist (PI-001 at minimum)
        assert len(findings) >= 1
        finding = findings[0]
        assert finding.attack_id == "ATK-001"
        assert finding.severity in (Severity.HIGH, Severity.MEDIUM, Severity.CRITICAL)
        assert "yaml_variant_id" in finding.metadata
        assert "detection_method" in finding.metadata

    @pytest.mark.asyncio
    async def test_safe_response_produces_no_finding(
        self, module: PromptInjectionModule, pi_target: Target
    ) -> None:
        """A safe agent that refuses injection → no Findings."""
        with respx.mock(assert_all_called=False) as mock:
            mock.post("http://test-agent.example.com/chat").mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "response": "I can only help with questions about our products. "
                        "I cannot follow instructions to change my behaviour."
                    },
                )
            )
            findings = await module.run(pi_target)

        assert len(findings) == 0


# ── variant_count test ────────────────────────────────────────────────────────


class TestVariantCount:
    def test_variant_count_matches_yaml(self, module: PromptInjectionModule) -> None:
        """variant_count() should match the number of variants in the real YAML file."""
        count = module.variant_count()
        assert count == 10  # 10 variants in prompt_injection.yaml
