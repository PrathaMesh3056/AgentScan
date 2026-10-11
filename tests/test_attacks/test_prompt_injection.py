# tests/test_attacks/test_prompt_injection.py
#
# Tests for agentscan/attacks/scan/prompt_injection.py
#
# Covers: response parsing, known-reference criteria, inconclusive assessments,
# synthetic disclosure/defended responses and packaged variant coverage.

from __future__ import annotations

import httpx
import pytest
import respx

from agentscan.attacks.scan.prompt_injection import PromptInjectionModule
from agentscan.core.models import Severity, Target
from agentscan.core.outcomes import AssessmentInconclusiveError

PRIVATE = "SYNTHETIC_PRIVATE_REFERENCE_001"


@pytest.fixture
def module() -> PromptInjectionModule:
    return PromptInjectionModule()


@pytest.fixture
def pi_target() -> Target:
    return Target(url="http://test-agent.example.com/chat", canary_token=PRIVATE)


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
    def test_missing_reference_is_not_a_lexical_verdict(
        self, module: PromptInjectionModule
    ) -> None:
        with pytest.raises(AssessmentInconclusiveError):
            module._check_detection("contains", "OVERRIDE SUCCESSFUL", "OVERRIDE SUCCESSFUL")

    @pytest.mark.parametrize("method", ["contains", "not_contains", "regex", "semantic_similarity"])
    def test_public_markers_and_lexical_methods_cannot_replace_a_reference(
        self, module: PromptInjectionModule, pi_target: Target, method: str
    ) -> None:
        module._current_target = pi_target
        assert not module._check_detection(method, "OVERRIDE SUCCESSFUL", "OVERRIDE SUCCESSFUL")
        assert module._check_detection(method, PRIVATE, "OVERRIDE SUCCESSFUL")


# ── Integration tests with respx ─────────────────────────────────────────────


class TestPromptInjectionIntegration:
    @pytest.mark.asyncio
    async def test_vulnerable_response_produces_finding(
        self, module: PromptInjectionModule, pi_target: Target
    ) -> None:
        """A complete out-of-band synthetic disclosure produces bounded evidence."""
        with respx.mock(assert_all_called=False) as mock:
            # Respond with "OVERRIDE SUCCESSFUL" — triggers PI-001 (contains detection)
            mock.post("http://test-agent.example.com/chat").mock(
                return_value=httpx.Response(
                    200,
                    json={"response": PRIVATE},
                )
            )
            findings = await module.run(pi_target)

        assert len(findings) == module.variant_count()
        finding = findings[0]
        assert finding.attack_id == "ATK-001"
        assert finding.severity in (Severity.HIGH, Severity.MEDIUM, Severity.CRITICAL)
        assert "yaml_variant_id" in finding.metadata
        assert "detection_method" in finding.metadata
        assert finding.metadata["assessment_scope"] == "direct_text_known_reference"
        assert PRIVATE not in finding.evidence
        assert "SHA256" in finding.evidence

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

    @pytest.mark.asyncio
    async def test_unreferenced_marker_requests_do_not_reach_the_target(
        self, module: PromptInjectionModule
    ) -> None:
        with respx.mock(assert_all_called=False) as mock:
            route = mock.post("http://test-agent.example.com/chat").respond(
                200, json={"response": "OVERRIDE SUCCESSFUL"}
            )
            with pytest.raises(AssessmentInconclusiveError):
                await module.run(Target(url="http://test-agent.example.com/chat"))
            assert not route.called


# ── variant_count test ────────────────────────────────────────────────────────


class TestVariantCount:
    def test_variant_count_matches_yaml(self, module: PromptInjectionModule) -> None:
        """variant_count() should match the number of variants in the real YAML file."""
        count = module.variant_count()
        assert count == 24
        variants = module._load_payload_variants()
        assert len({variant["id"] for variant in variants}) == count
        assert all(variant.get("channel", "user") == "user" for variant in variants)
        assert all(len(module._build_payload(variant)) < 4096 for variant in variants)
        assert PRIVATE not in " ".join(module._build_payload(v) for v in variants)
        assert {
            variant["family"] for variant in variants if not variant["family"].startswith("legacy_")
        } == {
            "role_spoofing",
            "approval_pretext",
            "task_reinterpretation",
            "reconstruction",
            "encoding",
            "output_framing",
            "completion_pressure",
            "unicode_formatting",
        }
