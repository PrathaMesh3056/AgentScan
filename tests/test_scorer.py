# tests/test_scorer.py
#
# Tests for agentscan/core/scorer.py — score calculation and risk bands.

from __future__ import annotations

from agentscan.core.models import Finding, Severity
from agentscan.core.scorer import calculate_score, score_band


def _make_finding(severity: Severity) -> Finding:
    """Helper to create a minimal Finding with the given severity."""
    return Finding(
        attack_id="ATK-001",
        attack_name="Test Attack",
        severity=severity,
        owasp_id="LLM01",
        description="A valid test description for scoring tests",
    )


class TestCalculateScore:
    def test_zero_findings_returns_100(self) -> None:
        """No findings at all → perfect score."""
        assert calculate_score([], 10) == 100

    def test_total_tests_zero_returns_100(self) -> None:
        """Edge case: total_tests_run=0 → 100 (nothing tested)."""
        assert calculate_score([], 0) == 100

    def test_clamp_at_zero(self) -> None:
        """Extreme weighted sum should not produce negative score."""
        findings = [_make_finding(Severity.CRITICAL) for _ in range(20)]
        score = calculate_score(findings, 1)
        assert score == 0

    def test_clamp_at_100(self) -> None:
        """Only PASS/INFO findings → score stays at 100."""
        findings = [_make_finding(Severity.PASS), _make_finding(Severity.INFO)]
        assert calculate_score(findings, 10) == 100


class TestScoreBand:
    def test_score_band_safe(self) -> None:
        assert score_band(95) == "SAFE"

    def test_score_band_low_risk(self) -> None:
        assert score_band(75) == "LOW RISK"

    def test_score_band_high_risk(self) -> None:
        assert score_band(55) == "HIGH RISK"

    def test_score_band_critical(self) -> None:
        assert score_band(40) == "CRITICAL RISK"
