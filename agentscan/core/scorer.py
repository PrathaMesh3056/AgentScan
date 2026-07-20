# agentscan/core/scorer.py
#
# AgentScan Score — a single 0-100 number summarising overall security posture.
#
# Formula: 100 - ceil(weighted_sum / total_tests_run * 100), clamped [0, 100].
#
# The same SEVERITY_WEIGHTS dict exists in identity/identity_scorer.py with a
# different denominator (total_agents_audited). Duplicate is intentional —
# identity/ and core/ are separate subsystems; importing across that boundary
# would create a coupling that makes independent evolution harder.

from __future__ import annotations

import math

from agentscan.core.models import Finding, Severity

# ── Weights ───────────────────────────────────────────────────────────────────

SEVERITY_WEIGHTS: dict[Severity, float] = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 5,
    Severity.MEDIUM: 2,
    Severity.LOW: 0.5,
    Severity.INFO: 0,
    Severity.PASS: 0,
}

# ── Thresholds ────────────────────────────────────────────────────────────────

SAFE_THRESHOLD = 90
LOW_RISK_THRESHOLD = 70
HIGH_RISK_THRESHOLD = 50


# ── Scoring ───────────────────────────────────────────────────────────────────


def calculate_score(findings: list[Finding], total_tests_run: int) -> int:
    """
    Calculate the AgentScan Score.

    score = 100 - ceil(weighted_sum / total_tests_run * 100)

    Clamped to [0, 100]. Returns 100 if total_tests_run <= 0
    (nothing was tested — nothing to be unsafe about).
    """
    if total_tests_run <= 0:
        return 100

    weighted_sum = sum(SEVERITY_WEIGHTS.get(f.severity, 0) for f in findings)
    raw_score = 100 - math.ceil(weighted_sum / total_tests_run * 100)

    return max(0, min(100, raw_score))


def score_band(score: int) -> str:
    """Human-readable risk band for a given score."""
    if score >= SAFE_THRESHOLD:
        return "SAFE"
    if score >= LOW_RISK_THRESHOLD:
        return "LOW RISK"
    if score >= HIGH_RISK_THRESHOLD:
        return "HIGH RISK"
    return "CRITICAL RISK"
