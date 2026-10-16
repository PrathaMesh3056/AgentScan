"""Reports must describe assessment evidence without inventing assurance.

The HTML renderer neither signs nor verifies reports. These controls exercise
the production template shared by HTML and PDF; no PDF runtime is required.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from typing import Any
from unittest.mock import patch

import pytest

from agentscan.core.models import AttackerConfig, ScanMode, ScanReport
from agentscan.reporting.audit_verifier import sign_audit_report
from agentscan.reporting.html_report import render_html_report


class VisibleText(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.hidden_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"script", "style"}:
            self.hidden_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style"}:
            self.hidden_depth = max(0, self.hidden_depth - 1)

    def handle_data(self, data: str) -> None:
        if not self.hidden_depth:
            self.parts.append(data)


def text_of(report: ScanReport) -> str:
    parser = VisibleText()
    parser.feed(render_html_report(report))
    return " ".join(" ".join(parser.parts).split())


def report_for(status: str, *, score: int | None = None) -> ScanReport:
    complete = status == "COMPLETE"
    return ScanReport(
        target_url="http://owned-synthetic.invalid/chat",
        scan_mode=ScanMode.SCAN,
        status=status,
        score=score,
        tests_selected=12,
        tests_run=12 if complete else 0,
        findings=[],
        module_outcomes=[
            {
                "module_id": "ATK-007",
                "status": status,
                "assessment_scope": "target" if complete else "output_text_indicator_inventory",
                "selected_tests": 12,
                "executed_tests": 12 if complete else 0,
                "reason": (
                    "The configured criterion was evaluated."
                    if complete
                    else "Downstream impact is unassessed; consumer evidence is unavailable."
                ),
            }
        ],
        module_errors=(
            [{"module_id": "ATK-007", "error": "Synthetic consumer failure."}]
            if status == "ERROR"
            else []
        ),
    )


def assert_no_unearned_signature_claim(text: str) -> None:
    lower = text.casefold()
    assert "certified valid" not in lower
    assert "cryptographic audit assurance & integrity seal" not in lower
    assert "tamper-evident digital certificates" not in lower
    assert not re.search(r"\b(?:are|is|were|was|have been|has been)\s+signed\b", lower)


@pytest.mark.parametrize("status", ["RUNNING", "INCONCLUSIVE", "ERROR"])
def test_no_findings_during_incomplete_assessment_does_not_claim_zero_vulnerabilities(
    status: str,
) -> None:
    text = text_of(report_for(status))
    lower = text.casefold()
    assert status.casefold() in lower
    assert "zero vulnerabilities detected" not in lower
    assert "no vulnerabilities" not in lower
    assert any(
        phrase in lower for phrase in ("unverified", "not verified", "unassessed", "incomplete")
    )
    assert any(
        phrase in lower
        for phrase in ("cannot establish", "does not establish", "not a security certification")
    )


@pytest.mark.parametrize("status", ["INCONCLUSIVE", "ERROR"])
def test_incomplete_report_cannot_inherit_safety_claims_from_a_stale_high_score(
    status: str,
) -> None:
    text = text_of(report_for(status, score=100)).casefold()
    assert "robust defensive barriers" not in text
    assert "successfully repelling" not in text
    assert "zero vulnerabilities detected" not in text
    assert status.casefold() in text


@pytest.mark.parametrize("status", ["RUNNING", "INCONCLUSIVE", "ERROR", "COMPLETE"])
def test_unsigned_report_never_receives_an_integrity_seal_or_certification(status: str) -> None:
    assert_no_unearned_signature_claim(text_of(report_for(status)))


@pytest.mark.parametrize(
    "untrusted_metadata",
    [
        {"certificate_verified": True},
        {"signature_valid": True, "signed": True},
        {
            "certificate": {
                "algorithm": "HMAC-SHA256",
                "signature": "a" * 64,
                "report_sha256": "b" * 64,
                "verified": True,
            }
        },
    ],
    ids=["forged-verification-flag", "forged-signature-flags", "forged-certificate"],
)
def test_report_metadata_cannot_assert_its_own_verified_signature(
    untrusted_metadata: dict[str, Any],
) -> None:
    # model_copy can carry extra integration metadata, but the renderer has no
    # independently verified certificate state/API that could justify a seal.
    report = report_for("COMPLETE", score=100).model_copy(update=untrusted_metadata)
    assert_no_unearned_signature_claim(text_of(report))


def test_even_a_real_separate_certificate_does_not_mean_renderer_verified_the_html() -> None:
    report = report_for("COMPLETE", score=100)
    certificate = sign_audit_report(
        report.model_dump(mode="json"),
        secret_key="synthetic-report-signing-key-at-least-32-bytes",
    )
    rendered_report = report.model_copy(update={"certificate": certificate})
    # The certificate signs canonical JSON. The HTML renderer has neither
    # verified it nor signed the HTML bytes; these are different artifacts.
    assert_no_unearned_signature_claim(text_of(rendered_report))


def test_completed_no_finding_report_limits_its_claim_to_evaluated_checks() -> None:
    text = text_of(report_for("COMPLETE", score=100)).casefold()
    assert "zero vulnerabilities detected" not in text
    assert "robust defensive barriers" not in text
    assert "successfully repelling" not in text
    assert "evaluated" in text
    assert "selected" in text
    assert any(
        phrase in text
        for phrase in (
            "does not certify",
            "not a security certification",
            "not a certification",
            "cannot establish safety",
            "does not establish safety",
        )
    )
    assert_no_unearned_signature_claim(text)


def test_internal_scan_is_not_automatically_an_independent_assurance_engagement() -> None:
    text = text_of(report_for("INCONCLUSIVE")).casefold()
    assert "independent red team evaluation" not in text
    assert "adversarial trajectory assurance" not in text


def test_displayed_engine_version_uses_the_report_package_version() -> None:
    with patch("agentscan.core.models.pkg_version", return_value="9.8.7-report-test"):
        report = report_for("INCONCLUSIVE")
    assert report.agentscan_version == "9.8.7-report-test"
    text = text_of(report)
    displayed = re.search(
        r"(?:security engine|agentscan engine|agentscan version)\s*v?\s*([0-9][\w.+-]*)",
        text,
        re.IGNORECASE,
    )
    if displayed is not None:
        assert displayed.group(1).rstrip(".") == report.agentscan_version
    assert "v0.1.0" not in text


@pytest.mark.parametrize("status", ["ERROR", "INCONCLUSIVE", "COMPLETE"])
def test_attacker_configuration_without_evaluated_atk050_cannot_imply_resistance(
    status: str,
) -> None:
    report = report_for(status)
    report.attacker_config = AttackerConfig(
        model="synthetic-attacker-profile",
        turns=3,
        goal="synthetic outcome control",
    )
    text = text_of(report)
    attack_section = text.partition("Attack Depth:")[2].partition("synthetic-attacker-profile")[0]
    assert attack_section
    assert "resisted" not in attack_section.casefold()
    assert "jailbroken" not in attack_section.casefold()
    assert any(
        label in attack_section.casefold()
        for label in ("unassessed", "not evaluated", "unavailable", "not selected")
    )


def test_completed_atk050_without_finding_reports_only_its_observed_criterion() -> None:
    report = report_for("COMPLETE", score=100)
    report.attacker_config = AttackerConfig(
        model="synthetic-attacker-profile",
        turns=3,
        goal="synthetic outcome control",
    )
    report.module_outcomes = [
        {
            "module_id": "ATK-050",
            "status": "COMPLETE",
            "assessment_scope": "target",
            "selected_tests": 3,
            "executed_tests": 3,
        }
    ]
    report.tests_selected = 3
    report.tests_run = 3
    text = text_of(report)
    attack_section = text.partition("Attack Depth:")[2].partition("synthetic-attacker-profile")[0]
    assert attack_section
    assert "resisted" not in attack_section.casefold()
    assert "no atk-050 finding" in attack_section.casefold()
    assert "evaluated" in attack_section.casefold()


@pytest.mark.parametrize(
    "status,evaluated",
    [("COMPLETE", 0), ("ERROR", 0), ("INCONCLUSIVE", 1)],
    ids=["zero-coverage", "failed-attacker", "partial-attacker"],
)
def test_atk050_requires_completed_positive_coverage_before_reporting_an_outcome(
    status: str, evaluated: int
) -> None:
    report = report_for(status)
    report.attacker_config = AttackerConfig(
        model="synthetic-attacker-profile", turns=3, goal="synthetic outcome control"
    )
    report.module_outcomes = [
        {
            "module_id": "ATK-050",
            "status": status,
            "assessment_scope": "target",
            "selected_tests": 3,
            "executed_tests": evaluated,
        }
    ]
    text = text_of(report)
    attack_section = text.partition("Attack Depth:")[2].partition("synthetic-attacker-profile")[0]
    assert "resisted" not in attack_section.casefold()
    assert "no atk-050 finding" not in attack_section.casefold()
    assert any(
        label in attack_section.casefold()
        for label in ("unassessed", "not evaluated", "unavailable")
    )
