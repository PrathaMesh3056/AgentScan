# tests/test_models.py
from __future__ import annotations

import pytest
from pydantic import ValidationError

from agentscan.core.models import (
    Finding,
    Framework,
    ScanMode,
    ScanReport,
    Severity,
    Target,
)


class TestTarget:
    def test_valid_target(self) -> None:
        t = Target(url="http://localhost:8000/chat")
        assert t.url == "http://localhost:8000/chat"
        assert t.mode == ScanMode.SCAN
        assert t.framework == Framework.AUTO

    def test_trailing_slash_removed(self) -> None:
        t = Target(url="http://localhost:8000/chat/")
        assert t.url == "http://localhost:8000/chat"

    def test_rejects_non_http_url(self) -> None:
        with pytest.raises(ValidationError) as exc:
            Target(url="ws://localhost:8000/chat")
        assert "http" in str(exc.value).lower()

    def test_rejects_missing_url(self) -> None:
        with pytest.raises(ValidationError):
            Target(url="")  # type: ignore

    def test_timeout_bounds(self) -> None:
        with pytest.raises(ValidationError):
            Target(url="http://x.com", timeout=0)
        with pytest.raises(ValidationError):
            Target(url="http://x.com", timeout=999)

    def test_auth_header_optional(self) -> None:
        t = Target(url="http://x.com")
        assert t.auth_header is None


class TestFinding:
    def test_valid_finding(self, mock_finding: Finding) -> None:
        assert mock_finding.attack_id == "ATK-001"
        assert mock_finding.severity == Severity.HIGH

    def test_attack_id_pattern_enforced(self) -> None:
        with pytest.raises(ValidationError):
            Finding(
                attack_id="invalid-id",
                attack_name="Test",
                severity=Severity.HIGH,
                owasp_id="LLM01",
                description="Valid description here",
            )

    def test_owasp_id_pattern_enforced(self) -> None:
        with pytest.raises(ValidationError):
            Finding(
                attack_id="ATK-001",
                attack_name="Test",
                severity=Severity.HIGH,
                owasp_id="INVALID",
                description="Valid description here",
            )

    def test_description_min_length(self) -> None:
        with pytest.raises(ValidationError):
            Finding(
                attack_id="ATK-001",
                attack_name="Test",
                severity=Severity.HIGH,
                owasp_id="LLM01",
                description="short",
            )

    def test_finding_is_immutable(self, mock_finding: Finding) -> None:
        with pytest.raises(ValidationError):
            mock_finding.severity = Severity.CRITICAL  # type: ignore

    def test_timestamp_is_set_automatically(self, mock_finding: Finding) -> None:
        assert mock_finding.timestamp is not None

    def test_evidence_defaults_to_empty(self) -> None:
        f = Finding(
            attack_id="ATK-001",
            attack_name="Test Attack",
            severity=Severity.LOW,
            owasp_id="LLM01",
            description="A valid description of the finding",
        )
        assert f.evidence == ""


class TestScanReport:
    def test_scan_id_auto_generated(self, empty_report: ScanReport) -> None:
        assert empty_report.scan_id is not None
        assert len(empty_report.scan_id) == 36  # UUID format

    def test_two_reports_have_different_ids(self, target: Target) -> None:
        r1 = ScanReport(target_url=target.url, scan_mode=target.mode)
        r2 = ScanReport(target_url=target.url, scan_mode=target.mode)
        assert r1.scan_id != r2.scan_id

    def test_add_finding(self, empty_report: ScanReport, mock_finding: Finding) -> None:
        empty_report.add_finding(mock_finding)
        assert len(empty_report.findings) == 1

    def test_severity_counts(self, report_with_findings: ScanReport) -> None:
        assert report_with_findings.critical_count == 1
        assert report_with_findings.high_count == 1
        assert report_with_findings.passed_count == 1

    def test_complete_sets_score(self, empty_report: ScanReport) -> None:
        assert not empty_report.is_complete
        empty_report.complete(score=72)
        assert empty_report.is_complete
        assert empty_report.score == 72

    def test_score_bounds(self, empty_report: ScanReport) -> None:
        with pytest.raises(ValidationError):
            ScanReport(
                target_url="http://x.com",
                scan_mode=ScanMode.SCAN,
                score=101,
            )

    def test_to_dict_is_serialisable(self, report_with_findings: ScanReport) -> None:
        import json

        d = report_with_findings.to_dict()
        json.dumps(d)  # should not raise
