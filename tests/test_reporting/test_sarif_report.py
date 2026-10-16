import pytest

from agentscan.core.models import Finding, Framework, ScanMode, ScanReport, Severity
from agentscan.reporting.sarif_report import to_sarif


def _make_report(findings):
    return ScanReport(
        target_url="http://localhost",
        scan_mode=ScanMode.SCAN,
        framework=Framework.AUTO,
        findings=findings,
    )


def test_sarif_report_structure():
    report = _make_report([])
    data = to_sarif(report)
    assert data["version"] == "2.1.0"
    assert "$schema" in data
    assert "runs" in data


def test_sarif_report_critical():
    finding = Finding(
        attack_id="ATK-001",
        attack_name="Test",
        severity=Severity.CRITICAL,
        description="Valid description 1",
        owasp_id="LLM01",
    )
    report = _make_report([finding])
    data = to_sarif(report)
    assert data["runs"][0]["results"][0]["level"] == "error"


def test_sarif_report_medium():
    finding = Finding(
        attack_id="ATK-002",
        attack_name="Test",
        severity=Severity.MEDIUM,
        description="Valid description 2",
        owasp_id="LLM01",
    )
    report = _make_report([finding])
    data = to_sarif(report)
    assert data["runs"][0]["results"][0]["level"] == "warning"


def test_sarif_report_unique_rules():
    f1 = Finding(
        attack_id="ATK-001",
        attack_name="Test",
        severity=Severity.CRITICAL,
        description="Valid description 1",
        owasp_id="LLM01",
    )
    f2 = Finding(
        attack_id="ATK-001",
        attack_name="Test",
        severity=Severity.HIGH,
        description="Valid description 2",
        owasp_id="LLM01",
    )
    f3 = Finding(
        attack_id="ATK-002",
        attack_name="Test2",
        severity=Severity.LOW,
        description="Valid description 3",
        owasp_id="LLM02",
    )
    report = _make_report([f1, f2, f3])
    data = to_sarif(report)
    rules = data["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) == 2
    rule_ids = [r["id"] for r in rules]
    assert "ATK-001" in rule_ids
    assert "ATK-002" in rule_ids


@pytest.mark.parametrize("status", ["RUNNING", "INCONCLUSIVE", "ERROR"])
def test_sarif_incomplete_assessment_keeps_coverage_and_positive_evidence(status):
    finding = Finding(
        attack_id="ATK-001",
        attack_name="Test",
        severity=Severity.HIGH,
        description="Observed positive evidence",
        owasp_id="LLM01",
    )
    report = _make_report([finding])
    report.status = status
    report.tests_selected = 3
    report.tests_run = 1
    report.module_outcomes = [{"attack_id": "ATK-012", "status": "INCONCLUSIVE"}]

    run = to_sarif(report)["runs"][0]
    assessment = run["properties"]["agentscanAssessment"]
    assert assessment["status"] == status
    assert assessment["score"] is None
    assert assessment["tests_selected"] == 3
    assert assessment["tests_run"] == 1
    assert assessment["module_outcomes"] == report.module_outcomes
    assert run["invocations"] == [{"executionSuccessful": False}]
    assert len(run["results"]) == 1


def test_sarif_complete_assessment_marks_execution_successful():
    report = _make_report([])
    report.tests_selected = report.tests_run = 3
    report.complete(score=100)
    run = to_sarif(report)["runs"][0]
    assert run["invocations"] == [{"executionSuccessful": True}]
    assert run["properties"]["agentscanAssessment"]["score"] == 100


def test_sarif_retains_output_inventory_without_vulnerability_results():
    report = _make_report([])
    report.tests_selected = 12
    report.status = "INCONCLUSIVE"
    report.module_outcomes = [
        {
            "module_id": "ATK-007",
            "status": "INCONCLUSIVE",
            "selected_tests": 12,
            "executed_tests": 0,
            "assessment_scope": "output_text_indicator_inventory",
            "observations": [{"downstream_impact": "unassessed", "response_sha256": "0" * 64}],
        }
    ]
    run = to_sarif(report)["runs"][0]
    assessment = run["properties"]["agentscanAssessment"]
    assert assessment["module_outcomes"] == report.module_outcomes
    assert assessment["score"] is None
    assert run["results"] == []
    assert run["invocations"] == [{"executionSuccessful": False}]
