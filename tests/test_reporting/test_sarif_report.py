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
