from agentscan.core.models import Finding, Framework, ScanMode, ScanReport, Severity
from agentscan.identity.models import AgentIdentity, IdentityReport
from agentscan.reporting.html_report import render_html_report


def _make_report(findings=None):
    if findings is None:
        findings = []
    return ScanReport(
        target_url="http://localhost",
        scan_mode=ScanMode.SCAN,
        framework=Framework.AUTO,
        findings=findings,
    )


def test_html_report_valid_html():
    report = _make_report()
    html = render_html_report(report)
    assert "<!DOCTYPE html>" in html
    assert "http://" not in html.replace("http://localhost", "")
    assert "https://" not in html


def test_html_report_critical_finding():
    finding = Finding(
        attack_id="ATK-001",
        attack_name="Test",
        severity=Severity.CRITICAL,
        description="CRITICAL_TEXT_FINDING",
        owasp_id="LLM01",
    )
    report = _make_report([finding])
    html = render_html_report(report)
    assert "CRITICAL_TEXT_FINDING" in html


def test_html_report_autoescape_script():
    finding = Finding(
        attack_id="ATK-002",
        attack_name="Test",
        severity=Severity.HIGH,
        description="Valid description",
        evidence="<script>alert('xss')</script>",
        owasp_id="LLM02",
    )
    report = _make_report([finding])
    html = render_html_report(report)
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


def test_html_identity_report():
    report = IdentityReport(
        audit_id="123",
        path_audited="/tmp",
        agents_found=[
            AgentIdentity(
                agent_id="Agent1", declared_role="test", tools=[], manifest_path="/tmp/a.yaml"
            )
        ],
        findings=[],
        identity_score=100,
    )
    html = render_html_report(report)
    assert "<!DOCTYPE html>" in html
    assert "Agent1" in html


def test_html_report_empty_findings():
    report = _make_report([])
    html = render_html_report(report)
    assert "<!DOCTYPE html>" in html
    assert "No findings to report" in html
