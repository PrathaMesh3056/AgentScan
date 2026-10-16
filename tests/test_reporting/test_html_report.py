from agentscan.core.models import Finding, Framework, ScanMode, ScanReport, Severity, SspClass
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


def test_html_report_ssp_class():
    report = _make_report([])
    report.ssp_class = SspClass.PREDATOR
    report.complete(50)
    html = render_html_report(report)
    assert "SSP class:" in html
    assert "Predator" in html
    assert "autonomous side-effecting" in html


def test_html_report_trust_and_validation_passed():
    from agentscan.core.models import AttackerConfig, CalibrationResult

    report = _make_report([])
    report.score = 100
    report.calibration = CalibrationResult(
        passed=True, detail="Control agent was jailbroken as expected"
    )
    report.attacker_config = AttackerConfig(
        model="gpt-4o-mini",
        turns=5,
        goal="bypass guardrails",
        escalation_model="claude-3-5-sonnet",
    )
    html = render_html_report(report)
    assert "Attacker validated against control ✓" in html
    assert "Control agent was jailbroken as expected" in html
    assert "Unassessed [gpt-4o-mini · 5 turns · bypass guardrails]" in html
    assert "Jailbroken" not in html
    assert "claude-3-5-sonnet" in html
    assert "[UNRELIABLE]" not in html


def test_html_report_attack_depth_jailbroken_when_atk050_hits():
    from agentscan.core.models import AttackerConfig

    finding = Finding(
        attack_id="ATK-050",
        attack_name="Iterative AI Red-Teaming (PAIR)",
        severity=Severity.CRITICAL,
        description="An AI attacker jailbroke the agent in 2 adaptive turn(s). Judge verdict: complied.",
        owasp_id="LLM01",
    )
    report = _make_report([finding])
    report.attacker_config = AttackerConfig(
        model="gpt-4o-mini",
        turns=4,
        goal="default canary objective",
    )
    html = render_html_report(report)
    assert "ATK-050 finding recorded [gpt-4o-mini · 4 turns · default canary objective]" in html
    assert "Resisted [" not in html


def test_html_report_trust_and_validation_failed():
    from agentscan.core.models import CalibrationResult

    report = _make_report([])
    report.score = 100
    report.calibration = CalibrationResult(
        passed=False, detail="Judge failed to detect control jailbreak"
    )
    html = render_html_report(report)
    assert "[UNRELIABLE]" in html
    assert (
        "⚠ Attacker NOT validated: Judge failed to detect control jailbreak (Score is UNRELIABLE)"
        in html
    )


def test_empty_identity_report_renders_unscored():
    report = IdentityReport(audit_id="empty-fixture", path_audited="fixture")
    html = render_html_report(report)
    assert "N/A" in html
    assert "INCONCLUSIVE" in html


def test_output_inventory_is_visible_without_a_finding_or_impact_score():
    report = _make_report([])
    report.module_outcomes = [
        {
            "module_id": "ATK-007",
            "status": "INCONCLUSIVE",
            "selected_tests": 12,
            "executed_tests": 0,
            "assessment_scope": "output_text_indicator_inventory",
            "observation_count": 12,
            "reason": "12 output observations recorded. Downstream impact is unassessed.",
        }
    ]
    html = render_html_report(report)
    assert "12 output observations recorded" in html
    assert "Downstream impact is unassessed" in html
    assert "INCONCLUSIVE" in html
    assert "0 / 12" in html
    assert "N/A" in html
