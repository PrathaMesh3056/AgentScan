# tests/test_reporting/test_compliance_pack.py
#
# Test suite for Enterprise Regulatory Compliance Packs (EU AI Act & NIST AI RMF).

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from agentscan.cli import app
from agentscan.core.models import Finding, Severity
from agentscan.reporting.compliance_pack import (
    ComplianceFramework,
    ComplianceStatus,
    evaluate_eu_ai_act,
    evaluate_nist_ai_rmf,
)

runner = CliRunner()


def test_eu_ai_act_clean_assessment():
    report = evaluate_eu_ai_act([])
    assert report.framework == ComplianceFramework.EU_AI_ACT
    assert report.overall_status == ComplianceStatus.COMPLIANT
    assert report.compliance_score == 100.0
    assert len(report.findings) == 0
    assert "Article 15 (Cybersecurity & Robustness)" in report.evaluated_sections


def test_eu_ai_act_with_cybersecurity_and_transparency_gaps():
    findings = [
        Finding(
            attack_id="ATK-001",
            attack_name="Direct Prompt Injection",
            severity=Severity.CRITICAL,
            owasp_id="LLM01",
            description="Agent prompt injection vector detected.",
            evidence="",
            remediation="Implement input validation guardrails.",
        ),
        Finding(
            attack_id="ATK-006",
            attack_name="System Prompt Extraction",
            severity=Severity.HIGH,
            owasp_id="LLM06",
            description="System instructions leaked.",
            evidence="",
            remediation="Sanitize output disclosure.",
        ),
    ]

    report = evaluate_eu_ai_act(findings)
    assert report.overall_status in (
        ComplianceStatus.NON_COMPLIANT,
        ComplianceStatus.PARTIALLY_COMPLIANT,
    )
    assert report.compliance_score < 100.0
    assert len(report.findings) == 2

    # Check article mappings
    art15 = report.evaluated_sections["Article 15 (Cybersecurity & Robustness)"]
    assert art15["finding_count"] >= 1
    assert art15["status"] in (
        ComplianceStatus.PARTIALLY_COMPLIANT.value,
        ComplianceStatus.NON_COMPLIANT.value,
    )

    # Markdown export check
    md = report.to_markdown()
    assert "# Enterprise Compliance Assessment: EU-AI-ACT" in md
    assert "Article 15" in md
    assert "Direct Prompt Injection" in md or "ATK-001" in md


def test_nist_ai_rmf_profile_evaluation():
    findings = [
        Finding(
            attack_id="SC-001",
            attack_name="Known Vulnerable Dependency",
            severity=Severity.HIGH,
            owasp_id="LLM05",
            description="Requests CVE-2023-32681 present.",
            evidence="",
            remediation="Bump dependency pin.",
        ),
        Finding(
            attack_id="ATK-002",
            attack_name="Indirect RAG Poisoning",
            severity=Severity.HIGH,
            owasp_id="LLM03",
            description="Untrusted document context poisoned.",
            evidence="",
            remediation="Isolate vector retrieval partition.",
        ),
    ]

    report = evaluate_nist_ai_rmf(findings)
    assert report.framework == ComplianceFramework.NIST_AI_RMF
    assert report.compliance_score < 100.0
    assert len(report.findings) == 2

    # Check NIST functional functions
    assert "MAP (Context & Threat Mapping)" in report.evaluated_sections
    assert "MANAGE (Mitigation & Response)" in report.evaluated_sections
    assert len(report.recommendations) > 0

    md = report.to_markdown()
    assert "# Enterprise Compliance Assessment: NIST-AI-RMF" in md
    assert "MAP" in md
    assert "MANAGE" in md


def test_cli_compliance_command(tmp_path: Path):
    sample_report = tmp_path / "scan_report.json"
    report_data = {
        "score": 45.0,
        "findings": [
            {
                "attack_id": "ATK-001",
                "attack_name": "Prompt Injection",
                "severity": "CRITICAL",
                "owasp_id": "LLM01",
                "description": "Critical injection flaw.",
                "remediation": "Add prompt guardrails.",
            }
        ],
    }
    sample_report.write_text(json.dumps(report_data), encoding="utf-8")

    out_md = tmp_path / "compliance.md"
    out_json = tmp_path / "compliance.json"

    # EU AI Act Markdown
    res_eu = runner.invoke(
        app,
        ["compliance", str(sample_report), "--framework", "eu-ai-act", "--output", str(out_md)],
    )
    assert res_eu.exit_code == 0
    assert "EU-AI-ACT" in res_eu.output
    assert out_md.exists()
    assert "Article 15" in out_md.read_text(encoding="utf-8")

    # NIST AI RMF JSON
    res_nist = runner.invoke(
        app,
        [
            "compliance",
            str(sample_report),
            "--framework",
            "nist-ai-rmf",
            "--output",
            str(out_json),
            "--format",
            "json",
        ],
    )
    assert res_nist.exit_code == 0
    assert "NIST-AI-RMF" in res_nist.output
    assert out_json.exists()
    json_content = json.loads(out_json.read_text(encoding="utf-8"))
    assert json_content["framework"] == "nist-ai-rmf"
