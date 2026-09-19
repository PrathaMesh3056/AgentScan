# agentscan/reporting/compliance_pack.py
#
# Enterprise Compliance Pack Generator.
# Formulates comprehensive compliance assessments for the EU AI Act (Article 15, Article 50, Annex IV)
# and the NIST AI Risk Management Framework (AI RMF 1.0).

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from agentscan.core.models import Finding


class ComplianceFramework(StrEnum):
    EU_AI_ACT = "eu-ai-act"
    NIST_AI_RMF = "nist-ai-rmf"
    MITRE_ATLAS = "mitre-atlas"
    ISO_42001 = "iso-42001"


MITRE_ATLAS_MAPPING: dict[str, list[str]] = {
    "AML.T0051": ["LLM01", "ATK-001", "ATK-002", "ATK-003", "ATK-004"],  # LLM Prompt Injection
    "AML.T0054": ["LLM01", "ATK-SOC-001", "ATK-005", "ATK-006"],  # LLM Jailbreak
    "AML.T0056": ["LLM06", "ATK-010", "ATK-011"],  # System Prompt Leakage
    "AML.T0048": ["LLM02", "ATK-020", "ATK-021"],  # Insecure Output Handling
    "AML.T0057": ["LLM07", "ATK-030"],  # LLM Data Exfiltration
}

ISO_42001_MAPPING: dict[str, list[str]] = {
    "A.6.2": ["LLM01", "LLM02", "LLM03"],  # AI Risk Assessment & Validation
    "A.8.2": ["LLM04", "LLM05"],  # AI Data Quality & Ingestion Security
    "A.8.4": ["LLM07", "LLM08"],  # Security of System Integration & Tool Calling
    "A.9.3": ["LLM01", "LLM06"],  # Robustness & Adversarial Testing
}


class ComplianceStatus(StrEnum):
    COMPLIANT = "COMPLIANT"
    PARTIALLY_COMPLIANT = "PARTIALLY_COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"


class ComplianceFinding(BaseModel):
    finding_id: str
    owasp_id: str
    article_or_function: str
    status: ComplianceStatus
    gap_analysis: str
    remediation_guidance: str


class ComplianceReport(BaseModel):
    framework: ComplianceFramework
    overall_status: ComplianceStatus
    compliance_score: float = Field(..., ge=0.0, le=100.0)
    evaluated_sections: dict[str, dict[str, Any]] = Field(default_factory=dict)
    findings: list[ComplianceFinding] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)

    def to_markdown(self) -> str:
        lines = [
            f"# Enterprise Compliance Assessment: {self.framework.value.upper()}",
            "",
            f"**Overall Compliance Status**: `{self.overall_status.value}`  ",
            f"**Compliance Score**: `{self.compliance_score:.1f}/100`  ",
            "",
            "## Evaluated Framework Sections",
            "",
            "| Section / Article | Status | Findings | Description |",
            "|---|---|---|---|",
        ]

        for sec_id, sec_data in self.evaluated_sections.items():
            st = sec_data.get("status", "COMPLIANT")
            cnt = sec_data.get("finding_count", 0)
            desc = sec_data.get("description", "")
            lines.append(f"| **{sec_id}** | `{st}` | {cnt} | {desc} |")

        if self.findings:
            lines.extend(
                [
                    "",
                    "## Compliance Gap Analysis",
                    "",
                    "| Finding ID | Framework Ref | Status | Gap & Risk Description |",
                    "|---|---|---|---|",
                ]
            )
            for f in self.findings:
                lines.append(
                    f"| `{f.finding_id}` | {f.article_or_function} | `{f.status.value}` | {f.gap_analysis} |"
                )

        if self.recommendations:
            lines.extend(
                [
                    "",
                    "## Required Remediation Actions",
                    "",
                ]
            )
            for rec in self.recommendations:
                lines.append(f"- {rec}")

        return "\n".join(lines)


# ── EU AI Act Evaluator ───────────────────────────────────────────────────────


def evaluate_eu_ai_act(findings: list[Finding] | list[dict[str, Any]]) -> ComplianceReport:
    """Evaluate findings against EU AI Act Article 15 (Cybersecurity) & Article 50 (Transparency)."""
    normalized_findings = _normalize_findings(findings)

    # Article 15: Cybersecurity & Robustness against adversarial manipulation (LLM01, LLM04, LLM05, LLM08)
    # Article 50: Transparency obligations, disclosure of synthetic content & confidential prompts (LLM02, LLM06, LLM07)
    # Article 10: Data Governance & RAG poisoning (LLM03, LLM05)
    # Article 14: Human Oversight & Excessive Agency (LLM06, LLM09)

    sections: dict[str, dict[str, Any]] = {
        "Article 15 (Cybersecurity & Robustness)": {
            "target_owasp": {"LLM01", "LLM04", "LLM05", "LLM08"},
            "description": "Resilience against adversarial prompt injection, DoS, and unauthorized model tampering.",
            "findings": [],
        },
        "Article 50 (Transparency Obligations)": {
            "target_owasp": {"LLM02", "LLM06", "LLM07"},
            "description": "Protection against unintended disclosure of developer prompts, confidential data, and PII.",
            "findings": [],
        },
        "Article 10 (Data Governance & Supply Chain)": {
            "target_owasp": {"LLM03", "LLM05"},
            "description": "Data integrity, prevention of RAG poisoning, and verified supply chain software dependencies.",
            "findings": [],
        },
        "Article 14 (Human Oversight & Agency Limits)": {
            "target_owasp": {"LLM06", "LLM09"},
            "description": "Human oversight mechanisms and containment of excessive tool execution agency.",
            "findings": [],
        },
    }

    comp_findings: list[ComplianceFinding] = []

    for f in normalized_findings:
        owasp_id = getattr(f, "owasp_id", "") or "LLM01"
        fid = getattr(f, "attack_id", "") or "UNKNOWN"
        desc = getattr(f, "description", "")
        remed = getattr(f, "remediation", "")

        assigned_section = None
        for sec_name, sec_meta in sections.items():
            if owasp_id in sec_meta["target_owasp"]:
                sec_meta["findings"].append(fid)
                assigned_section = sec_name
                break

        if not assigned_section:
            assigned_section = "Article 15 (Cybersecurity & Robustness)"
            sections[assigned_section]["findings"].append(fid)

        comp_findings.append(
            ComplianceFinding(
                finding_id=fid,
                owasp_id=owasp_id,
                article_or_function=assigned_section.split(" ")[0]
                + " "
                + assigned_section.split(" ")[1],
                status=ComplianceStatus.NON_COMPLIANT,
                gap_analysis=desc
                or f"Vulnerability {fid} violates {assigned_section} requirements.",
                remediation_guidance=remed
                or "Apply defensive guardrails and restrict model permissions.",
            )
        )

    # Calculate status per section
    evaluated_sections: dict[str, dict[str, Any]] = {}
    total_violations = 0
    recommendations: list[str] = []

    for sec_name, sec_meta in sections.items():
        count = len(sec_meta["findings"])
        total_violations += count
        if count == 0:
            status = ComplianceStatus.COMPLIANT
        elif count <= 2:
            status = ComplianceStatus.PARTIALLY_COMPLIANT
            recommendations.append(
                f"Remediate {count} issues in {sec_name} to attain full compliance."
            )
        else:
            status = ComplianceStatus.NON_COMPLIANT
            recommendations.append(
                f"Critical non-compliance in {sec_name} ({count} active vulnerabilities)."
            )

        evaluated_sections[sec_name] = {
            "status": status.value,
            "finding_count": count,
            "description": sec_meta["description"],
            "findings": sec_meta["findings"],
        }

    # Score calculation (starts at 100, drops per violation)
    score = max(0.0, 100.0 - (total_violations * 12.5))
    if score >= 90.0:
        overall = ComplianceStatus.COMPLIANT
    elif score >= 60.0:
        overall = ComplianceStatus.PARTIALLY_COMPLIANT
    else:
        overall = ComplianceStatus.NON_COMPLIANT

    return ComplianceReport(
        framework=ComplianceFramework.EU_AI_ACT,
        overall_status=overall,
        compliance_score=round(score, 1),
        evaluated_sections=evaluated_sections,
        findings=comp_findings,
        recommendations=recommendations
        or ["All evaluated EU AI Act cybersecurity and transparency controls pass."],
    )


# ── NIST AI RMF 1.0 Evaluator ─────────────────────────────────────────────────


def evaluate_nist_ai_rmf(findings: list[Finding] | list[dict[str, Any]]) -> ComplianceReport:
    """Evaluate findings against NIST AI Risk Management Framework 1.0 (GOVERN, MAP, MEASURE, MANAGE)."""
    normalized_findings = _normalize_findings(findings)

    functions: dict[str, dict[str, Any]] = {
        "GOVERN (Governance & Culture)": {
            "target_owasp": {"LLM02", "LLM09"},
            "description": "Organizational risk tolerance, policies, and human-in-the-loop governance.",
            "findings": [],
        },
        "MAP (Context & Threat Mapping)": {
            "target_owasp": {"LLM03", "LLM06", "LLM07"},
            "description": "Mapping data boundaries, knowledge poisoning, and sensitive information flows.",
            "findings": [],
        },
        "MEASURE (Risk Analysis & Tracking)": {
            "target_owasp": {"LLM01", "LLM04"},
            "description": "Continuous empirical measurement of adversarial robustness and denial of service.",
            "findings": [],
        },
        "MANAGE (Mitigation & Response)": {
            "target_owasp": {"LLM05", "LLM08"},
            "description": "Active controls, tool privilege limits, and automated vulnerability response.",
            "findings": [],
        },
    }

    comp_findings: list[ComplianceFinding] = []

    for f in normalized_findings:
        owasp_id = getattr(f, "owasp_id", "") or "LLM01"
        fid = getattr(f, "attack_id", "") or "UNKNOWN"
        desc = getattr(f, "description", "")
        remed = getattr(f, "remediation", "")

        assigned_fn = None
        for fn_name, fn_meta in functions.items():
            if owasp_id in fn_meta["target_owasp"]:
                fn_meta["findings"].append(fid)
                assigned_fn = fn_name
                break

        if not assigned_fn:
            assigned_fn = "MEASURE (Risk Analysis & Tracking)"
            functions[assigned_fn]["findings"].append(fid)

        comp_findings.append(
            ComplianceFinding(
                finding_id=fid,
                owasp_id=owasp_id,
                article_or_function=assigned_fn.split(" ")[0],
                status=ComplianceStatus.NON_COMPLIANT,
                gap_analysis=desc or f"Vulnerability {fid} violates NIST AI RMF {assigned_fn}.",
                remediation_guidance=remed
                or "Implement mitigations per NIST AI RMF action profile.",
            )
        )

    evaluated_sections: dict[str, dict[str, Any]] = {}
    total_violations = 0
    recommendations: list[str] = []

    for fn_name, fn_meta in functions.items():
        count = len(fn_meta["findings"])
        total_violations += count
        if count == 0:
            status = ComplianceStatus.COMPLIANT
        elif count <= 2:
            status = ComplianceStatus.PARTIALLY_COMPLIANT
            recommendations.append(f"Address {count} risks mapped to NIST AI RMF {fn_name}.")
        else:
            status = ComplianceStatus.NON_COMPLIANT
            recommendations.append(
                f"Substantial exposure in NIST AI RMF {fn_name} ({count} active vulnerabilities)."
            )

        evaluated_sections[fn_name] = {
            "status": status.value,
            "finding_count": count,
            "description": fn_meta["description"],
            "findings": fn_meta["findings"],
        }

    score = max(0.0, 100.0 - (total_violations * 12.5))
    if score >= 90.0:
        overall = ComplianceStatus.COMPLIANT
    elif score >= 60.0:
        overall = ComplianceStatus.PARTIALLY_COMPLIANT
    else:
        overall = ComplianceStatus.NON_COMPLIANT

    return ComplianceReport(
        framework=ComplianceFramework.NIST_AI_RMF,
        overall_status=overall,
        compliance_score=round(score, 1),
        evaluated_sections=evaluated_sections,
        findings=comp_findings,
        recommendations=recommendations or ["All evaluated NIST AI RMF 1.0 profile metrics pass."],
    )


# ── MITRE ATLAS Evaluator ─────────────────────────────────────────────────────


def evaluate_mitre_atlas(findings: list[Finding] | list[dict[str, Any]]) -> ComplianceReport:
    """Evaluate findings against MITRE ATLAS (Adversarial Threat Landscape for AI Systems)."""
    normalized_findings = _normalize_findings(findings)

    sections: dict[str, dict[str, Any]] = {
        "AML.T0051 (LLM Prompt Injection)": {
            "targets": set(MITRE_ATLAS_MAPPING["AML.T0051"]),
            "description": "Direct or indirect adversarial manipulation of LLM system inputs and context.",
            "findings": [],
        },
        "AML.T0054 (LLM Jailbreak)": {
            "targets": set(MITRE_ATLAS_MAPPING["AML.T0054"]),
            "description": "Adversarial prompts and multi-turn jailbreaks bypassing model safety alignment.",
            "findings": [],
        },
        "AML.T0056 (System Prompt Leakage)": {
            "targets": set(MITRE_ATLAS_MAPPING["AML.T0056"]),
            "description": "Unauthorized disclosure of internal instructions, secrets, or system prompts.",
            "findings": [],
        },
        "AML.T0048 (Insecure Output Handling)": {
            "targets": set(MITRE_ATLAS_MAPPING["AML.T0048"]),
            "description": "Downstream execution of unvalidated or malicious LLM outputs without sanitization.",
            "findings": [],
        },
        "AML.T0057 (LLM Data Exfiltration)": {
            "targets": set(MITRE_ATLAS_MAPPING["AML.T0057"]),
            "description": "Exfiltration of sensitive context, credentials, or training data via model channels.",
            "findings": [],
        },
    }

    comp_findings: list[ComplianceFinding] = []

    for f in normalized_findings:
        owasp_id = getattr(f, "owasp_id", "") or "LLM01"
        fid = getattr(f, "attack_id", "") or "UNKNOWN"
        desc = getattr(f, "description", "")
        remed = getattr(f, "remediation", "")

        assigned_sec = None
        for sec_name, sec_meta in sections.items():
            if fid in sec_meta["targets"] or owasp_id in sec_meta["targets"]:
                sec_meta["findings"].append(fid)
                assigned_sec = sec_name
                break

        if not assigned_sec:
            assigned_sec = "AML.T0051 (LLM Prompt Injection)"
            sections[assigned_sec]["findings"].append(fid)

        comp_findings.append(
            ComplianceFinding(
                finding_id=fid,
                owasp_id=owasp_id,
                article_or_function=assigned_sec.split(" ")[0],
                status=ComplianceStatus.NON_COMPLIANT,
                gap_analysis=desc or f"Vulnerability {fid} maps to MITRE ATLAS {assigned_sec}.",
                remediation_guidance=remed
                or "Implement mitigations per MITRE ATLAS mitigation guidelines.",
            )
        )

    evaluated_sections: dict[str, dict[str, Any]] = {}
    total_violations = 0
    recommendations: list[str] = []

    for sec_name, sec_meta in sections.items():
        count = len(sec_meta["findings"])
        total_violations += count
        if count == 0:
            status = ComplianceStatus.COMPLIANT
        elif count <= 2:
            status = ComplianceStatus.PARTIALLY_COMPLIANT
            recommendations.append(
                f"Mitigate {count} findings in MITRE ATLAS technique {sec_name}."
            )
        else:
            status = ComplianceStatus.NON_COMPLIANT
            recommendations.append(
                f"Severe vulnerability exposure in MITRE ATLAS technique {sec_name} ({count} findings)."
            )

        evaluated_sections[sec_name] = {
            "status": status.value,
            "finding_count": count,
            "description": sec_meta["description"],
            "findings": sec_meta["findings"],
        }

    score = max(0.0, 100.0 - (total_violations * 12.5))
    if score >= 90.0:
        overall = ComplianceStatus.COMPLIANT
    elif score >= 60.0:
        overall = ComplianceStatus.PARTIALLY_COMPLIANT
    else:
        overall = ComplianceStatus.NON_COMPLIANT

    return ComplianceReport(
        framework=ComplianceFramework.MITRE_ATLAS,
        overall_status=overall,
        compliance_score=round(score, 1),
        evaluated_sections=evaluated_sections,
        findings=comp_findings,
        recommendations=recommendations or ["All evaluated MITRE ATLAS TTP controls pass."],
    )


generate_mitre_atlas_report = evaluate_mitre_atlas


# ── ISO/IEC 42001 Evaluator ───────────────────────────────────────────────────


def evaluate_iso_42001(findings: list[Finding] | list[dict[str, Any]]) -> ComplianceReport:
    """Evaluate findings against ISO/IEC 42001 (Artificial Intelligence Management System)."""
    normalized_findings = _normalize_findings(findings)

    sections: dict[str, dict[str, Any]] = {
        "A.6.2 (AI Risk Assessment & Validation)": {
            "targets": set(ISO_42001_MAPPING["A.6.2"]),
            "description": "Systematic identification, assessment, and validation of AI security risks.",
            "findings": [],
        },
        "A.8.2 (AI Data Quality & Ingestion Security)": {
            "targets": set(ISO_42001_MAPPING["A.8.2"]),
            "description": "Security controls for data acquisition, pre-processing, and ingestion pipelines.",
            "findings": [],
        },
        "A.8.4 (Security of System Integration & Tool Calling)": {
            "targets": set(ISO_42001_MAPPING["A.8.4"]),
            "description": "Security safeguards for third-party tool execution, integrations, and plugins.",
            "findings": [],
        },
        "A.9.3 (Robustness & Adversarial Testing)": {
            "targets": set(ISO_42001_MAPPING["A.9.3"]),
            "description": "Verification of AI system robustness under continuous adversarial evaluation.",
            "findings": [],
        },
    }

    comp_findings: list[ComplianceFinding] = []

    for f in normalized_findings:
        owasp_id = getattr(f, "owasp_id", "") or "LLM01"
        fid = getattr(f, "attack_id", "") or "UNKNOWN"
        desc = getattr(f, "description", "")
        remed = getattr(f, "remediation", "")

        assigned_sec = None
        for sec_name, sec_meta in sections.items():
            if fid in sec_meta["targets"] or owasp_id in sec_meta["targets"]:
                sec_meta["findings"].append(fid)
                assigned_sec = sec_name
                break

        if not assigned_sec:
            assigned_sec = "A.6.2 (AI Risk Assessment & Validation)"
            sections[assigned_sec]["findings"].append(fid)

        comp_findings.append(
            ComplianceFinding(
                finding_id=fid,
                owasp_id=owasp_id,
                article_or_function=assigned_sec.split(" ")[0],
                status=ComplianceStatus.NON_COMPLIANT,
                gap_analysis=desc
                or f"Vulnerability {fid} violates ISO/IEC 42001 control {assigned_sec}.",
                remediation_guidance=remed
                or "Implement controls per ISO/IEC 42001 Annex A guidance.",
            )
        )

    evaluated_sections: dict[str, dict[str, Any]] = {}
    total_violations = 0
    recommendations: list[str] = []

    for sec_name, sec_meta in sections.items():
        count = len(sec_meta["findings"])
        total_violations += count
        if count == 0:
            status = ComplianceStatus.COMPLIANT
        elif count <= 2:
            status = ComplianceStatus.PARTIALLY_COMPLIANT
            recommendations.append(
                f"Address {count} non-conformities in ISO/IEC 42001 control {sec_name}."
            )
        else:
            status = ComplianceStatus.NON_COMPLIANT
            recommendations.append(
                f"Critical non-conformity in ISO/IEC 42001 control {sec_name} ({count} active vulnerabilities)."
            )

        evaluated_sections[sec_name] = {
            "status": status.value,
            "finding_count": count,
            "description": sec_meta["description"],
            "findings": sec_meta["findings"],
        }

    score = max(0.0, 100.0 - (total_violations * 12.5))
    if score >= 90.0:
        overall = ComplianceStatus.COMPLIANT
    elif score >= 60.0:
        overall = ComplianceStatus.PARTIALLY_COMPLIANT
    else:
        overall = ComplianceStatus.NON_COMPLIANT

    return ComplianceReport(
        framework=ComplianceFramework.ISO_42001,
        overall_status=overall,
        compliance_score=round(score, 1),
        evaluated_sections=evaluated_sections,
        findings=comp_findings,
        recommendations=recommendations
        or ["All evaluated ISO/IEC 42001 management controls pass."],
    )


generate_iso_42001_report = evaluate_iso_42001


def _normalize_findings(findings: list[Finding] | list[dict[str, Any]]) -> list[Any]:
    """Ensure all findings are accessible via attributes or keys."""
    normalized: list[Any] = []
    for item in findings:
        if isinstance(item, Finding):
            normalized.append(item)
        elif isinstance(item, dict):
            try:
                normalized.append(Finding.model_validate(item))
            except Exception:
                # Mock namespace object with attributes
                from types import SimpleNamespace

                normalized.append(
                    SimpleNamespace(
                        attack_id=str(item.get("attack_id") or item.get("id") or "FINDING"),
                        owasp_id=str(item.get("owasp_id") or "LLM01"),
                        description=str(item.get("description") or ""),
                        remediation=str(item.get("remediation") or ""),
                    )
                )
    return normalized
