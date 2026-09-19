# agentscan/reporting/sarif_report.py
#
# Production SARIF 2.1.0 Exporter for GitHub Advanced Security & Code Scanning.

from __future__ import annotations

from typing import Any

from agentscan.core.models import ScanReport, _installed_version
from agentscan.identity.models import IdentityReport


def to_sarif(report: ScanReport | IdentityReport) -> dict[str, Any]:
    """
    Export an AgentScan report to OASIS SARIF 2.1.0 schema.
    Fully compatible with GitHub Code Scanning alerts, GitLab SAST, and DefectDojo.
    """
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    version = _installed_version()

    for finding in report.findings:
        attack_id = finding.attack_id or "ATK-UNKNOWN"
        if attack_id not in rules:
            owasp_id = getattr(finding, "owasp_id", "LLM-GENERIC")
            rules[attack_id] = {
                "id": attack_id,
                "name": getattr(finding, "attack_name", attack_id),
                "shortDescription": {"text": finding.description or f"Vulnerability {attack_id}"},
                "fullDescription": {
                    "text": (
                        f"{finding.description}\n\n"
                        f"OWASP Category: {owasp_id}\n"
                        f"Remediation: {finding.remediation or 'Implement input validation and defensive guardrails.'}"
                    )
                },
                "help": {
                    "text": (
                        f"Remediation Guidance:\n{finding.remediation or 'Review agent prompt and output handling.'}"
                    ),
                    "markdown": (
                        f"### Vulnerability Details\n\n"
                        f"**OWASP Category**: `{owasp_id}`  \n"
                        f"**Severity**: `{finding.severity.value}`  \n\n"
                        f"### Remediation\n\n"
                        f"{finding.remediation or 'Implement strict boundary validation.'}"
                    ),
                },
                "properties": {
                    "tags": ["security", "ai-security", "owasp-top-10", owasp_id],
                    "precision": "high",
                },
                "defaultConfiguration": {
                    "level": (
                        "error"
                        if finding.severity.value in ["CRITICAL", "HIGH"]
                        else "warning"
                        if finding.severity.value == "MEDIUM"
                        else "note"
                    )
                },
            }

        # Level calculation
        severity_value = finding.severity.value
        level = (
            "error"
            if severity_value in ["CRITICAL", "HIGH"]
            else "warning"
            if severity_value == "MEDIUM"
            else "note"
        )

        # Determine physical location
        manifest_path = (
            getattr(finding, "metadata", {}).get("manifest_path") or "agentscan/target_agent.py"
        )

        result: dict[str, Any] = {
            "ruleId": attack_id,
            "level": level,
            "message": {"text": f"[{finding.severity.value}] {finding.description}"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": str(manifest_path),
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": 1,
                            "startColumn": 1,
                        },
                    }
                }
            ],
        }

        results.append(result)

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AgentScan",
                        "version": version,
                        "semanticVersion": version,
                        "informationUri": "https://github.com/PrathaMesh3056/AgentScan",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
