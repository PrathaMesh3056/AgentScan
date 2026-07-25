from agentscan.core.models import ScanReport
from agentscan.identity.models import IdentityReport


def to_sarif(report: ScanReport | IdentityReport) -> dict:
    rules = {}
    for finding in report.findings:
        if finding.attack_id not in rules:
            rules[finding.attack_id] = {
                "id": finding.attack_id,
                "name": getattr(finding, "attack_name", finding.attack_id),
                "shortDescription": {"text": finding.description or "No description provided."},
            }

    results = []
    for finding in report.findings:
        severity_value = finding.severity.value
        if severity_value in ["CRITICAL", "HIGH"]:
            level = "error"
        elif severity_value == "MEDIUM":
            level = "warning"
        else:
            level = "note"

        from typing import Any

        result: dict[str, Any] = {
            "ruleId": finding.attack_id,
            "level": level,
            "message": {"text": finding.description},
        }

        manifest_path = getattr(finding, "metadata", {}).get("manifest_path")
        if manifest_path:
            result["locations"] = [
                {"physicalLocation": {"artifactLocation": {"uri": manifest_path}}}
            ]

        results.append(result)

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "AgentScan", "rules": list(rules.values())}},
                "results": results,
            }
        ],
    }
