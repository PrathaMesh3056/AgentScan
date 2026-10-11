from pathlib import Path

import yaml

from agentscan.core.models import Finding
from agentscan.core.taxonomy import ATLAS_VERSION, OWASP_VERSION, atlas_for_finding

MAPPINGS_FILE = Path(__file__).parent / "compliance_mappings.yaml"


def _load_mappings() -> dict[str, dict]:
    if not MAPPINGS_FILE.exists():
        return {}
    with open(MAPPINGS_FILE, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not data:
        return {}
    return {item["owasp_id"]: item for item in data}


_MAPPINGS = _load_mappings()


def map_finding_to_compliance(finding: Finding) -> dict:
    owasp_id = getattr(finding, "owasp_id", None)
    if not owasp_id or owasp_id not in _MAPPINGS:
        return {
            "nist_function": "Not mapped",
            "mitre_atlas_technique": "Not mapped",
            "eu_ai_act_article": "Not mapped",
        }
    return {
        **_MAPPINGS[owasp_id],
        "mitre_atlas_technique": atlas_for_finding(finding) or "Not mapped",
        "owasp_version": OWASP_VERSION,
        "atlas_version": ATLAS_VERSION,
    }


def generate_compliance_summary(findings: list[Finding]) -> dict[str, list]:
    summary: dict[str, list[str]] = {
        "nist_function": [],
        "mitre_atlas_technique": [],
        "eu_ai_act_article": [],
    }

    for f in findings:
        mapping = map_finding_to_compliance(f)
        for key in summary:
            val = mapping.get(key, "Not mapped")
            if val != "Not mapped" and val not in summary[key]:
                summary[key].append(val)

    return summary
