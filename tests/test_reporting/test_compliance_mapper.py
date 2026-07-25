from agentscan.core.models import Finding, Severity
from agentscan.reporting.compliance_mapper import (
    generate_compliance_summary,
    map_finding_to_compliance,
)


def test_map_finding_to_compliance_llm01():
    finding = Finding(
        attack_id="ATK-001",
        attack_name="Test",
        severity=Severity.MEDIUM,
        description="Valid description",
        owasp_id="LLM01",
    )
    mapping = map_finding_to_compliance(finding)
    assert mapping.get("owasp_id") == "LLM01"


def test_map_finding_to_compliance_llm08():
    finding = Finding(
        attack_id="ATK-002",
        attack_name="Test",
        severity=Severity.MEDIUM,
        description="Valid description",
        owasp_id="LLM08",
    )
    mapping = map_finding_to_compliance(finding)
    assert mapping.get("owasp_id") == "LLM08"
    assert mapping != map_finding_to_compliance(
        Finding(
            attack_id="ATK-001",
            attack_name="Test",
            severity=Severity.MEDIUM,
            description="Valid description",
            owasp_id="LLM01",
        )
    )


def test_map_finding_to_compliance_unmapped():
    finding = Finding(
        attack_id="ATK-003",
        attack_name="Test",
        severity=Severity.MEDIUM,
        description="Valid description",
        owasp_id="LLM99",
    )
    mapping = map_finding_to_compliance(finding)
    assert mapping["nist_function"] == "Not mapped"
    assert mapping["mitre_atlas_technique"] == "Not mapped"
    assert mapping["eu_ai_act_article"] == "Not mapped"


def test_generate_compliance_summary():
    finding1 = Finding(
        attack_id="ATK-001",
        attack_name="Test",
        severity=Severity.MEDIUM,
        description="Valid description",
        owasp_id="LLM01",
    )
    finding2 = Finding(
        attack_id="ATK-002",
        attack_name="Test",
        severity=Severity.MEDIUM,
        description="Valid description",
        owasp_id="LLM08",
    )
    finding3 = Finding(
        attack_id="ATK-003",
        attack_name="Test",
        severity=Severity.MEDIUM,
        description="Valid description",
        owasp_id="LLM01",
    )
    summary = generate_compliance_summary([finding1, finding2, finding3])

    mapping1 = map_finding_to_compliance(finding1)
    mapping2 = map_finding_to_compliance(finding2)

    assert mapping1["nist_function"] in summary["nist_function"]
    assert mapping2["nist_function"] in summary["nist_function"]
    assert len(summary["nist_function"]) == 2
