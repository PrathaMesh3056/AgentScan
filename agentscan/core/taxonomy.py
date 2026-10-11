"""Versioned references; mappings describe scenarios, not certified coverage.

OWASP: https://genai.owasp.org/llm-top-10/ (2025)
ATLAS: https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/v6/ATLAS-2026.09.yaml
"""

OWASP_VERSION = "2025"
ATLAS_VERSION = "2026.09"
OWASP_CATEGORIES = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}
ATLAS_TECHNIQUES = {
    "AML.T0051": "LLM Prompt Injection",
    "AML.T0051.000": "Direct",
    "AML.T0051.001": "Indirect",
    "AML.T0053": "AI Agent Tool Invocation",
    "AML.T0054": "LLM Jailbreak",
    "AML.T0055": "Unsecured Credentials",
    "AML.T0056": "LLM Meta Prompt Extraction",
    "AML.T0057": "LLM Data Leakage",
    "AML.T0059": "Erode Dataset Integrity",
}
ATTACK_ATLAS = {
    "ATK-001": "AML.T0051.000",
    "ATK-002": "AML.T0054",
    "ATK-003": "AML.T0057",
    "ATK-005": "AML.T0051.001",
    "ATK-010": "AML.T0054",
    "ATK-011": "AML.T0051.000",
    "ATK-012": "AML.T0056",
    "ATK-014": "AML.T0057",
    "ATK-018": "AML.T0057",
    "ATK-028": "AML.T0051.000",
    "ATK-050": "AML.T0051",
    "ATK-SOC-001": "AML.T0054",
}


def atlas_for_finding(finding) -> str | None:
    explicit = getattr(finding, "mitre_atlas_id", None)
    if explicit in ATLAS_TECHNIQUES:
        return explicit
    return ATTACK_ATLAS.get(getattr(finding, "attack_id", ""))
