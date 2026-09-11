# tests/test_remediation/test_guardrails.py

from pathlib import Path

from agentscan.core.models import Finding, Severity
from agentscan.remediation.guardrails import plan_guardrails


def test_guardrails_synthesis(tmp_path: Path) -> None:
    findings = [
        Finding(
            attack_id="ATK-001",
            attack_name="Direct Prompt Injection",
            severity=Severity.HIGH,
            owasp_id="LLM01",
            description="Agent leaked system prompt on injection payload.",
            evidence="leaked prompt",
        ),
        Finding(
            attack_id="ATK-007",
            attack_name="Insecure Output Handling",
            severity=Severity.HIGH,
            owasp_id="LLM02",
            description="Agent reflected unescaped XSS payload.",
            evidence="<script>alert(1)</script>",
        ),
    ]

    actions = plan_guardrails(findings, tmp_path)
    assert len(actions) == 2
    paths = [a.path for a in actions]
    assert any(p.endswith("agent_guardrails.co") for p in paths)
    assert any(p.endswith("system_prompt_guard.md") for p in paths)

    colang_action = next(a for a in actions if a.path.endswith("agent_guardrails.co"))
    assert "define flow check_prompt_injection" in colang_action.after
    assert "sanitize_output" in colang_action.after

    prompt_action = next(a for a in actions if a.path.endswith("system_prompt_guard.md"))
    assert "Instruction Boundary Integrity" in prompt_action.after
    assert "Output Sanitization" in prompt_action.after
