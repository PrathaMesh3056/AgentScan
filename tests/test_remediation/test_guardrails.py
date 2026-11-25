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


def test_plan_guardrails_skips_files_that_already_match(tmp_path: Path) -> None:
    """Re-running guardrail planning must not rewrite an identical policy file."""
    findings = [
        Finding(
            attack_id="ATK-001",
            attack_name="Direct Prompt Injection",
            severity=Severity.HIGH,
            owasp_id="LLM01",
            description="Agent leaked system prompt on injection payload.",
            evidence="leaked prompt",
        )
    ]

    initial = plan_guardrails(findings, tmp_path)
    assert len(initial) == 2
    for action in initial:
        path = Path(action.path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(action.after, encoding="utf-8")

    assert plan_guardrails(findings, tmp_path) == []


def test_plan_guardrails_plans_only_the_changed_file(tmp_path: Path) -> None:
    """A current Colang file must not suppress a still-missing prompt guard."""
    findings = [
        Finding(
            attack_id="ATK-007",
            attack_name="Insecure Output Handling",
            severity=Severity.HIGH,
            owasp_id="LLM02",
            description="Agent reflected unescaped XSS payload.",
            evidence="<script>alert(1)</script>",
        )
    ]

    initial = plan_guardrails(findings, tmp_path)
    colang_action = next(a for a in initial if a.path.endswith("agent_guardrails.co"))
    colang_path = Path(colang_action.path)
    colang_path.parent.mkdir(parents=True, exist_ok=True)
    colang_path.write_text(colang_action.after, encoding="utf-8")

    remaining = plan_guardrails(findings, tmp_path)
    assert [Path(action.path).name for action in remaining] == ["system_prompt_guard.md"]
