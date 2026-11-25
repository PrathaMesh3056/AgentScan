# tests/test_remediation/test_pin_bump.py

from pathlib import Path

from agentscan.core.models import Finding, Severity
from agentscan.remediation.pin_bump import plan_pin_bumps


def test_pin_bump_requirements_txt(tmp_path: Path) -> None:
    req = tmp_path / "requirements.txt"
    req.write_text("langchain==0.0.120\nrequests>=2.28.0\n", encoding="utf-8")

    finding = Finding(
        attack_id="SC-001",
        attack_name="Known-vulnerable dependency",
        severity=Severity.HIGH,
        owasp_id="LLM05",
        description="Dependency 'langchain==0.0.120' is vulnerable. Upgrade to >=0.0.155.",
        evidence="package=langchain, version=0.0.120",
        metadata={"package": "langchain", "version": "0.0.120", "fix_version": "0.0.155"},
    )

    actions = plan_pin_bumps([finding], tmp_path)
    assert len(actions) == 1
    action = actions[0]
    assert action.kind == "pin_bump"
    assert action.finding_id == "SC-001"
    assert "langchain==0.0.155" in action.after
    assert "requests>=2.28.0" in action.after


def test_pin_bump_pyproject_toml(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        '[project]\ndependencies = [\n    "langchain==0.0.120",\n    "pydantic>=2.0",\n]\n',
        encoding="utf-8",
    )

    finding = Finding(
        attack_id="SC-001",
        attack_name="Known-vulnerable dependency",
        severity=Severity.HIGH,
        owasp_id="LLM05",
        description="Dependency 'langchain==0.0.120' is vulnerable. Upgrade to >=0.0.155.",
        evidence="package=langchain, version=0.0.120",
        metadata={"package": "langchain", "version": "0.0.120", "fix_version": "0.0.155"},
    )

    actions = plan_pin_bumps([finding], tmp_path)
    assert len(actions) == 1
    assert '"langchain==0.0.155"' in actions[0].after
