# tests/test_remediation/test_pin_bump_operators.py
#
# QA-037: version bumps must preserve the operator the operator wrote.

from __future__ import annotations

from pathlib import Path

import pytest

from agentscan.core.models import Finding, Severity
from agentscan.remediation.pin_bump import plan_pin_bumps

MARKED = "langchain==0.0.120 ; python_version < '3.9'"
MARKED_FIXED = "langchain==0.0.155 ; python_version < '3.9'"

CASES = [
    ("langchain==0.0.120", "langchain==0.0.155"),
    ("langchain~=0.0.120", "langchain~=0.0.155"),
    ("langchain>=0.0.120", "langchain>=0.0.155"),
    ("langchain == 0.0.120", "langchain == 0.0.155"),
    (MARKED, MARKED_FIXED),
]


def _sc001() -> Finding:
    return Finding(
        attack_id="SC-001",
        attack_name="Known-vulnerable dependency",
        severity=Severity.HIGH,
        owasp_id="LLM05",
        description="Dependency 'langchain==0.0.120' is vulnerable. Upgrade to >=0.0.155.",
        evidence="package=langchain, version=0.0.120",
        metadata={"package": "langchain", "version": "0.0.120", "fix_version": "0.0.155"},
    )


def _bump_requirements(tmp_path: Path, line: str) -> str:
    (tmp_path / "requirements.txt").write_text(line + "\n", encoding="utf-8")
    actions = plan_pin_bumps([_sc001()], tmp_path)
    assert len(actions) == 1
    return actions[0].after


def _bump_pyproject(tmp_path: Path, line: str) -> str:
    (tmp_path / "pyproject.toml").write_text(
        f'[project]\ndependencies = [\n    "{line}",\n]\n', encoding="utf-8"
    )
    actions = plan_pin_bumps([_sc001()], tmp_path)
    assert len(actions) == 1
    return actions[0].after


@pytest.mark.parametrize(("line", "expected"), CASES)
def test_requirements_bump_preserves_operator(tmp_path: Path, line: str, expected: str) -> None:
    assert _bump_requirements(tmp_path, line) == expected + "\n"


@pytest.mark.parametrize(("line", "expected"), CASES)
def test_pyproject_bump_preserves_operator(tmp_path: Path, line: str, expected: str) -> None:
    updated = _bump_pyproject(tmp_path, line)

    assert expected in updated


@pytest.mark.parametrize("line", ["langchain<=0.0.120", "langchain<0.0.121", "langchain!=0.0.120"])
def test_upper_bounds_become_a_lower_bound_on_the_fix(tmp_path: Path, line: str) -> None:
    """An upper bound cannot express "install the fix"; it becomes >=<fix>."""
    assert _bump_requirements(tmp_path, line) == "langchain>=0.0.155\n"


def test_unrelated_requirements_are_untouched(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text(
        "langchain==0.0.120\nrequests>=2.28.0\n", encoding="utf-8"
    )
    actions = plan_pin_bumps([_sc001()], tmp_path)
    assert "requests>=2.28.0" in actions[0].after
