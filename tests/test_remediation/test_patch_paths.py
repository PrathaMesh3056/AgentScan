# tests/test_remediation/test_patch_paths.py
#
# QA-037: patches must be LF-normalized and carry repo-relative paths.

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from agentscan.cli import app
from agentscan.core.models import Finding, Severity
from agentscan.remediation.git_pr import GitPRAutomator
from agentscan.remediation.models import FixAction, FixPlan
from agentscan.remediation.patch_generator import (
    generate_github_pr_payload,
    generate_unified_patch,
)

runner = CliRunner()


def _crlf_plan(tmp_path: Path) -> FixPlan:
    target = tmp_path / "src" / "agent.py"
    target.parent.mkdir()
    target.write_text("DEBUG = True\r\n", encoding="utf-8", newline="")
    action = FixAction(
        path=str(target),
        kind="ast_patch",
        finding_id="SC-014",
        before='DEBUG = True\r\nprint("ready")\r\n',
        after='DEBUG = False\r\nprint("ready")\r\n',
    )
    plan = FixPlan(actions=[action])
    plan.bind_root(tmp_path)
    return plan


def test_unified_patch_contains_only_lf(tmp_path: Path) -> None:
    patch = generate_unified_patch(_crlf_plan(tmp_path), base_dir=tmp_path)

    assert patch
    assert "\r" not in patch
    assert "--- a/src/agent.py\n" in patch
    assert "+++ b/src/agent.py\n" in patch


def test_git_pr_diff_uses_relative_nested_path_and_lf(tmp_path: Path) -> None:
    plan = _crlf_plan(tmp_path)
    body = GitPRAutomator(repo_path=tmp_path).generate_pr_body(plan)

    assert "--- a/src/agent.py" in body
    assert "+++ b/src/agent.py" in body
    assert "a/agent.py" not in body
    assert "\r" not in body


def test_git_pr_body_reports_relative_file_path(tmp_path: Path) -> None:
    plan = _crlf_plan(tmp_path)
    body = GitPRAutomator(repo_path=tmp_path).generate_pr_body(plan)

    assert "**File Path**: `src/agent.py`" in body
    assert str(tmp_path) not in body


def test_github_payload_uses_relative_paths(tmp_path: Path) -> None:
    payload = generate_github_pr_payload(_crlf_plan(tmp_path))

    assert "`src/agent.py`" in payload["body"]
    assert str(tmp_path) not in payload["body"]
    assert payload["metadata"]["paths_affected"] == ["src/agent.py"]
    assert "\r" not in payload["metadata"]["patch"]


def _sc014(settings: Path) -> dict[str, object]:
    return {
        "findings": [
            Finding(
                attack_id="SC-014",
                attack_name="Debug mode enabled",
                severity=Severity.MEDIUM,
                owasp_id="LLM05",
                description="DEBUG = True ships tracebacks to users.",
                evidence="app/settings.py:1",
                metadata={"file": str(settings)},
            ).model_dump(mode="json")
        ]
    }


def test_cli_fix_diff_headers_are_repo_relative(tmp_path: Path) -> None:
    settings = tmp_path / "app" / "settings.py"
    settings.parent.mkdir()
    settings.write_text("DEBUG = True\n", encoding="utf-8")
    report = tmp_path / "report.json"
    report.write_text(json.dumps(_sc014(settings)), encoding="utf-8")

    result = runner.invoke(app, ["fix", str(report)])

    assert result.exit_code == 0, result.output
    assert "a/app/settings.py" in result.output
    assert "b/app/settings.py" in result.output
