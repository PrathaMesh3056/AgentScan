# tests/test_remediation/test_provenance_map.py
#
# QA-037: every finding must map to the remediation actions planned from it.

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from agentscan.cli import app
from agentscan.core.models import Finding, Severity
from agentscan.remediation.engine import RemediationEngine
from agentscan.remediation.git_pr import GitPRAutomator
from agentscan.remediation.models import FixAction, FixPlan

runner = CliRunner()


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


def test_plan_provenance_links_every_action_to_its_finding(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("langchain==0.0.120\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        '[project]\ndependencies = ["langchain==0.0.120"]\n', encoding="utf-8"
    )
    plan = RemediationEngine(tmp_path).plan([_sc001()])

    provenance = plan.provenance_map()

    entry = provenance["SC-001"]
    assert entry["finding_id"] == "SC-001"
    assert entry["actions"] == list(range(1, len(plan.actions) + 1))
    assert set(entry["paths"]) == {"requirements.txt", "pyproject.toml"}
    assert entry["kinds"] == ["pin_bump"]
    planned = sorted(index for item in provenance.values() for index in item["actions"])
    assert planned == list(range(1, len(plan.actions) + 1))


def test_provenance_paths_are_repo_relative(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("langchain==0.0.120\n", encoding="utf-8")
    plan = RemediationEngine(tmp_path).plan([_sc001()])

    for entry in plan.provenance_map().values():
        for path in entry["paths"]:
            assert not Path(path).is_absolute()
            assert "\\" not in path
            assert str(tmp_path) not in path


def test_provenance_groups_actions_by_finding(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("one\n", encoding="utf-8")
    (tmp_path / "policy.yml").write_text("two\n", encoding="utf-8")
    plan = FixPlan(
        actions=[
            FixAction(
                path=str(tmp_path / "requirements.txt"),
                kind="pin_bump",
                finding_id="SC-001",
                before="one\n",
                after="one-fixed\n",
            ),
            FixAction(
                path=str(tmp_path / "policy.yml"),
                kind="guardrails",
                finding_id="ATK-009",
                before="two\n",
                after="two-fixed\n",
            ),
        ]
    )
    plan.bind_root(tmp_path)

    provenance = plan.provenance_map()

    assert provenance["SC-001"]["paths"] == ["requirements.txt"]
    assert provenance["ATK-009"]["paths"] == ["policy.yml"]
    assert provenance["SC-001"]["actions"] == [1]
    assert provenance["ATK-009"]["actions"] == [2]


def test_pr_body_renders_finding_to_action_provenance() -> None:
    plan = FixPlan(
        actions=[
            FixAction(
                path="src/agent.py",
                kind="ast_patch",
                finding_id="SC-014",
                before="DEBUG = True\n",
                after="DEBUG = False\n",
            ),
            FixAction(
                path="requirements.txt",
                kind="pin_bump",
                finding_id="SC-001",
                before="langchain==0.0.120\n",
                after="langchain==0.0.155\n",
            ),
        ]
    )

    body = GitPRAutomator(repo_path=Path.cwd()).generate_pr_body(plan)

    assert "Finding to Action Provenance" in body
    assert "| `SC-001` |" in body
    assert "| `SC-014` |" in body
    assert "`src/agent.py`" in body


def test_fix_output_artifact_includes_provenance(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("langchain==0.0.120\n", encoding="utf-8")
    report = tmp_path / "report.json"
    report.write_text(
        json.dumps({"findings": [_sc001().model_dump(mode="json")]}), encoding="utf-8"
    )
    artifact = tmp_path / "plan.json"

    result = runner.invoke(app, ["fix", str(report), "--output", str(artifact)])

    assert result.exit_code == 0, result.output
    data = json.loads(artifact.read_text(encoding="utf-8"))
    assert data["provenance"]["SC-001"]["paths"] == ["requirements.txt"]
    assert data["provenance"]["SC-001"]["kinds"] == ["pin_bump"]
    assert data["provenance"]["SC-001"]["actions"] == [1]
