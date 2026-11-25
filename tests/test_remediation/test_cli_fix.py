# tests/test_remediation/test_cli_fix.py

import json
from pathlib import Path

from typer.testing import CliRunner

from agentscan.cli import app

runner = CliRunner()


def test_cli_fix_dry_run_and_apply(tmp_path: Path) -> None:
    code_file = tmp_path / "app.py"
    code_file.write_text("DEBUG = True\n", encoding="utf-8")

    # 1. Dry run
    res = runner.invoke(app, ["fix", str(tmp_path)])
    assert res.exit_code == 0
    assert "Planned" in res.output
    assert "DEBUG = False" in res.output
    assert "Dry-run mode" in res.output
    # File not modified yet
    assert code_file.read_text(encoding="utf-8") == "DEBUG = True\n"

    # 2. Apply mode
    res_apply = runner.invoke(app, ["fix", str(tmp_path), "--apply"])
    assert res_apply.exit_code == 0
    assert "Successfully applied" in res_apply.output
    # File is now modified
    assert code_file.read_text(encoding="utf-8") == "DEBUG = False\n"


def test_cli_fix_from_json_report(tmp_path: Path) -> None:
    req = tmp_path / "requirements.txt"
    req.write_text("langchain==0.0.120\n", encoding="utf-8")

    report_file = tmp_path / "report.json"
    report_data = {
        "findings": [
            {
                "attack_id": "SC-001",
                "attack_name": "Known-vulnerable dependency",
                "severity": "HIGH",
                "owasp_id": "LLM05",
                "description": "Dependency 'langchain==0.0.120' is vulnerable. Upgrade to >=0.0.155.",
                "evidence": "pkg=langchain",
                "metadata": {
                    "package": "langchain",
                    "version": "0.0.120",
                    "fix_version": "0.0.155",
                },
            }
        ]
    }
    report_file.write_text(json.dumps(report_data), encoding="utf-8")

    plan_output = tmp_path / "plan.json"
    res = runner.invoke(
        app,
        ["fix", str(report_file), "--apply", "--output", str(plan_output)],
    )
    assert res.exit_code == 0
    assert "Successfully applied" in res.output
    assert "langchain==0.0.155" in req.read_text(encoding="utf-8")
    assert plan_output.exists()
