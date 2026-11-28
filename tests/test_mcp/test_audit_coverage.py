from __future__ import annotations

import json

from agentscan.mcp.server import handle_audit


def test_vulnerable_fixture_not_safe(tmp_path):
    (tmp_path / "requirements.txt").write_text("langchain==0.0.154\n", encoding="utf-8")
    data = json.loads(handle_audit({"path": str(tmp_path), "offline": True}))
    assert not (data["status"] == "SAFE" and data["score"] == 100 and data["findings_count"] == 0)
    assert data["status"] == "INCONCLUSIVE"
    assert data["findings_count"] >= 1


def test_clean_fixture_no_findings(tmp_path):
    (tmp_path / "good.py").write_text("x = 1\n", encoding="utf-8")
    data = json.loads(handle_audit({"path": str(tmp_path), "offline": True}))
    assert data["findings_count"] == 0


def test_mcp_cli_agree(tmp_path):
    from typer.testing import CliRunner

    from agentscan.cli import app

    (tmp_path / "requirements.txt").write_text("langchain==0.0.154\n", encoding="utf-8")
    mcp_data = json.loads(handle_audit({"path": str(tmp_path), "offline": True}))
    out = tmp_path / "cli.json"
    result = CliRunner().invoke(app, ["audit", str(tmp_path), "--offline", "--output", str(out)])
    assert result.exit_code == 0, result.output
    cli_data = json.loads(out.read_text())
    assert mcp_data["status"] == cli_data["status"]
    assert mcp_data["findings_count"] == len(cli_data["findings"])
    assert len(mcp_data["coverage"]) == len(cli_data["audit_coverage"])
