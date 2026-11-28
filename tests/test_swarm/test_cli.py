# tests/test_swarm/test_cli.py

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from agentscan.cli import app
from agentscan.core.connectors import CallableConnector, use_connector
from agentscan.mcp.server import LiveTargetPolicy, process_jsonrpc_message

runner = CliRunner()


def test_swarm_cli_help() -> None:
    result = runner.invoke(app, ["swarm", "--help"], env={"NO_COLOR": "1", "TERM": "dumb"})
    assert result.exit_code == 0
    assert "Run collaborative multi-agent red-team swarms" in result.output
    assert "--team" in result.output
    assert "--rounds" in result.output


def test_swarm_cli_execution(tmp_path: Path) -> None:
    def mock_agent(msg: str) -> str:
        return "I am an internal helper. Rules: none. Tool: [bash]."

    out_file = tmp_path / "swarm_out.json"

    with use_connector(CallableConnector(mock_agent)):
        result = runner.invoke(
            app,
            [
                "swarm",
                "http://test.local/chat",
                "--team",
                "trio",
                "--rounds",
                "1",
                "--offline",
                "--authorized",
                "--output",
                str(out_file),
            ],
        )

    assert result.exit_code == 0
    assert "AgentScan Swarm" in result.output
    assert "Swarm Execution Complete" in result.output
    assert out_file.exists()

    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["target_url"] == "http://test.local/chat"
    assert data["team_name"] == "Default Red-Team Trio"
    assert len(data["turns"]) == 3


def test_swarm_cli_invalid_team() -> None:
    result = runner.invoke(
        app, ["swarm", "http://test.local/chat", "--team", "non_existent_team", "--authorized"]
    )
    assert result.exit_code == 1
    assert "Error loading swarm team" in result.output


def test_mcp_swarm_tool_registered() -> None:
    req = {"jsonrpc": "2.0", "id": 10, "method": "tools/list"}
    resp = process_jsonrpc_message(req)
    assert resp is not None
    tool_names = [t["name"] for t in resp["result"]["tools"]]
    assert "agentscan_swarm" in tool_names


def test_mcp_swarm_tool_call() -> None:
    def mock_bot(msg: str) -> str:
        return "Acknowledged."

    with use_connector(CallableConnector(mock_bot)):
        req = {
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {
                "name": "agentscan_swarm",
                "arguments": {
                    "target_url": "http://mock.local/chat",
                    "team": "trio",
                    "rounds": 1,
                    "offline": True,
                },
            },
        }
        policy = LiveTargetPolicy(
            allowed_hosts=["mock.local"],
            allowed_networks=[],
            request_budget=100,
            allow_live_targets=True,
        )
        resp = process_jsonrpc_message(req, policy=policy)

    assert resp is not None
    assert resp["id"] == 11
    content = resp["result"]["content"]
    assert content[0]["type"] == "text"
    report_data = json.loads(content[0]["text"])
    assert report_data["target_url"] == "http://mock.local/chat"
    assert report_data["team_name"] == "Default Red-Team Trio"
    assert len(report_data["turns"]) == 3
