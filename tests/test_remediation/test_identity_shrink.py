# tests/test_remediation/test_identity_shrink.py

import json
from pathlib import Path

from agentscan.core.models import Finding, Severity
from agentscan.remediation.identity_shrink import plan_identity_shrinks


def test_identity_shrink_agent_manifest(tmp_path: Path) -> None:
    manifest = tmp_path / "bot.agent.json"
    data = {
        "agent_id": "support_bot",
        "tools": [
            {"tool_name": "send_email", "capability_scopes": ["send_email"]},
            {"tool_name": "execute_shell", "capability_scopes": ["shell"]},
        ],
    }
    manifest.write_text(json.dumps(data, indent=2), encoding="utf-8")

    finding = Finding(
        attack_id="ID-002",
        attack_name="Over-privileged tool scope",
        severity=Severity.HIGH,
        owasp_id="LLM08",
        description="Tool 'execute_shell' has disallowed scope 'shell'.",
        evidence="tool=execute_shell",
        metadata={"agent_id": "support_bot", "tool_name": "execute_shell", "scope": "shell"},
    )

    actions = plan_identity_shrinks([finding], tmp_path)
    assert len(actions) == 1
    action = actions[0]
    assert action.kind == "identity_shrink"
    updated_data = json.loads(action.after)
    tool_names = [t["tool_name"] for t in updated_data["tools"]]
    assert "send_email" in tool_names
    assert "execute_shell" not in tool_names


def test_identity_shrink_mcp_config(tmp_path: Path) -> None:
    mcp_cfg = tmp_path / "mcp_config.json"
    data = {
        "mcpServers": {
            "sqlite": {"command": "uvx", "scopes": ["db:read", "shell"]},
        }
    }
    mcp_cfg.write_text(json.dumps(data, indent=2), encoding="utf-8")

    finding = Finding(
        attack_id="SC-020",
        attack_name="Excessive MCP Server Scope",
        severity=Severity.CRITICAL,
        owasp_id="LLM07",
        description="MCP server granted shell scope.",
        evidence="scope=shell",
    )

    actions = plan_identity_shrinks([finding], tmp_path)
    assert len(actions) == 1
    updated = json.loads(actions[0].after)
    scopes = updated["mcpServers"]["sqlite"]["scopes"]
    assert "db:read" in scopes
    assert "shell" not in scopes
