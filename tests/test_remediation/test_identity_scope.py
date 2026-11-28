# tests/test_remediation/test_identity_scope.py

import json
from pathlib import Path

from agentscan.core.models import Finding, Severity
from agentscan.remediation.identity_shrink import plan_identity_shrinks


def _write_manifest(path: Path, agent_id: str, tools: list[dict]) -> None:
    path.write_text(
        json.dumps({"agent_id": agent_id, "tools": tools}, indent=2),
        encoding="utf-8",
    )


def test_flagged_agent_loses_only_flagged_scope(tmp_path: Path) -> None:
    flagged = tmp_path / "flagged.agent.json"
    _write_manifest(
        flagged,
        "flagged",
        [
            {
                "tool_name": "send_email",
                "capability_scopes": ["send_email", "shell"],
            }
        ],
    )

    finding = Finding(
        attack_id="ID-002",
        attack_name="Over-privileged tool scope",
        severity=Severity.HIGH,
        owasp_id="LLM06",
        description="Tool 'send_email' has disallowed scope 'shell'.",
        evidence="tool=send_email",
        metadata={
            "agent_id": "flagged",
            "manifest_path": str(flagged),
            "tool_name": "send_email",
            "scope": "shell",
        },
    )

    actions = plan_identity_shrinks([finding], tmp_path)
    assert len(actions) == 1
    updated = json.loads(actions[0].after)
    tool = updated["tools"][0]
    assert tool["tool_name"] == "send_email"
    assert tool["capability_scopes"] == ["send_email"]


def test_unrelated_agent_keeps_its_tool(tmp_path: Path) -> None:
    flagged = tmp_path / "flagged.agent.json"
    unrelated = tmp_path / "unrelated.agent.json"
    _write_manifest(
        flagged,
        "flagged",
        [{"tool_name": "run_shell", "capability_scopes": ["shell"]}],
    )
    _write_manifest(
        unrelated,
        "unrelated",
        [{"tool_name": "run_shell", "capability_scopes": ["shell"]}],
    )

    finding = Finding(
        attack_id="ID-002",
        attack_name="Over-privileged tool scope",
        severity=Severity.HIGH,
        owasp_id="LLM06",
        description="Tool 'run_shell' has disallowed scope 'shell'.",
        evidence="tool=run_shell",
        metadata={
            "agent_id": "flagged",
            "manifest_path": str(flagged),
            "tool_name": "run_shell",
            "scope": "shell",
        },
    )

    actions = plan_identity_shrinks([finding], tmp_path)
    assert len(actions) == 1
    assert Path(actions[0].path).name == "flagged.agent.json"
    # Unrelated manifest is untouched (no action for it).
    assert all(Path(a.path).name != "unrelated.agent.json" for a in actions)
    unrelated_after = json.loads(unrelated.read_text(encoding="utf-8"))
    assert unrelated_after["tools"][0]["capability_scopes"] == ["shell"]


def test_shared_scope_does_not_cross_contaminate(tmp_path: Path) -> None:
    agent_a = tmp_path / "a.agent.json"
    agent_b = tmp_path / "b.agent.json"
    _write_manifest(
        agent_a,
        "agent_a",
        [{"tool_name": "tool_a", "capability_scopes": ["shared", "a_only"]}],
    )
    _write_manifest(
        agent_b,
        "agent_b",
        [{"tool_name": "tool_b", "capability_scopes": ["shared", "b_only"]}],
    )

    finding = Finding(
        attack_id="ID-002",
        attack_name="Over-privileged tool scope",
        severity=Severity.HIGH,
        owasp_id="LLM06",
        description="Tool 'tool_a' has disallowed scope 'shared'.",
        evidence="tool=tool_a",
        metadata={
            "agent_id": "agent_a",
            "manifest_path": str(agent_a),
            "tool_name": "tool_a",
            "scope": "shared",
        },
    )

    actions = plan_identity_shrinks([finding], tmp_path)
    assert len(actions) == 1

    a_data = json.loads(actions[0].after)
    assert a_data["tools"][0]["capability_scopes"] == ["a_only"]

    b_data = json.loads(agent_b.read_text(encoding="utf-8"))
    assert b_data["tools"][0]["capability_scopes"] == ["shared", "b_only"]


def test_idempotent_plan(tmp_path: Path) -> None:
    flagged = tmp_path / "flagged.agent.json"
    _write_manifest(
        flagged,
        "flagged",
        [{"tool_name": "run_shell", "capability_scopes": ["shell"]}],
    )
    finding = Finding(
        attack_id="ID-002",
        attack_name="Over-privileged tool scope",
        severity=Severity.HIGH,
        owasp_id="LLM06",
        description="Tool 'run_shell' has disallowed scope 'shell'.",
        evidence="tool=run_shell",
        metadata={
            "agent_id": "flagged",
            "manifest_path": str(flagged),
            "tool_name": "run_shell",
            "scope": "shell",
        },
    )
    first = plan_identity_shrinks([finding], tmp_path)
    assert len(first) == 1
    flagged.write_text(first[0].after, encoding="utf-8")
    second = plan_identity_shrinks([finding], tmp_path)
    assert second == []
