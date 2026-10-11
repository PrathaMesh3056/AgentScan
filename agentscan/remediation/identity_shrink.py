# agentscan/remediation/identity_shrink.py
#
# Identity and RBAC least-privilege policy shrinking:
#   ID-001, ID-002: Remove over-privileged or undeclared tool scopes from *.agent.json
#   SC-020: Strip shell execution scope from mcp_config.json

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agentscan.core.models import Finding
from agentscan.remediation.models import FixAction
from agentscan.remediation.paths import contained_path


def _shrink_agent_manifest(
    manifest_path: Path,
    flagged_tools: set[str],
    flagged_scopes: set[str],
) -> str | None:
    """Remove flagged tools or capability scopes from an *.agent.json manifest."""
    try:
        data: dict[str, Any] = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception:
        return None

    tools = data.get("tools", [])
    if not isinstance(tools, list):
        return None

    modified = False
    new_tools: list[dict[str, Any]] = []

    for tool in tools:
        if not isinstance(tool, dict):
            new_tools.append(tool)
            continue

        tool_name = tool.get("tool_name", "")
        # If the entire tool was flagged as over-privileged, drop it
        if tool_name in flagged_tools:
            modified = True
            continue

        # If specific scopes inside the tool were flagged, prune them
        scopes = tool.get("capability_scopes", [])
        if isinstance(scopes, list):
            pruned_scopes = [s for s in scopes if s not in flagged_scopes]
            if len(pruned_scopes) != len(scopes):
                tool["capability_scopes"] = pruned_scopes
                modified = True

        new_tools.append(tool)

    if not modified:
        return None

    data["tools"] = new_tools
    return json.dumps(data, indent=2) + "\n"


def _shrink_mcp_config(config_path: Path) -> str | None:
    """Sanitize dangerous scopes (e.g. shell) in mcp_config.json."""
    try:
        data: dict[str, Any] = json.loads(config_path.read_text(encoding="utf-8"))
    except Exception:
        return None

    modified = False
    servers = data.get("mcpServers", {})
    if isinstance(servers, dict):
        for s_cfg in servers.values():
            if isinstance(s_cfg, dict):
                scopes = s_cfg.get("scopes", [])
                if isinstance(scopes, list) and "shell" in scopes:
                    s_cfg["scopes"] = [s for s in scopes if s != "shell"]
                    modified = True

    if not modified:
        return None

    return json.dumps(data, indent=2) + "\n"


def plan_identity_shrinks(findings: list[Finding], root_path: Path) -> list[FixAction]:
    """Generate identity_shrink FixActions for ID-* and SC-020 findings."""
    id_findings = [f for f in findings if f.attack_id.startswith("ID-") or f.attack_id == "SC-020"]
    if not id_findings or not root_path.exists():
        return []

    flagged_tools: set[str] = set()
    flagged_scopes: set[str] = set()

    for f in id_findings:
        if "tool_name" in f.metadata:
            flagged_tools.add(str(f.metadata["tool_name"]))
        if "scope" in f.metadata:
            flagged_scopes.add(str(f.metadata["scope"]))

    actions: list[FixAction] = []

    # 1. Search for *.agent.json files
    manifest_files = (
        [root_path]
        if root_path.is_file() and root_path.name.endswith(".agent.json")
        else list(root_path.rglob("*.agent.json"))
    )

    for m_path in manifest_files:
        m_path = contained_path(root_path, m_path)
        try:
            original = m_path.read_text(encoding="utf-8")
        except Exception:
            continue
        new_content = _shrink_agent_manifest(m_path, flagged_tools, flagged_scopes)
        if new_content and new_content != original:
            actions.append(
                FixAction(
                    path=str(m_path.resolve()),
                    kind="identity_shrink",
                    finding_id=id_findings[0].attack_id,
                    before=original,
                    after=new_content,
                    applied=False,
                )
            )

    # 2. Search for mcp_config.json
    mcp_files = (
        [root_path]
        if root_path.is_file() and "mcp" in root_path.name.lower()
        else list(root_path.rglob("*mcp*.json"))
    )

    for m_path in mcp_files:
        m_path = contained_path(root_path, m_path)
        try:
            original = m_path.read_text(encoding="utf-8")
        except Exception:
            continue
        new_content = _shrink_mcp_config(m_path)
        if new_content and new_content != original:
            actions.append(
                FixAction(
                    path=str(m_path.resolve()),
                    kind="identity_shrink",
                    finding_id="SC-020",
                    before=original,
                    after=new_content,
                    applied=False,
                )
            )

    return actions
