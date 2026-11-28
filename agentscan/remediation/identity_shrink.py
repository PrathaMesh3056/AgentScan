# agentscan/remediation/identity_shrink.py
#
# Identity and RBAC least-privilege policy shrinking:
#   ID-001, ID-002: Remove over-privileged or undeclared tool scopes from *.agent.json
#   SC-020: Strip shell execution scope from mcp_config.json
#
# Each shrink is scoped to the finding's manifest_path/agent_id. Scopes are
# evaluated against THAT agent's declared role; an allowed scope is never
# removed, and one agent's finding is never applied to another manifest.

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from agentscan.core.models import Finding
from agentscan.remediation.models import FixAction
from agentscan.remediation.paths import contained_path


def _manifest_data(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _allowed_scopes_for(manifest: dict[str, Any]) -> set[str]:
    """Return the set of scopes allowed for this manifest's declared role."""
    role_name = manifest.get("declared_role")
    if not isinstance(role_name, str) or not role_name:
        return set()
    try:
        from agentscan.identity.permission_mapper import load_role_policies

        roles = load_role_policies()
    except Exception:
        return set()
    role = roles.get(role_name)
    if role is None:
        return set()
    return set(getattr(role, "allowed_scopes", []) or [])


def _target_manifests_for_finding(
    finding: Finding,
    manifest_paths: list[Path],
    manifest_data: dict[Path, dict[str, Any]],
    root_path: Path,
) -> list[Path]:
    """Return the subset of manifests this finding applies to."""
    ref = None
    for key in ("manifest_path", "file", "path"):
        value = finding.metadata.get(key)
        if isinstance(value, str) and value.strip():
            ref = value.strip()
            break

    if ref is not None:
        try:
            if Path(ref).is_absolute():
                target = Path(ref).resolve()
            else:
                target = contained_path(root_path, ref)
        except Exception:
            target = Path(ref)
        matched: list[Path] = []
        for mp in manifest_paths:
            try:
                if mp.resolve() == target.resolve():
                    matched.append(mp)
                    continue
            except Exception:
                pass
            if mp.name == target.name:
                matched.append(mp)
        return matched

    agent_id = finding.metadata.get("agent_id")
    if isinstance(agent_id, str) and agent_id.strip():
        matched = []
        any_with_agent_id = False
        for mp in manifest_paths:
            md = manifest_data.get(mp, {})
            manifest_agent_id = md.get("agent_id")
            if isinstance(manifest_agent_id, str):
                any_with_agent_id = True
                if manifest_agent_id == agent_id:
                    matched.append(mp)
        if any_with_agent_id:
            return matched
        return list(manifest_paths)

    return list(manifest_paths)


def _shrink_agent_manifest(
    manifest_path: Path,
    remove_tools: set[str],
    tool_scopes: dict[str, set[str]],
    global_scopes: set[str],
) -> str | None:
    """Remove flagged tools or capability scopes from one *.agent.json manifest."""
    data = _manifest_data(manifest_path)
    try:
        parsed: dict[str, Any] = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception:
        return None

    tools = parsed.get("tools", [])
    if not isinstance(tools, list):
        return None

    allowed = _allowed_scopes_for(parsed if isinstance(parsed, dict) else data)

    modified = False
    new_tools: list[dict[str, Any]] = []

    for tool in tools:
        if not isinstance(tool, dict):
            new_tools.append(tool)
            continue

        tool_name = tool.get("tool_name", "")
        if isinstance(tool_name, str) and tool_name in remove_tools:
            modified = True
            continue

        scopes = tool.get("capability_scopes", [])
        if isinstance(scopes, list):
            to_remove: set[str] = set()
            if isinstance(tool_name, str) and tool_name in tool_scopes:
                to_remove.update(tool_scopes[tool_name])
            to_remove.update(global_scopes)
            to_remove = {s for s in to_remove if s not in allowed}

            if to_remove:
                pruned_scopes = [s for s in scopes if s not in to_remove]
                if len(pruned_scopes) != len(scopes):
                    if not pruned_scopes:
                        modified = True
                        continue
                    tool["capability_scopes"] = pruned_scopes
                    modified = True

        new_tools.append(tool)

    if not modified:
        return None

    parsed["tools"] = new_tools
    return json.dumps(parsed, indent=2) + "\n"


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

    actions: list[FixAction] = []

    if root_path.is_file() and root_path.name.endswith(".agent.json"):
        manifest_files = [root_path]
    else:
        manifest_files = sorted(root_path.rglob("*.agent.json"))

    manifest_files = [contained_path(root_path, m) for m in manifest_files]
    manifest_data: dict[Path, dict[str, Any]] = {mp: _manifest_data(mp) for mp in manifest_files}

    agent_findings = [f for f in id_findings if f.attack_id.startswith("ID-")]

    removals: dict[Path, dict[str, Any]] = {
        mp: {
            "remove_tools": set(),
            "tool_scopes": defaultdict(set),
            "global_scopes": set(),
            "finding_ids": [],
        }
        for mp in manifest_files
    }

    for f in agent_findings:
        tool_name = f.metadata.get("tool_name")
        scope = f.metadata.get("scope")
        targets = _target_manifests_for_finding(f, manifest_files, manifest_data, root_path)
        for mp in targets:
            bucket = removals[mp]
            bucket["finding_ids"].append(f.attack_id)
            tn = tool_name if isinstance(tool_name, str) and tool_name.strip() else None
            sc = scope if isinstance(scope, str) and scope.strip() else None

            allowed = _allowed_scopes_for(manifest_data.get(mp, {}))
            if sc is not None and sc in allowed:
                sc = None

            if sc is not None:
                if tn is not None:
                    bucket["tool_scopes"][tn].add(sc)
                else:
                    bucket["global_scopes"].add(sc)
            if tn is not None and sc is None and "scope" not in f.metadata:
                bucket["remove_tools"].add(tn)

    for m_path in manifest_files:
        bucket = removals[m_path]
        has_removals = (
            bool(bucket["remove_tools"])
            or bool(bucket["tool_scopes"])
            or bool(bucket["global_scopes"])
        )
        if not has_removals:
            continue
        try:
            original = m_path.read_text(encoding="utf-8")
        except Exception:
            continue
        new_content = _shrink_agent_manifest(
            m_path,
            bucket["remove_tools"],
            {k: set(v) for k, v in bucket["tool_scopes"].items()},
            bucket["global_scopes"],
        )
        if new_content and new_content != original:
            finding_id = sorted(bucket["finding_ids"])[0] if bucket["finding_ids"] else "ID-002"
            actions.append(
                FixAction(
                    path=str(m_path.resolve()),
                    kind="identity_shrink",
                    finding_id=finding_id,
                    before=original,
                    after=new_content,
                    applied=False,
                )
            )

    sc020_present = any(f.attack_id == "SC-020" for f in id_findings)
    if sc020_present:
        if root_path.is_file() and "mcp" in root_path.name.lower():
            mcp_files = [root_path]
        else:
            mcp_files = sorted(root_path.rglob("*mcp*.json"))
        mcp_files = [contained_path(root_path, m) for m in mcp_files]

        for m_path in mcp_files:
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
