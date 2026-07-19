# agentscan/identity/permission_mapper.py
#
# Compares each AgentIdentity's declared tool scopes against the
# least-privilege baseline in identity/policies/roles.yaml.
#
# Two paths:
#   1. declared_role matches a known role  -> baseline comparison
#   2. declared_role is None / unknown     -> dangerous-keyword fallback
#
# "Silence is not permission": a scope that is simply absent from
# allowed_scopes is flagged even if it isn't explicitly in disallowed_scopes.
# That's why ID-002 fires for delete_customer_record even though
# customer_support_agent's disallowed_scopes list doesn't happen to name it.

from __future__ import annotations

from pathlib import Path

import yaml
from loguru import logger

from agentscan.core.models import Finding, Severity
from agentscan.identity.models import AgentIdentity, RolePolicy

POLICY_FILE = Path(__file__).parent / "policies" / "roles.yaml"


def load_role_policies(policy_file: Path = POLICY_FILE) -> dict[str, RolePolicy]:
    """
    Load roles.yaml into a dict keyed by role name for O(1) lookup.
    Returns an empty dict if the file is missing — callers then treat
    every agent as having an unmatched role (safe default: more scrutiny,
    not less).
    """
    if not policy_file.exists():
        logger.error(f"Role policy file not found: {policy_file}")
        return {}

    with open(policy_file, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    roles = data.get("roles", [])
    return {r["role"]: RolePolicy(**r) for r in roles}


def load_dangerous_keywords(policy_file: Path = POLICY_FILE) -> list[str]:
    """Load the fallback dangerous-capability keyword list from roles.yaml."""
    if not policy_file.exists():
        return []

    with open(policy_file, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    return data.get("dangerous_capability_keywords", [])


def map_permissions(
    agent: AgentIdentity,
    roles: dict[str, RolePolicy],
    dangerous_keywords: list[str],
) -> list[Finding]:
    """
    Return all ID-* Findings for one agent.

    - If declared_role matches a known role: compare every capability_scope
      against that role's allowed_scopes / disallowed_scopes.
    - Otherwise: emit ID-008 (no scope declaration) plus any dangerous-
      keyword matches found in the agent's own tool names / scopes.
    """
    findings: list[Finding] = []

    role = roles.get(agent.declared_role) if agent.declared_role else None

    if role is None:
        findings.append(_no_scope_declaration_finding(agent))
        findings.extend(_dangerous_keyword_findings(agent, dangerous_keywords))
        return findings

    for tool in agent.tools:
        for scope in tool.capability_scopes:
            if scope in role.disallowed_scopes:
                findings.append(
                    _over_privileged_finding(
                        agent,
                        tool.tool_name,
                        scope,
                        role.role,
                        reason="explicitly disallowed for this role",
                    )
                )
            elif scope not in role.allowed_scopes:
                findings.append(
                    _over_privileged_finding(
                        agent,
                        tool.tool_name,
                        scope,
                        role.role,
                        reason="not declared in this role's allowed scopes",
                    )
                )

    return findings


# ── Finding builders ──────────────────────────────────────────────────────────


def _over_privileged_finding(
    agent: AgentIdentity,
    tool_name: str,
    scope: str,
    role: str,
    reason: str,
) -> Finding:
    return Finding(
        attack_id="ID-002",
        attack_name="Over-privileged tool",
        severity=Severity.CRITICAL,
        owasp_id="LLM08",
        description=(
            f"Agent '{agent.agent_id}' has access to '{tool_name}' "
            f"(scope '{scope}') which is {reason} "
            f"(declared role: {role})."
        ),
        evidence=f"agent_id={agent.agent_id}, tool={tool_name}, scope={scope}, role={role}",
        remediation=(
            f"Remove '{scope}' from agent '{agent.agent_id}', or update "
            f"'{role}' in identity/policies/roles.yaml if this access is intentional."
        ),
        metadata={
            "agent_id": agent.agent_id,
            "tool_name": tool_name,
            "scope": scope,
            "declared_role": role,
            "manifest_path": agent.manifest_path,
        },
    )


def _no_scope_declaration_finding(agent: AgentIdentity) -> Finding:
    tool_count = len(agent.tools)
    return Finding(
        attack_id="ID-008",
        attack_name="No scope declaration",
        severity=Severity.HIGH,
        owasp_id="LLM08",
        description=(
            f"Agent '{agent.agent_id}' has {tool_count} registered tool(s) "
            f"with no policy baseline defined — declared_role is missing "
            f"or does not match any entry in identity/policies/roles.yaml."
        ),
        evidence=f"agent_id={agent.agent_id}, declared_role={agent.declared_role!r}, tool_count={tool_count}",
        remediation=(
            f"Add a 'declared_role' matching an entry in roles.yaml for "
            f"'{agent.agent_id}', or add a new role policy covering its actual needs."
        ),
        metadata={"agent_id": agent.agent_id, "manifest_path": agent.manifest_path},
    )


def _dangerous_keyword_findings(
    agent: AgentIdentity, dangerous_keywords: list[str]
) -> list[Finding]:
    """
    For agents with no matched role: scan every tool_name and every
    capability_scope for a dangerous-keyword substring match.
    This is the safety net for undeclared agents that also happen to
    hold high-risk capabilities.
    """
    findings: list[Finding] = []
    seen: set[str] = set()  # avoid duplicate findings for the same tool

    for tool in agent.tools:
        haystack = " ".join([tool.tool_name, *tool.capability_scopes]).lower()
        for keyword in dangerous_keywords:
            if keyword.lower() in haystack and tool.tool_name not in seen:
                seen.add(tool.tool_name)
                findings.append(
                    Finding(
                        attack_id="ID-009",
                        attack_name="Dangerous capability on undeclared agent",
                        severity=Severity.CRITICAL,
                        owasp_id="LLM08",
                        description=(
                            f"Agent '{agent.agent_id}' has no declared role but "
                            f"holds tool '{tool.tool_name}' matching the "
                            f"dangerous-capability keyword '{keyword}'."
                        ),
                        evidence=f"agent_id={agent.agent_id}, tool={tool.tool_name}, keyword={keyword}",
                        remediation=(
                            f"Declare a role for '{agent.agent_id}' immediately and "
                            f"confirm '{tool.tool_name}' is genuinely required."
                        ),
                        metadata={
                            "agent_id": agent.agent_id,
                            "tool_name": tool.tool_name,
                            "matched_keyword": keyword,
                        },
                    )
                )
    return findings
