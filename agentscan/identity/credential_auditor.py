# agentscan/identity/credential_auditor.py
#
# Detects when two or more agents share the same credential_ref.
# This is the #1 gap 2026 AI agent security surveys keep finding:
# most production deployments have no independent identity per agent —
# just one shared API key with no accountable trail back to which
# agent actually made a given call.
#
# Rule #12 (IDE context): never invent credential_ref. Any AgentIdentity
# with credential_ref=None is silently excluded here — a false "shared
# credential" finding is worse than a missed one for this specific check.

from __future__ import annotations

from collections import defaultdict

from agentscan.core.models import Finding, Severity
from agentscan.identity.models import AgentIdentity


def audit_credentials(agents: list[AgentIdentity]) -> list[Finding]:
    """
    Group all agents by credential_ref. Any group with 2+ distinct
    agent_ids produces exactly one CRITICAL Finding naming every agent
    in that group.

    Agents with credential_ref=None are skipped entirely — we never
    guess which credential an under-specified manifest is using.
    """
    groups: dict[str, list[AgentIdentity]] = defaultdict(list)

    for agent in agents:
        if agent.credential_ref is None:
            continue
        groups[agent.credential_ref].append(agent)

    findings: list[Finding] = []
    for credential_ref, group in groups.items():
        if len(group) < 2:
            continue

        agent_ids = [a.agent_id for a in group]
        findings.append(_shared_credential_finding(credential_ref, agent_ids, group))

    return findings


def _shared_credential_finding(
    credential_ref: str,
    agent_ids: list[str],
    group: list[AgentIdentity],
) -> Finding:
    agent_list = ", ".join(f"'{aid}'" for aid in agent_ids)
    return Finding(
        attack_id="ID-005",
        attack_name="Shared credential across agents",
        severity=Severity.CRITICAL,
        owasp_id="LLM08",
        description=(
            f"Agents {agent_list} all authenticate with credential "
            f"'{credential_ref}' — no independent identity, no accountable "
            f"trail back to which agent performed a given action."
        ),
        evidence=(f"credential_ref={credential_ref} shared by {len(group)} agents: {agent_ids}"),
        remediation=(
            f"Issue each of {agent_list} its own credential/token so actions "
            f"can be attributed to a single accountable identity. Rotate "
            f"'{credential_ref}' after splitting."
        ),
        metadata={
            "credential_ref": credential_ref,
            "agent_ids": agent_ids,
            "manifest_paths": [a.manifest_path for a in group],
        },
    )
