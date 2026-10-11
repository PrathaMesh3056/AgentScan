# agentscan/identity/rbac_graph.py
#
# Models agents, tools, credentials, and scopes as a networkx DiGraph and
# emits ID-010 when a low-trust agent can reach a dangerous scope through
# another agent (calls edge) or a shared-credential hop — without duplicating
# per-agent ID-002 / ID-009 findings for direct tool access.

from __future__ import annotations

from typing import TYPE_CHECKING

import networkx as nx
from loguru import logger

from agentscan.core.models import Finding, Severity
from agentscan.identity.models import AgentIdentity, RolePolicy

if TYPE_CHECKING:
    from collections.abc import Iterable


def _agent_node(agent_id: str) -> str:
    return f"agent:{agent_id}"


def _tool_node(agent_id: str, tool_name: str) -> str:
    return f"tool:{agent_id}:{tool_name}"


def _scope_node(scope: str) -> str:
    return f"scope:{scope}"


def _cred_node(credential_ref: str) -> str:
    return f"cred:{credential_ref}"


def _node_agent_id(node: str) -> str | None:
    if node.startswith("agent:"):
        return node[len("agent:") :]
    return None


def build_rbac_graph(
    agents: list[AgentIdentity],
    roles: dict[str, RolePolicy],
    dangerous_keywords: list[str],
) -> nx.DiGraph:
    """Build a directed graph of agents, tools, scopes, and credentials."""
    del roles, dangerous_keywords  # reserved for API symmetry with audit entry point
    graph: nx.DiGraph = nx.DiGraph()
    known_agent_ids = {agent.agent_id for agent in agents}

    for agent in agents:
        agent_node = _agent_node(agent.agent_id)
        graph.add_node(agent_node, node_type="agent", agent_id=agent.agent_id)

        for target_id in agent.calls_agents:
            if target_id not in known_agent_ids:
                logger.debug(
                    f"Agent '{agent.agent_id}' calls unknown agent '{target_id}' — skipping edge"
                )
                continue
            target_node = _agent_node(target_id)
            graph.add_edge(agent_node, target_node, edge_type="calls")

        for tool in agent.tools:
            tool_node = _tool_node(agent.agent_id, tool.tool_name)
            graph.add_node(
                tool_node,
                node_type="tool",
                agent_id=agent.agent_id,
                tool_name=tool.tool_name,
            )
            graph.add_edge(agent_node, tool_node, edge_type="uses")

            for scope in tool.capability_scopes:
                scope_node = _scope_node(scope)
                graph.add_node(scope_node, node_type="scope", scope=scope)
                graph.add_edge(tool_node, scope_node, edge_type="grants")

        if agent.credential_ref is not None:
            cred_node = _cred_node(agent.credential_ref)
            graph.add_node(
                cred_node,
                node_type="cred",
                credential_ref=agent.credential_ref,
            )
            graph.add_edge(cred_node, agent_node, edge_type="authenticates")
            graph.add_edge(agent_node, cred_node, edge_type="authenticated_by")

    return graph


def is_low_trust_agent(
    agent: AgentIdentity,
    roles: dict[str, RolePolicy],
    dangerous_keywords: list[str],
) -> bool:
    """True when the agent is an escalation source (unmatched role or no dangerous tools)."""
    role = roles.get(agent.declared_role) if agent.declared_role else None
    if role is None:
        return True

    for tool in agent.tools:
        haystack = " ".join([tool.tool_name, *tool.capability_scopes]).lower()
        for keyword in dangerous_keywords:
            if keyword.lower() in haystack:
                return False
    return True


def scope_matches_dangerous_keyword(scope: str, dangerous_keywords: list[str]) -> bool:
    lowered = scope.lower()
    return any(keyword.lower() in lowered for keyword in dangerous_keywords)


def _dangerous_scope_nodes(graph: nx.DiGraph, dangerous_keywords: list[str]) -> list[str]:
    scopes: list[str] = []
    for node, data in graph.nodes(data=True):
        if data.get("node_type") != "scope":
            continue
        scope = data.get("scope", "")
        if scope_matches_dangerous_keyword(scope, dangerous_keywords):
            scopes.append(node)
    return scopes


def _path_has_inter_agent_hop(graph: nx.DiGraph, path: list[str], source_agent_id: str) -> bool:
    for index in range(len(path) - 1):
        source = path[index]
        target = path[index + 1]
        edge_type = graph.edges[source, target].get("edge_type")

        if edge_type == "calls":
            return True

        if edge_type == "authenticated_by" and target.startswith("cred:") and index + 2 < len(path):
            next_node = path[index + 2]
            next_agent = _node_agent_id(next_node)
            if next_agent is not None and next_agent != source_agent_id:
                return True

        if edge_type == "authenticates" and source.startswith("cred:"):
            target_agent = _node_agent_id(target)
            if target_agent is not None and target_agent != source_agent_id:
                return True

    return False


def find_escalation_paths(
    graph: nx.DiGraph,
    agents: list[AgentIdentity],
    roles: dict[str, RolePolicy],
    dangerous_keywords: list[str],
) -> list[Finding]:
    """Return ID-010 findings for multi-hop privilege escalation paths."""
    agents_by_id = {agent.agent_id: agent for agent in agents}
    dangerous_scopes = _dangerous_scope_nodes(graph, dangerous_keywords)
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()

    for agent in agents:
        if not is_low_trust_agent(agent, roles, dangerous_keywords):
            continue

        source_node = _agent_node(agent.agent_id)
        if source_node not in graph:
            continue

        for scope_node in dangerous_scopes:
            scope = graph.nodes[scope_node].get("scope", scope_node[len("scope:") :])
            if scope in agent.all_scopes():
                continue

            pair = (agent.agent_id, scope)
            if pair in seen:
                continue

            try:
                path = nx.shortest_path(graph, source_node, scope_node)
            except nx.NetworkXNoPath:
                continue

            if not _path_has_inter_agent_hop(graph, path, agent.agent_id):
                continue

            seen.add(pair)
            findings.append(
                _escalation_finding(
                    source_agent=agents_by_id[agent.agent_id],
                    scope=scope,
                    path=path,
                )
            )

    return findings


def audit_rbac_graph(
    agents: list[AgentIdentity],
    roles: dict[str, RolePolicy],
    dangerous_keywords: list[str],
) -> list[Finding]:
    """Build the RBAC graph and run multi-hop escalation detection."""
    graph = build_rbac_graph(agents, roles, dangerous_keywords)
    return find_escalation_paths(graph, agents, roles, dangerous_keywords)


def graph_to_view(graph: nx.DiGraph) -> dict[str, object]:
    """Serialize an RBAC DiGraph for the local UI / JSON APIs."""
    nodes = [{"id": node_id, **dict(data)} for node_id, data in graph.nodes(data=True)]
    edges = [
        {"source": source, "target": target, **dict(data)}
        for source, target, data in graph.edges(data=True)
    ]
    return {"nodes": nodes, "edges": edges}


def _escalation_finding(source_agent: AgentIdentity, scope: str, path: Iterable[str]) -> Finding:
    path_list = list(path)
    hop_count = len(path_list) - 1
    path_str = " -> ".join(path_list)
    return Finding(
        attack_id="ID-010",
        attack_name="Multi-hop privilege escalation",
        severity=Severity.CRITICAL,
        owasp_id="LLM06",
        description=(
            f"Low-trust agent '{source_agent.agent_id}' can reach dangerous scope "
            f"'{scope}' through another agent or a shared credential "
            f"({hop_count} hop(s))."
        ),
        evidence=(
            f"agent_id={source_agent.agent_id}, scope={scope}, "
            f"path={path_str}, hop_count={hop_count}"
        ),
        remediation=(
            f"Remove or restrict cross-agent calls and shared credentials for "
            f"'{source_agent.agent_id}', and ensure scope '{scope}' is not "
            f"reachable via indirect paths."
        ),
        metadata={
            "agent_id": source_agent.agent_id,
            "scope": scope,
            "path": path_list,
            "hop_count": hop_count,
            "manifest_path": source_agent.manifest_path,
        },
    )
