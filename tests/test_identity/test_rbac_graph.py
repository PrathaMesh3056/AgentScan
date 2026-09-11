# tests/test_identity/test_rbac_graph.py
#
# Unit tests for the networkx RBAC graph auditor (ID-010).

from __future__ import annotations

from agentscan.core.models import Severity
from agentscan.identity.models import AgentIdentity, RolePolicy, ToolPermission
from agentscan.identity.rbac_graph import (
    audit_rbac_graph,
    build_rbac_graph,
    find_escalation_paths,
    is_low_trust_agent,
)


def _triage_agent(**overrides: object) -> AgentIdentity:
    defaults: dict[str, object] = {
        "agent_id": "triage",
        "declared_role": None,
        "tools": [ToolPermission(tool_name="web_search", capability_scopes=["web_search"])],
        "credential_ref": "SHARED_KEY",
        "calls_agents": [],
        "manifest_path": "fake/triage.agent.json",
    }
    defaults.update(overrides)
    return AgentIdentity(**defaults)  # type: ignore[arg-type]


def _dba_agent(**overrides: object) -> AgentIdentity:
    defaults: dict[str, object] = {
        "agent_id": "dba",
        "declared_role": "coding_agent",
        "tools": [
            ToolPermission(
                tool_name="sql_runner",
                capability_scopes=["exec_sql"],
            )
        ],
        "credential_ref": "SHARED_KEY",
        "calls_agents": [],
        "manifest_path": "fake/dba.agent.json",
    }
    defaults.update(overrides)
    return AgentIdentity(**defaults)  # type: ignore[arg-type]


class TestBuildRbacGraph:
    def test_graph_contains_expected_node_and_edge_types(self) -> None:
        triage = _triage_agent(calls_agents=["dba"])
        dba = _dba_agent()
        roles = {"coding_agent": RolePolicy(role="coding_agent", allowed_scopes=["exec_sql"])}
        keywords = ["exec_", "delete_"]

        graph = build_rbac_graph([triage, dba], roles, keywords)

        assert _agent_node("triage") in graph
        assert _tool_node("dba", "sql_runner") in graph
        assert _scope_node("exec_sql") in graph
        assert _cred_node("SHARED_KEY") in graph

        assert graph.edges[_agent_node("triage"), _agent_node("dba")]["edge_type"] == "calls"
        assert (
            graph.edges[_agent_node("dba"), _tool_node("dba", "sql_runner")]["edge_type"] == "uses"
        )
        assert (
            graph.edges[_tool_node("dba", "sql_runner"), _scope_node("exec_sql")]["edge_type"]
            == "grants"
        )
        assert (
            graph.edges[_cred_node("SHARED_KEY"), _agent_node("triage")]["edge_type"]
            == "authenticates"
        )
        assert (
            graph.edges[_agent_node("triage"), _cred_node("SHARED_KEY")]["edge_type"]
            == "authenticated_by"
        )


class TestFindEscalationPaths:
    def test_calls_hop_to_dba_execute_sql_produces_id_010(self) -> None:
        triage = _triage_agent(calls_agents=["dba"])
        dba = _dba_agent()
        roles = {"coding_agent": RolePolicy(role="coding_agent", allowed_scopes=["exec_sql"])}
        keywords = ["exec_", "delete_", "shell"]

        findings = audit_rbac_graph([triage, dba], roles, keywords)

        assert len(findings) == 1
        assert findings[0].attack_id == "ID-010"
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].metadata["scope"] == "exec_sql"
        assert _agent_node("triage") in findings[0].metadata["path"]
        assert _agent_node("dba") in findings[0].metadata["path"]

    def test_dangerous_scope_on_self_without_calls_produces_no_id_010(self) -> None:
        agent = AgentIdentity(
            agent_id="self_dangerous",
            declared_role=None,
            tools=[
                ToolPermission(tool_name="shell_runner", capability_scopes=["exec_shell"]),
            ],
            manifest_path="fake/self.agent.json",
        )
        keywords = ["exec_", "shell"]

        findings = audit_rbac_graph([agent], {}, keywords)

        assert findings == []

    def test_unknown_calls_target_does_not_crash_or_finding(self) -> None:
        triage = _triage_agent(calls_agents=["missing_agent"])
        keywords = ["exec_"]

        graph = build_rbac_graph([triage], {}, keywords)
        findings = find_escalation_paths(graph, [triage], {}, keywords)

        assert "calls" not in {data["edge_type"] for _, _, data in graph.edges(data=True)}
        assert findings == []

    def test_shared_credential_hop_without_calls_produces_id_010(self) -> None:
        triage = _triage_agent(credential_ref="SHARED_KEY", calls_agents=[])
        privileged = AgentIdentity(
            agent_id="privileged",
            declared_role="coding_agent",
            tools=[ToolPermission(tool_name="shell_tool", capability_scopes=["exec_shell"])],
            credential_ref="SHARED_KEY",
            manifest_path="fake/privileged.agent.json",
        )
        roles = {"coding_agent": RolePolicy(role="coding_agent", allowed_scopes=["exec_shell"])}
        keywords = ["exec_", "shell"]

        findings = audit_rbac_graph([triage, privileged], roles, keywords)

        assert len(findings) == 1
        assert findings[0].attack_id == "ID-010"
        path = findings[0].metadata["path"]
        assert _cred_node("SHARED_KEY") in path
        assert _agent_node("privileged") in path

    def test_isolated_agents_produce_empty_findings(self) -> None:
        agent_a = AgentIdentity(
            agent_id="a",
            declared_role=None,
            tools=[ToolPermission(tool_name="lookup", capability_scopes=["lookup"])],
            manifest_path="fake/a.agent.json",
        )
        agent_b = AgentIdentity(
            agent_id="b",
            declared_role="coding_agent",
            tools=[ToolPermission(tool_name="shell_tool", capability_scopes=["exec_shell"])],
            credential_ref="UNIQUE_B",
            manifest_path="fake/b.agent.json",
        )
        roles = {"coding_agent": RolePolicy(role="coding_agent", allowed_scopes=["exec_shell"])}
        keywords = ["exec_"]

        findings = audit_rbac_graph([agent_a, agent_b], roles, keywords)

        assert findings == []


class TestLowTrustClassification:
    def test_matched_role_with_dangerous_tool_is_not_low_trust(self) -> None:
        agent = AgentIdentity(
            agent_id="dba",
            declared_role="coding_agent",
            tools=[ToolPermission(tool_name="exec_sql_runner", capability_scopes=["exec_sql"])],
            manifest_path="fake/dba.agent.json",
        )
        roles = {"coding_agent": RolePolicy(role="coding_agent", allowed_scopes=["exec_sql"])}
        keywords = ["exec_"]

        assert is_low_trust_agent(agent, roles, keywords) is False

    def test_unmatched_role_is_low_trust(self) -> None:
        agent = _triage_agent()
        assert is_low_trust_agent(agent, {}, ["exec_"]) is True


def _agent_node(agent_id: str) -> str:
    return f"agent:{agent_id}"


def _tool_node(agent_id: str, tool_name: str) -> str:
    return f"tool:{agent_id}:{tool_name}"


def _scope_node(scope: str) -> str:
    return f"scope:{scope}"


def _cred_node(credential_ref: str) -> str:
    return f"cred:{credential_ref}"
