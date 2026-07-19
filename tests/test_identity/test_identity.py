# tests/test_identity/test_identity.py
#
# Minimum coverage per the build guide checkpoint:
# 1. clean manifest -> no findings
# 2. over-privileged tool -> at least one finding
# 3. two agents sharing credential_ref -> shared-credential finding
# 4. undeclared role -> keyword-fallback path (ID-008 + dangerous keyword)
#
# Plus: manifest_loader reads the real fixture directory, and a full
# end-to-end orchestrator run reproducing the exact module checkpoint
# scenario described in the build guide.

from __future__ import annotations

from pathlib import Path

import pytest

from agentscan.core.models import Severity
from agentscan.identity.credential_auditor import audit_credentials
from agentscan.identity.manifest_loader import load_manifests
from agentscan.identity.models import AgentIdentity, RolePolicy, ToolPermission
from agentscan.identity.orchestrator import format_terminal_report, run_identity_audit
from agentscan.identity.permission_mapper import map_permissions

FIXTURE_DIR = Path(__file__).parent.parent / "fixtures" / "demo-agents"


# ── Shared test policy (small, self-contained — doesn't depend on the real roles.yaml) ──


@pytest.fixture
def support_role() -> RolePolicy:
    return RolePolicy(
        role="customer_support_agent",
        allowed_scopes=["read_customer_data", "send_email", "create_ticket"],
        disallowed_scopes=["delete_database", "execute_shell"],
    )


@pytest.fixture
def roles_map(support_role: RolePolicy) -> dict[str, RolePolicy]:
    return {support_role.role: support_role}


@pytest.fixture
def dangerous_keywords() -> list[str]:
    return ["delete_", "exec_", "shell", "admin"]


# ═══════════════════════════════════════════════════════════════
# 1. CLEAN MANIFEST -> NO FINDINGS
# ═══════════════════════════════════════════════════════════════


class TestCleanManifest:
    def test_agent_fully_within_allowed_scopes_produces_no_findings(
        self, roles_map: dict[str, RolePolicy], dangerous_keywords: list[str]
    ) -> None:
        clean_agent = AgentIdentity(
            agent_id="clean_support_agent",
            declared_role="customer_support_agent",
            credential_ref="UNIQUE_KEY_1",
            tools=[
                ToolPermission(tool_name="send_email", capability_scopes=["send_email"]),
                ToolPermission(tool_name="create_ticket", capability_scopes=["create_ticket"]),
            ],
            manifest_path="fake/clean.agent.json",
        )

        findings = map_permissions(clean_agent, roles_map, dangerous_keywords)

        assert findings == []


# ═══════════════════════════════════════════════════════════════
# 2. OVER-PRIVILEGED TOOL -> AT LEAST ONE FINDING
# ═══════════════════════════════════════════════════════════════


class TestOverPrivilegedTool:
    def test_scope_outside_allowed_list_produces_finding(
        self, roles_map: dict[str, RolePolicy], dangerous_keywords: list[str]
    ) -> None:
        agent = AgentIdentity(
            agent_id="over_privileged_agent",
            declared_role="customer_support_agent",
            credential_ref="UNIQUE_KEY_2",
            tools=[
                ToolPermission(tool_name="send_email", capability_scopes=["send_email"]),
                ToolPermission(
                    tool_name="delete_customer_record",
                    capability_scopes=["delete_customer_record"],  # not in allowed_scopes
                ),
            ],
            manifest_path="fake/over_privileged.agent.json",
        )

        findings = map_permissions(agent, roles_map, dangerous_keywords)

        assert len(findings) >= 1
        assert any(f.attack_id == "ID-002" for f in findings)
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_explicitly_disallowed_scope_produces_finding(
        self, roles_map: dict[str, RolePolicy], dangerous_keywords: list[str]
    ) -> None:
        agent = AgentIdentity(
            agent_id="dangerous_agent",
            declared_role="customer_support_agent",
            tools=[
                ToolPermission(tool_name="admin_console", capability_scopes=["execute_shell"]),
            ],
            manifest_path="fake/dangerous.agent.json",
        )

        findings = map_permissions(agent, roles_map, dangerous_keywords)

        assert len(findings) == 1
        assert "explicitly disallowed" in findings[0].description


# ═══════════════════════════════════════════════════════════════
# 3. SHARED CREDENTIAL -> CRITICAL FINDING NAMING BOTH AGENTS
# ═══════════════════════════════════════════════════════════════


class TestSharedCredential:
    def test_two_agents_sharing_credential_produces_critical_finding(self) -> None:
        agent_a = AgentIdentity(
            agent_id="agent_a", credential_ref="SHARED_KEY", manifest_path="fake/a.json"
        )
        agent_b = AgentIdentity(
            agent_id="agent_b", credential_ref="SHARED_KEY", manifest_path="fake/b.json"
        )

        findings = audit_credentials([agent_a, agent_b])

        assert len(findings) == 1
        assert findings[0].attack_id == "ID-005"
        assert findings[0].severity == Severity.CRITICAL
        assert "agent_a" in findings[0].description
        assert "agent_b" in findings[0].description

    def test_three_agents_two_sharing_one_unique_produces_one_finding(self) -> None:
        agent_a = AgentIdentity(agent_id="a", credential_ref="SHARED", manifest_path="a")
        agent_b = AgentIdentity(agent_id="b", credential_ref="SHARED", manifest_path="b")
        agent_c = AgentIdentity(agent_id="c", credential_ref="UNIQUE", manifest_path="c")

        findings = audit_credentials([agent_a, agent_b, agent_c])

        assert len(findings) == 1  # only the shared pair triggers a finding
        assert set(findings[0].metadata["agent_ids"]) == {"a", "b"}

    def test_agents_with_no_credential_ref_never_flagged(self) -> None:
        """Rule #12 — never guess. Both agents lack credential_ref -> skipped entirely."""
        agent_a = AgentIdentity(agent_id="a", credential_ref=None, manifest_path="a")
        agent_b = AgentIdentity(agent_id="b", credential_ref=None, manifest_path="b")

        findings = audit_credentials([agent_a, agent_b])

        assert findings == []

    def test_unique_credentials_produce_no_findings(self) -> None:
        agent_a = AgentIdentity(agent_id="a", credential_ref="KEY_A", manifest_path="a")
        agent_b = AgentIdentity(agent_id="b", credential_ref="KEY_B", manifest_path="b")

        findings = audit_credentials([agent_a, agent_b])

        assert findings == []


# ═══════════════════════════════════════════════════════════════
# 4. UNDECLARED ROLE -> KEYWORD-FALLBACK PATH
# ═══════════════════════════════════════════════════════════════


class TestUndeclaredRoleFallback:
    def test_no_declared_role_produces_no_scope_declaration_finding(
        self, roles_map: dict[str, RolePolicy], dangerous_keywords: list[str]
    ) -> None:
        agent = AgentIdentity(
            agent_id="undeclared_agent",
            declared_role=None,
            tools=[ToolPermission(tool_name="web_search", capability_scopes=["web_search"])],
            manifest_path="fake/undeclared.agent.json",
        )

        findings = map_permissions(agent, roles_map, dangerous_keywords)

        assert len(findings) == 1
        assert findings[0].attack_id == "ID-008"
        assert findings[0].severity == Severity.HIGH

    def test_undeclared_role_with_dangerous_tool_produces_two_findings(
        self, roles_map: dict[str, RolePolicy], dangerous_keywords: list[str]
    ) -> None:
        agent = AgentIdentity(
            agent_id="risky_undeclared_agent",
            declared_role=None,
            tools=[
                ToolPermission(tool_name="delete_records", capability_scopes=["delete_records"]),
            ],
            manifest_path="fake/risky.agent.json",
        )

        findings = map_permissions(agent, roles_map, dangerous_keywords)

        assert len(findings) == 2  # ID-008 (no role) + ID-009 (dangerous keyword)
        attack_ids = {f.attack_id for f in findings}
        assert attack_ids == {"ID-008", "ID-009"}
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_role_not_in_policy_file_treated_as_undeclared(
        self, roles_map: dict[str, RolePolicy], dangerous_keywords: list[str]
    ) -> None:
        agent = AgentIdentity(
            agent_id="unknown_role_agent",
            declared_role="role_that_does_not_exist_in_yaml",
            tools=[ToolPermission(tool_name="web_search", capability_scopes=["web_search"])],
            manifest_path="fake/unknown_role.agent.json",
        )

        findings = map_permissions(agent, roles_map, dangerous_keywords)

        assert any(f.attack_id == "ID-008" for f in findings)


# ═══════════════════════════════════════════════════════════════
# MANIFEST LOADER — reads real fixture files
# ═══════════════════════════════════════════════════════════════


class TestManifestLoader:
    def test_loads_all_three_demo_fixtures(self) -> None:
        agents = load_manifests(FIXTURE_DIR)

        assert len(agents) == 3
        agent_ids = {a.agent_id for a in agents}
        assert agent_ids == {"support_agent", "billing_agent", "insights_agent"}

    def test_credential_ref_parsed_correctly(self) -> None:
        agents = load_manifests(FIXTURE_DIR)
        support = next(a for a in agents if a.agent_id == "support_agent")
        assert support.credential_ref == "OPENAI_KEY_PROD"

    def test_null_declared_role_parses_as_none(self) -> None:
        agents = load_manifests(FIXTURE_DIR)
        insights = next(a for a in agents if a.agent_id == "insights_agent")
        assert insights.declared_role is None

    def test_raises_on_missing_path(self) -> None:
        with pytest.raises(FileNotFoundError):
            load_manifests("/definitely/does/not/exist")


# ═══════════════════════════════════════════════════════════════
# END-TO-END — the exact module checkpoint scenario
# ═══════════════════════════════════════════════════════════════


class TestModuleCheckpoint:
    """
    Reproduces the build guide's checkpoint exactly:

    'Run agentscan audit --path ./tests/fixtures/demo-agents --scan-identity
    against a small fixture directory containing 3 fake agent manifests where:
    one agent has a tool outside its declared role's allowed_scopes, and two
    agents share the same credential_ref.'
    """

    def test_full_audit_produces_shared_credential_finding(self) -> None:
        report = run_identity_audit(str(FIXTURE_DIR))

        shared_cred_findings = [f for f in report.findings if f.attack_id == "ID-005"]
        assert len(shared_cred_findings) == 1
        assert shared_cred_findings[0].severity == Severity.CRITICAL
        assert "support_agent" in shared_cred_findings[0].description
        assert "billing_agent" in shared_cred_findings[0].description

    def test_full_audit_produces_over_privileged_finding(self) -> None:
        report = run_identity_audit(str(FIXTURE_DIR))

        over_priv_findings = [f for f in report.findings if f.attack_id == "ID-002"]
        assert len(over_priv_findings) >= 1
        assert over_priv_findings[0].severity in (Severity.CRITICAL, Severity.HIGH)

    def test_full_audit_produces_no_scope_declaration_finding(self) -> None:
        report = run_identity_audit(str(FIXTURE_DIR))

        no_scope_findings = [f for f in report.findings if f.attack_id == "ID-008"]
        assert len(no_scope_findings) == 1
        assert "insights_agent" in no_scope_findings[0].description

    def test_identity_score_reduced_from_100(self) -> None:
        report = run_identity_audit(str(FIXTURE_DIR))

        assert report.identity_score is not None
        assert 0 <= report.identity_score < 100
        assert report.total_agents_audited == 3

    def test_terminal_report_contains_all_required_elements(self) -> None:
        report = run_identity_audit(str(FIXTURE_DIR))
        output = format_terminal_report(report)

        assert "Identity & Authorization Audit" in output
        assert "ID-005" in output
        assert "ID-002" in output
        assert "AgentScan Identity Score" in output
        assert str(report.identity_score) in output
