# agentscan/identity/models.py
#
# Data models for the Agent Identity & Authorization Audit.
#
# Design note: this reuses core.models.Finding and core.models.Severity —
# NOT a separate finding type. Same shape, same scorer math, same report
# renderer. Only the attack_id prefix ("ID-" instead of "ATK-"/"SC-") and
# owasp_id (almost always "LLM08", occasionally "LLM07") distinguish an
# identity finding from an attack or supply-chain finding.

from __future__ import annotations

from pydantic import BaseModel, Field

from agentscan.core.models import Finding


class ToolPermission(BaseModel):
    """
    One capability an agent has been granted, as declared in its manifest.

    source tells you WHERE this permission was declared — useful later when
    LangChain agent-definition parsing is added alongside MCP config parsing.
    """

    tool_name: str = Field(
        ...,
        description="Name of the tool/function the agent can call.",
    )

    capability_scopes: list[str] = Field(
        default_factory=list,
        description=(
            "What this tool actually lets the agent do. Usually one scope "
            "per tool (e.g. ['send_email']), but a single tool can expose "
            "multiple scopes (e.g. a generic 'admin_api' tool exposing "
            "['read_customer_data', 'delete_customer_record'])."
        ),
    )

    source: str = Field(
        default="custom_manifest",
        description="Where this permission was declared: mcp_config | langchain_agent | custom_manifest",
    )


class AgentIdentity(BaseModel):
    """
    One deployed AI agent, as reconstructed from a manifest file on disk.

    credential_ref is deliberately Optional with no default guessing logic
    anywhere in this module — see IDE context rule #12. An agent whose
    credential cannot be confidently resolved is simply excluded from the
    shared-credential check, never force-matched.
    """

    agent_id: str = Field(
        ...,
        min_length=1,
        description="Unique identifier for this agent, as declared in its manifest.",
    )

    declared_role: str | None = Field(
        default=None,
        description=(
            "The role this agent claims to fulfil, matched against "
            "identity/policies/roles.yaml. None means no role was declared "
            "at all — this agent gets the dangerous-capability keyword "
            "fallback check instead of a baseline comparison."
        ),
    )

    tools: list[ToolPermission] = Field(
        default_factory=list,
        description="Every tool/capability this agent has been granted.",
    )

    credential_ref: str | None = Field(
        default=None,
        description=(
            "Which credential (env var name, secret name) this agent "
            "authenticates with. None if the manifest didn't declare one "
            "clearly — never inferred or guessed."
        ),
    )

    manifest_path: str = Field(
        ...,
        description="Filesystem path to the manifest this identity was parsed from.",
    )

    def all_scopes(self) -> list[str]:
        """Flatten every capability_scope across every tool into one list."""
        scopes: list[str] = []
        for tool in self.tools:
            scopes.extend(tool.capability_scopes)
        return scopes


class RolePolicy(BaseModel):
    """
    One entry from identity/policies/roles.yaml.
    Defines what a given declared_role is and isn't allowed to do.
    """

    role: str
    allowed_scopes: list[str] = Field(default_factory=list)
    disallowed_scopes: list[str] = Field(default_factory=list)


class IdentityReport(BaseModel):
    """
    The complete output of one identity audit run.
    Analogous to core.models.ScanReport, but for a static directory audit
    instead of a live-target scan.
    """

    audit_id: str = Field(
        ...,
        description="Unique identifier for this audit run.",
    )

    path_audited: str = Field(
        ...,
        description="The directory that was scanned for agent manifests.",
    )

    agents_found: list[AgentIdentity] = Field(
        default_factory=list,
        description="Every agent identity successfully parsed during this audit.",
    )

    findings: list[Finding] = Field(
        default_factory=list,
        description="All ID- prefixed findings from this audit. Reuses core Finding model.",
    )

    identity_score: int | None = Field(
        default=None,
        ge=0,
        le=100,
        description="AgentScan Identity Score (0-100). See identity_scorer.py.",
    )

    @property
    def total_agents_audited(self) -> int:
        return len(self.agents_found)

    @property
    def critical_count(self) -> int:
        from agentscan.core.models import Severity

        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        from agentscan.core.models import Severity

        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    def agents_without_declared_role(self) -> list[AgentIdentity]:
        return [a for a in self.agents_found if a.declared_role is None]
