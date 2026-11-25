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

    calls_agents: list[str] = Field(
        default_factory=list,
        description=(
            "Other agent IDs this agent is permitted to invoke. Used by "
            "the RBAC graph auditor to detect multi-hop privilege escalation."
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

    audit_coverage: list[dict] = Field(
        default_factory=list,
        description="Per-module source and assessment limits for static audits.",
    )
    status: str = Field(
        default="INCONCLUSIVE",
        description="Assessment completion, separate from findings severity.",
    )
    assessment_label: str = Field(
        default="Identity & RBAC Entitlement Audit",
        description="Human label for the assessed mode (e.g. mixed supply-chain + identity).",
    )
    scope_complete: bool = Field(
        default=False,
        description="True only when every static-audit module was selected for this run.",
    )
    module_errors: list[dict[str, str]] = Field(
        default_factory=list,
        description="Modules that raised during this run; kept separate from findings.",
    )
    total_checks: int = Field(
        default=0,
        ge=0,
        description="Checks executed across the assessed modules.",
    )

    @property
    def total_agents_audited(self) -> int:
        return len(self.agents_found)

    @property
    def modules_ran(self) -> list[dict]:
        """Coverage entries for modules that were actually assessed."""
        from agentscan.reporting.audit_coverage import RAN_STATUSES

        return [e for e in self.audit_coverage if e.get("status") in RAN_STATUSES]

    @property
    def modules_skipped(self) -> list[dict]:
        """Coverage entries for catalog modules not selected for this run."""
        from agentscan.reporting.audit_coverage import STATUS_SKIPPED

        return [e for e in self.audit_coverage if e.get("status") == STATUS_SKIPPED]

    @property
    def modules_errored(self) -> list[dict]:
        """Coverage entries for modules that raised during this run."""
        from agentscan.reporting.audit_coverage import STATUS_ERROR

        return [e for e in self.audit_coverage if e.get("status") == STATUS_ERROR]

    @property
    def coverage_summary(self) -> str:
        if not self.audit_coverage:
            return "Coverage was not recorded for this report."
        return (
            f"{len(self.modules_ran)} ran \u00b7 {len(self.modules_skipped)} not selected "
            f"\u00b7 {len(self.modules_errored)} errored"
        )

    @property
    def score_label(self) -> str:
        if not self.modules_ran:
            return "Identity Score"
        modules = {str(entry.get("module", "")) for entry in self.modules_ran}
        return "Identity Score" if modules <= {"identity"} else "Audit Score"

    @property
    def coverage_scope_note(self) -> str:
        if not self.audit_coverage:
            return "Coverage was not recorded for this report."
        ran = len(self.modules_ran)
        skipped = len(self.modules_skipped)
        errored = len(self.modules_errored)
        return (
            f"{ran} of {len(self.audit_coverage)} coverage entries assessed; "
            f"{skipped} not selected, {errored} errored."
        )

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
