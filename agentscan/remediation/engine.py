# agentscan/remediation/engine.py
#
# RemediationEngine: Orchestrates planning and application of safe fixes.

from __future__ import annotations

from pathlib import Path

from agentscan.core.models import Finding
from agentscan.remediation.ast_patch import plan_ast_patches
from agentscan.remediation.guardrails import plan_guardrails
from agentscan.remediation.identity_shrink import plan_identity_shrinks
from agentscan.remediation.models import FixAction, FixPlan
from agentscan.remediation.paths import contained_path
from agentscan.remediation.pin_bump import plan_pin_bumps


class RemediationEngine:
    """Plans and applies remediation actions for AgentScan findings."""

    def __init__(self, root_path: str | Path) -> None:
        self.root_path = Path(root_path).resolve()

    def plan(
        self,
        findings: list[Finding],
        kinds: list[str] | None = None,
    ) -> FixPlan:
        """Inspect findings and return a FixPlan with all proposed FixActions."""
        actions: list[FixAction] = []

        allowed_kinds = set(kinds) if kinds else None
        # Validate untrusted finding paths before a planner can read them.
        for finding in findings:
            if finding.metadata.get("file"):
                contained_path(self.root_path, str(finding.metadata["file"]))

        # 1. Dependency pin bumping (SC-001)
        if allowed_kinds is None or "pin_bump" in allowed_kinds:
            actions.extend(plan_pin_bumps(findings, self.root_path))

        # 2. Insecure AST config & code patching (SC-011..014)
        if allowed_kinds is None or "ast_patch" in allowed_kinds:
            actions.extend(plan_ast_patches(findings, self.root_path))

        # 3. Identity and MCP scope shrinking (ID-*, SC-020)
        if allowed_kinds is None or "identity_shrink" in allowed_kinds:
            actions.extend(plan_identity_shrinks(findings, self.root_path))

        # 4. Defensive guardrails synthesis (ATK-*)
        if allowed_kinds is None or "guardrails" in allowed_kinds:
            actions.extend(plan_guardrails(findings, self.root_path))

        plan = FixPlan(actions=actions)
        plan.bind_root(self.root_path)
        return plan

    def apply(self, plan: FixPlan) -> FixPlan:
        """Execute all planned FixActions by writing modified files to disk."""
        plan.bind_root(self.root_path)
        plan.apply()
        return plan


def plan_and_apply(
    findings: list[Finding],
    root_path: str | Path,
    apply_changes: bool = False,
    kinds: list[str] | None = None,
) -> FixPlan:
    """Convenience helper to plan (and optionally apply) remediations."""
    engine = RemediationEngine(root_path)
    plan = engine.plan(findings, kinds=kinds)
    if apply_changes:
        engine.apply(plan)
    return plan
