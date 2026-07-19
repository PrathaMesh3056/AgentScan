# agentscan/identity/orchestrator.py
#
# NOTE: this file is NOT in the original AGENTSCAN_IDE_CONTEXT.md file tree.
# It exists because step 07 of the build guide ("CLI wiring") describes a
# sequence — manifest_loader -> permission_mapper + credential_auditor ->
# identity_scorer, print results — that needs a home. cli.py doesn't exist
# yet (it ships in Module 1). Rather than block this module on Module 1,
# that sequence lives here as run_identity_audit(). When cli.py is built,
# the --scan-identity flag becomes a two-line call into this function.
#
# Add this file to your copy of AGENTSCAN_IDE_CONTEXT.md's identity/ tree.

from __future__ import annotations

import uuid

from agentscan.identity.credential_auditor import audit_credentials
from agentscan.identity.identity_scorer import calculate_identity_score, score_band
from agentscan.identity.manifest_loader import load_manifests
from agentscan.identity.models import IdentityReport
from agentscan.identity.permission_mapper import (
    load_dangerous_keywords,
    load_role_policies,
    map_permissions,
)


def run_identity_audit(path: str) -> IdentityReport:
    """
    Full identity audit pipeline for a directory of agent manifests.

    1. Load every *.agent.json manifest under `path` -> AgentIdentity objects
    2. Load role policies + dangerous-keyword fallback list from roles.yaml
    3. Run permission_mapper against every agent (over-privileged / no-scope)
    4. Run credential_auditor across ALL agents at once (shared-credential)
    5. Score the combined findings -> Identity Score (0-100)

    This is the single entry point cli.py will call for `--scan-identity`.
    """
    agents = load_manifests(path)

    roles = load_role_policies()
    dangerous_keywords = load_dangerous_keywords()

    findings = []
    for agent in agents:
        findings.extend(map_permissions(agent, roles, dangerous_keywords))

    # Shared-credential check runs once across ALL agents, not per-agent
    findings.extend(audit_credentials(agents))

    score = calculate_identity_score(findings, total_agents_audited=len(agents))

    return IdentityReport(
        audit_id=str(uuid.uuid4()),
        path_audited=path,
        agents_found=agents,
        findings=findings,
        identity_score=score,
    )


def format_terminal_report(report: IdentityReport) -> str:
    """
    Render an IdentityReport as the terminal-style text shown in the README.
    Pure function (returns a string) so it's trivially testable — the real
    CLI wraps this with rich for colour once cli.py exists.
    """
    lines = ["[Identity & Authorization Audit]", ""]

    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    sorted_findings = sorted(
        report.findings,
        key=lambda f: (
            severity_order.index(f.severity.value)
            if f.severity.value in severity_order
            else len(severity_order)
        ),
    )

    for f in sorted_findings:
        lines.append(f"[{f.severity.value:8s}]  {f.attack_id:8s}  {f.description}")

    lines.append("")
    band = score_band(report.identity_score or 0)
    lines.append(f"AgentScan Identity Score:  {report.identity_score} / 100  [{band}]")

    return "\n".join(lines)
