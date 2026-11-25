"""Single static-audit orchestration path for CLI, MCP and dashboard (QA-036).

Every surface runs the same module set through run_static_audit so a run is
described by the same findings, coverage entries, assessment status and
module errors regardless of where it was started.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agentscan.core.models import Finding
from agentscan.core.scorer import calculate_score, score_band
from agentscan.identity.models import IdentityReport
from agentscan.reporting.audit_coverage import (
    AUDIT_MODULES,
    STATUS_COMPLETE,
    assessment_label,
    assessment_status,
    build_coverage,
    coverage_counts,
    module_for,
    normalize_selection,
    scope_complete,
)


@dataclass
class AuditRun:
    """The complete result of one static audit run."""

    path: str
    selected: list[str]
    findings: list[Finding] = field(default_factory=list)
    coverage: list[dict[str, Any]] = field(default_factory=list)
    module_errors: list[dict[str, str]] = field(default_factory=list)
    total_checks: int = 0

    @property
    def status(self) -> str:
        return assessment_status(self.coverage)

    @property
    def assessment_label(self) -> str:
        return assessment_label(self.selected)

    @property
    def scope_complete(self) -> bool:
        return scope_complete(self.selected)

    @property
    def score(self) -> int | None:
        if self.status != STATUS_COMPLETE:
            return None
        return calculate_score(self.findings, self.total_checks)

    @property
    def risk_band(self) -> str:
        return score_band(self.score)

    @property
    def coverage_counts(self) -> dict[str, int]:
        return coverage_counts(self.coverage)

    @property
    def coverage_scope_note(self) -> str:
        if not self.coverage:
            return "Coverage was not recorded for this run."
        counts = self.coverage_counts
        return (
            f"{len(self.selected)} of {len(AUDIT_MODULES)} audit modules selected; "
            f"{counts['skipped']} coverage records marked not selected, "
            f"{counts['errored']} errored."
        )

    def payload(self) -> dict[str, Any]:
        """Shared JSON fields used by every surface (findings are surface-specific)."""
        return {
            "path": self.path,
            "status": self.status,
            "score": self.score,
            "risk_band": self.risk_band,
            "assessment_label": self.assessment_label,
            "scope_complete": self.scope_complete,
            "coverage": self.coverage,
            "coverage_counts": self.coverage_counts,
            "coverage_scope_note": self.coverage_scope_note,
            "module_errors": self.module_errors,
            "total_checks": self.total_checks,
        }

    def to_identity_report(self, *, audit_id: str | None = None) -> IdentityReport:
        """Build the on-disk static-audit report with explicit coverage fields."""
        return IdentityReport(
            audit_id=audit_id or str(uuid.uuid4()),
            path_audited=self.path,
            agents_found=[],
            findings=self.findings,
            identity_score=self.score,
            audit_coverage=self.coverage,
            status=self.status,
            assessment_label=self.assessment_label,
            scope_complete=self.scope_complete,
            module_errors=self.module_errors,
            total_checks=self.total_checks,
        )


def _run_module(
    key: str,
    path: str,
    *,
    offline: bool,
    show_transitive: bool,
    rules_path: Path | str | None,
) -> tuple[list[Finding], int, list[dict[str, Any]]]:
    coverage: list[dict[str, Any]] = []

    if key == "scan_deps":
        from agentscan.supply_chain.dep_scanner import scan_dependencies

        findings, checks = scan_dependencies(
            path,
            offline=offline,
            show_transitive=show_transitive,
            coverage=coverage,
        )
    elif key == "scan_config":
        from agentscan.supply_chain.config_auditor import scan_config

        findings, checks = scan_config(path, coverage=coverage)
    elif key == "scan_secrets":
        from agentscan.supply_chain.secret_scanner import scan_secrets

        findings, checks = scan_secrets(path, coverage=coverage)
    elif key == "scan_typo":
        from agentscan.supply_chain.typosquat_detector import scan_typosquats

        findings, checks = scan_typosquats(path, coverage=coverage)
    elif key == "scan_mcp":
        from agentscan.supply_chain.mcp_auditor import scan_mcp_configs

        findings, checks = scan_mcp_configs(path, coverage=coverage)
    elif key == "scan_identity":
        from agentscan.identity.orchestrator import run_identity_audit

        report = run_identity_audit(path)
        return report.findings, len(report.agents_found), report.audit_coverage
    elif key == "scan_frameworks":
        from agentscan.supply_chain.framework_auditor import scan_frameworks

        findings, checks = scan_frameworks(path, coverage=coverage)
    elif key == "scan_semgrep":
        from agentscan.supply_chain.semgrep_auditor import scan_semgrep

        findings, checks = scan_semgrep(
            path,
            rules_path=rules_path,
            fallback_to_native=True,
            coverage=coverage,
        )
    else:
        raise ValueError(f"Unknown audit module: {key}")

    return findings, checks, coverage


def run_static_audit(
    path: str | Path,
    selected: list[str] | tuple[str, ...] | None = None,
    *,
    offline: bool = True,
    show_transitive: bool = False,
    rules_path: Path | str | None = None,
) -> AuditRun:
    """Run the selected static modules and preserve per-module failures.

    A scanner exception is recorded as an ERROR coverage entry plus a
    module_errors item instead of aborting the whole run, so callers can still
    report which modules completed and why the assessment is inconclusive.
    """
    selection = normalize_selection(selected)
    audit_path = str(path)
    run = AuditRun(path=audit_path, selected=selection)
    records: list[dict[str, Any]] = []
    errors: dict[str, str] = {}

    for key in selection:
        try:
            findings, checks, module_records = _run_module(
                key,
                audit_path,
                offline=offline,
                show_transitive=show_transitive,
                rules_path=rules_path,
            )
        except Exception as exc:  # noqa: BLE001 - per-module isolation is the point
            message = f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__
            errors[key] = message
            continue
        run.findings.extend(findings)
        run.total_checks += checks
        records.extend(module_records)

    run.coverage = build_coverage(selection, records, errors)
    run.module_errors = [
        {"module": key, "module_name": module_for(key).label, "error": message}
        for key, message in errors.items()
    ]
    return run
