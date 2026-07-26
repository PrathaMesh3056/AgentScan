# agentscan/cli.py
#
# CLI entry point for AgentScan.
#
# Commands:
#   agentscan scan   <target> [--framework auto] [--output report.json] [--fail-on CRITICAL]
#   agentscan audit  <path>   [--scan-deps] [--scan-config] [--scan-secrets]
#                             [--scan-typo] [--scan-mcp] [--scan-identity]
#   agentscan list-attacks
#
# Uses Typer for argument parsing and Rich for coloured terminal output.

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from agentscan.attacks.registry import registry
from agentscan.core.models import Finding, Framework, ScanMode, ScanReport, Target
from agentscan.core.runner import run_scan_multi
from agentscan.core.scorer import calculate_score, score_band
from agentscan.identity.models import IdentityReport

app = typer.Typer(
    name="agentscan",
    help="Open-source security scanner for AI agents.",
    add_completion=False,
)

console = Console()

# ── Severity display colours ──────────────────────────────────────────────────

_SEVERITY_COLOURS: dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "dim",
    "INFO": "dim",
    "PASS": "green",
}

# ── Severity ordering for --fail-on ──────────────────────────────────────────

_SEVERITY_ORDER: dict[str, int] = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
    "PASS": 0,
}


def write_report(report: ScanReport | IdentityReport, output_path: Path) -> None:
    ext = output_path.suffix.lower()
    if ext == ".json":
        data = report.to_dict() if hasattr(report, "to_dict") else report.model_dump(mode="json")
        output_path.write_text(json.dumps(data, indent=2))
    elif ext == ".html":
        from agentscan.reporting.html_report import render_html_report

        html = render_html_report(report)
        output_path.write_text(html, encoding="utf-8")
    elif ext == ".pdf":
        from agentscan.reporting.pdf_report import render_pdf_report

        render_pdf_report(report, output_path)
    elif ext == ".sarif":
        from agentscan.reporting.sarif_report import to_sarif

        data = to_sarif(report)
        output_path.write_text(json.dumps(data, indent=2))
    else:
        raise typer.BadParameter(f"Unsupported output format: {ext}")


@app.command()
def scan(
    target: str = typer.Argument(..., help="The HTTP endpoint to scan."),
    framework: str = typer.Option("auto", help="Agent framework (auto-detect by default)."),
    output: Path | None = typer.Option(None, help="Write JSON report to this file."),  # noqa: B008
    fail_on: str | None = typer.Option(
        None,
        "--fail-on",
        help="Exit with code 1 if any finding has severity >= this threshold.",
    ),  # noqa: B008
    exploit: bool = typer.Option(
        False, "--exploit", help="Run active EXPLOIT modules alongside SCAN modules."
    ),
    system_prompt: str | None = typer.Option(
        None,
        "--system-prompt",
        help="The expected system prompt content for EXPLOIT mode exfiltration tests.",
    ),
    deep: bool = typer.Option(False, "--deep", help="Run DEEP mode neural activation probes."),
) -> None:
    """Run a security scan against an LLM agent endpoint."""
    # Build target
    target_obj = Target(url=target, framework=Framework(framework), system_prompt=system_prompt)

    # Determine modes
    modes = (
        [ScanMode.SCAN]
        + ([ScanMode.EXPLOIT] if exploit else [])
        + ([ScanMode.DEEP] if deep else [])
    )

    # Run scan
    report = asyncio.run(run_scan_multi(target_obj, modes))

    # Render findings table
    if report.findings:
        table = Table(title="AgentScan Findings", show_lines=True)
        table.add_column("Attack ID", style="cyan", no_wrap=True)
        table.add_column("Severity", no_wrap=True)
        table.add_column("Description")

        for finding in report.findings:
            severity_str = finding.severity.value
            colour = _SEVERITY_COLOURS.get(severity_str, "")
            table.add_row(
                finding.attack_id,
                f"[{colour}]{severity_str}[/{colour}]",
                finding.description,
            )

        console.print(table)
    else:
        console.print("[green]No vulnerabilities found.[/green]")

    # Print score
    band = score_band(report.score) if report.score is not None else "UNKNOWN"
    score_val = report.score if report.score is not None else 0
    console.print(f"\nAgentScan Score: {score_val}/100  [{band}]")

    # Write JSON output
    if output is not None:
        write_report(report, output)
        console.print(f"Report written to {output}")

    # Fail-on threshold check
    if fail_on is not None:
        threshold = _SEVERITY_ORDER.get(fail_on.upper(), 0)
        for finding in report.findings:
            finding_level = _SEVERITY_ORDER.get(finding.severity.value, 0)
            if finding_level >= threshold:
                raise typer.Exit(code=1)


@app.command()
def audit(  # noqa: PLR0912, PLR0913
    path: str = typer.Argument(..., help="Directory to audit (manifests, source files, deps)."),
    scan_deps: bool = typer.Option(False, "--scan-deps", help="Scan dependencies for known CVEs."),
    scan_config: bool = typer.Option(
        False, "--scan-config", help="Audit config files for dangerous patterns."
    ),
    scan_secrets: bool = typer.Option(False, "--scan-secrets", help="Scan for hardcoded secrets."),
    scan_typo: bool = typer.Option(False, "--scan-typo", help="Detect typosquatted packages."),
    scan_mcp: bool = typer.Option(False, "--scan-mcp", help="Audit MCP configuration files."),
    scan_identity: bool = typer.Option(
        False, "--scan-identity", help="Run identity & authorization audit."
    ),
    output: Path | None = typer.Option(None, help="Write JSON findings to this file."),  # noqa: B008
) -> None:
    """Audit a project directory for AI supply-chain and identity risks."""
    # If no flag is given, run all six categories (sensible default)
    run_all = not any([scan_deps, scan_config, scan_secrets, scan_typo, scan_mcp, scan_identity])

    all_findings: list[Finding] = []
    total_checks = 0

    # ── Lazy imports (keep startup fast when only `scan` is used) ─────────────
    if run_all or scan_deps:
        from agentscan.supply_chain.dep_scanner import scan_dependencies

        f, c = scan_dependencies(path)
        all_findings.extend(f)
        total_checks += c

    if run_all or scan_config:
        from agentscan.supply_chain.config_auditor import scan_config as _scan_cfg

        f, c = _scan_cfg(path)
        all_findings.extend(f)
        total_checks += c

    if run_all or scan_secrets:
        from agentscan.supply_chain.secret_scanner import scan_secrets as _scan_sec

        f, c = _scan_sec(path)
        all_findings.extend(f)
        total_checks += c

    if run_all or scan_typo:
        from agentscan.supply_chain.typosquat_detector import scan_typosquats

        f, c = scan_typosquats(path)
        all_findings.extend(f)
        total_checks += c

    if run_all or scan_mcp:
        from agentscan.supply_chain.mcp_auditor import scan_mcp_configs

        f, c = scan_mcp_configs(path)
        all_findings.extend(f)
        total_checks += c

    if run_all or scan_identity:
        from agentscan.identity.orchestrator import run_identity_audit

        report = run_identity_audit(path)
        all_findings.extend(report.findings)
        total_checks += max(len(report.agents_found), 1)

    # ── Render findings table ──────────────────────────────────────────────────
    if all_findings:
        table = Table(title="AgentScan Audit Findings", show_lines=True)
        table.add_column("Finding ID", style="cyan", no_wrap=True)
        table.add_column("Severity", no_wrap=True)
        table.add_column("Description")

        # Sort: CRITICAL first
        sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "PASS"]
        sorted_findings = sorted(
            all_findings,
            key=lambda f: (
                sev_order.index(f.severity.value) if f.severity.value in sev_order else 99
            ),
        )
        for finding in sorted_findings:
            sev_str = finding.severity.value
            colour = _SEVERITY_COLOURS.get(sev_str, "")
            table.add_row(
                finding.attack_id,
                f"[{colour}]{sev_str}[/{colour}]",
                finding.description,
            )
        console.print(table)
    else:
        console.print("[green]No issues found.[/green]")

    # ── Score ──────────────────────────────────────────────────────────────────
    score = calculate_score(all_findings, max(total_checks, 1))
    band = score_band(score)
    console.print(f"\nAgentScan Audit Score: {score}/100  [{band}]")

    # ── JSON output ────────────────────────────────────────────────────────────
    if output is not None:
        import uuid

        from agentscan.identity.models import IdentityReport

        report = IdentityReport(
            audit_id=str(uuid.uuid4()),
            path_audited=path,
            agents_found=[],
            findings=all_findings,
            identity_score=score,
        )
        write_report(report, output)
        console.print(f"Findings written to {output}")


@app.command("list-attacks")
def list_attacks() -> None:
    """List all registered attack modules."""
    registry.load_all()

    modules = registry.get_all()

    table = Table(title="AgentScan Attack Modules", show_lines=True)
    table.add_column("Attack ID", style="cyan", no_wrap=True)
    table.add_column("Name", style="bold")
    table.add_column("OWASP ID", no_wrap=True)
    table.add_column("Supported Modes")

    for module in modules:
        modes = ", ".join(m.value for m in module.supported_modes)
        table.add_row(
            module.attack_id,
            module.attack_name,
            module.owasp_id,
            modes,
        )

    console.print(table)


if __name__ == "__main__":
    app()
