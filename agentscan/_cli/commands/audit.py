# agentscan/cli/commands/audit.py
#
# 'agentscan audit' command — supply-chain & static audit logic.

from __future__ import annotations

from pathlib import Path

import typer
from rich.table import Table

from agentscan._cli._shared import (
    _SEVERITY_COLOURS,
    _fail_on_should_exit,
    app,
    console,
    write_report,
)


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
    scan_frameworks: bool = typer.Option(
        False,
        "--scan-frameworks",
        help="Audit agent frameworks (CrewAI, LangGraph, AutoGen) for insecure patterns.",
    ),
    scan_semgrep: bool = typer.Option(
        False,
        "--scan-semgrep",
        help="Run Semgrep AI rules (pickle/torch.load, shell=True, prompt interpolation, dangerous eval/exec). "
        "Automatically uses native AST engine if semgrep binary is missing.",
    ),
    rules: Path | None = typer.Option(  # noqa: B008
        None,
        "--rules",
        help="Custom Semgrep YAML rules file for code auditing.",
    ),
    aibom: bool = typer.Option(
        False,
        "--aibom",
        help="Write a CycloneDX 1.6 AIBOM JSON (pinned packages + model/MCP stubs).",
    ),
    fail_on: str | None = typer.Option(
        None,
        "--fail-on",
        help="Exit with code 1 if any finding has severity >= this threshold.",
    ),
    output: Path | None = typer.Option(None, help="Write JSON findings to this file."),  # noqa: B008
    offline: bool = typer.Option(
        False,
        "--offline",
        help="Disable live network lookups (e.g. OSV.dev); audit using offline database only.",
    ),
    show_transitive: bool = typer.Option(
        False,
        "--show-transitive",
        help="Trace and display full dependency chains from root packages to vulnerable transitive dependencies.",
    ),
) -> None:
    """Audit a project directory for AI supply-chain and identity risks."""
    # If no flag is given, run the built-in categories (Semgrep stays opt-in).
    run_all = not any(
        [
            scan_deps,
            scan_config,
            scan_secrets,
            scan_typo,
            scan_mcp,
            scan_identity,
            scan_frameworks,
            scan_semgrep,
            aibom,
        ]
    )

    selected = None
    if not run_all:
        selected = [
            key
            for key, enabled in zip(
                (
                    "scan_deps",
                    "scan_config",
                    "scan_secrets",
                    "scan_typo",
                    "scan_mcp",
                    "scan_identity",
                    "scan_frameworks",
                    "scan_semgrep",
                ),
                (
                    scan_deps,
                    scan_config,
                    scan_secrets,
                    scan_typo,
                    scan_mcp,
                    scan_identity,
                    scan_frameworks,
                    scan_semgrep,
                ),
                strict=True,
            )
            if enabled
        ]

    # One shared orchestration path with the MCP server and dashboard.
    from agentscan.reporting.audit_runner import run_static_audit

    run = run_static_audit(
        path,
        selected,
        offline=offline,
        show_transitive=show_transitive,
        rules_path=rules if scan_semgrep else None,
    )
    all_findings = list(run.findings)
    coverage = run.coverage

    aibom_path: Path | None = None
    if aibom:
        from agentscan.supply_chain.aibom import write_aibom

        scanners_on = any(
            [
                scan_deps,
                scan_config,
                scan_secrets,
                scan_typo,
                scan_mcp,
                scan_identity,
                scan_frameworks,
                scan_semgrep,
                run_all,
            ]
        )
        aibom_path = Path("aibom.cdx.json") if scanners_on or output is None else output
        write_aibom(path, aibom_path)
        console.print(f"AIBOM written to {aibom_path}")

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
            desc = finding.description
            if show_transitive and finding.metadata.get("transitive_path_str"):
                desc = f"{desc}\n[dim]Chain: {finding.metadata['transitive_path_str']}[/dim]"
            table.add_row(
                finding.attack_id,
                f"[{colour}]{sev_str}[/{colour}]",
                desc,
            )
        console.print(table)
    else:
        console.print("No findings recorded. Review the selected checks and their coverage.")

    # ── Score and explicit coverage ────────────────────────────────────────────
    score = run.score
    band = run.risk_band
    score_text = f"{score}/100" if score is not None else "N/A"
    console.print(f"\nAgentScan Audit Score: {score_text}  [{band}]  ({run.assessment_label})")
    console.print(f"Assessment status: {run.status} - {run.coverage_scope_note}")
    for item in coverage:
        module_key = item.get("module_key", item.get("module", "unknown"))
        console.print(f"{module_key}: {item['status']} ({item.get('source', 'no input')})")
    for error in run.module_errors:
        console.print(f"[red]{error['module_name']}: ERROR (not assessed) - {error['error']}[/red]")

    # ── JSON output ────────────────────────────────────────────────────────────
    if output is not None and output != aibom_path:
        write_report(run.to_identity_report(), output)
        console.print(f"Findings written to {output}")

    if fail_on is not None and _fail_on_should_exit(all_findings, fail_on):
        raise typer.Exit(code=1)
