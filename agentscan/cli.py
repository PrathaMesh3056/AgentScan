# agentscan/cli.py
#
# CLI entry point for AgentScan.
#
# Commands:
#   agentscan scan <target> [--framework auto] [--output report.json] [--fail-on CRITICAL]
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
from agentscan.core.models import Framework, Target
from agentscan.core.runner import run_scan
from agentscan.core.scorer import score_band

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
) -> None:
    """Run a security scan against an LLM agent endpoint."""
    # Build target
    target_obj = Target(url=target, framework=Framework(framework))

    # Run scan
    report = asyncio.run(run_scan(target_obj))

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
        output.write_text(json.dumps(report.to_dict(), indent=2))
        console.print(f"Report written to {output}")

    # Fail-on threshold check
    if fail_on is not None:
        threshold = _SEVERITY_ORDER.get(fail_on.upper(), 0)
        for finding in report.findings:
            finding_level = _SEVERITY_ORDER.get(finding.severity.value, 0)
            if finding_level >= threshold:
                raise typer.Exit(code=1)


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
