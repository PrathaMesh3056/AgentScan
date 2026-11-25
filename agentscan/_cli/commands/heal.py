# agentscan/cli/commands/heal.py
#
# 'agentscan heal' and 'agentscan heal-server' commands — self-healing & patch execution.

from __future__ import annotations

import contextlib
import json
from pathlib import Path

import typer
from rich.panel import Panel
from rich.table import Table

from agentscan._cli._shared import app, console
from agentscan.core.models import Finding


@app.command(name="heal")
def heal_command(
    target_path: Path = typer.Argument(..., help="Path to repo or file to inspect and heal."),  # noqa: B008
    report_file: Path | None = typer.Option(  # noqa: B008
        None, "--report", "-r", help="Optional path to an existing scan or audit JSON report."
    ),
    patch_out: Path | None = typer.Option(  # noqa: B008
        None, "--patch-out", "-p", help="Output path for generated .patch file."
    ),
    apply: bool = typer.Option(  # noqa: B008
        False, "--apply", help="Apply fixes directly to source files (default: False, dry-run)."
    ),
) -> None:
    """Automated self-healing: plans fixes, produces unified git diffs, and optionally applies changes."""
    from agentscan.remediation.engine import RemediationEngine
    from agentscan.remediation.patch_generator import generate_unified_patch

    resolved_path = target_path.resolve()
    if not resolved_path.exists():
        console.print(f"[bold red]Error: Target path does not exist:[/bold red] {resolved_path}")
        raise typer.Exit(code=1)

    findings: list[Finding] = []
    if report_file is not None:
        if not report_file.exists():
            console.print(f"[bold red]Error: Report file not found:[/bold red] {report_file}")
            raise typer.Exit(code=1)
        try:
            data = json.loads(report_file.read_text(encoding="utf-8"))
            raw_findings = (
                data.get("findings", [])
                if isinstance(data, dict)
                else (data if isinstance(data, list) else [])
            )
            for item in raw_findings:
                with contextlib.suppress(Exception):
                    findings.append(Finding.model_validate(item))
        except Exception as e:
            console.print(f"[bold red]Failed to parse report file:[/bold red] {e}")
            raise typer.Exit(code=1) from None
    else:
        # Run static configuration & framework auditors to discover remediable findings
        from agentscan.supply_chain.config_auditor import scan_config
        from agentscan.supply_chain.framework_auditor import scan_frameworks

        cfg_f, _ = scan_config(str(resolved_path))
        findings.extend(cfg_f)
        fw_f, _ = scan_frameworks(str(resolved_path))
        findings.extend(fw_f)
        if (resolved_path / "requirements.txt").exists() or (
            resolved_path / "pyproject.toml"
        ).exists():
            from agentscan.supply_chain.dep_scanner import scan_dependencies

            dep_f, _ = scan_dependencies(str(resolved_path), offline=True)
            findings.extend(dep_f)

    engine = RemediationEngine(root_path=resolved_path)
    plan = engine.plan(findings)

    mode_label = "[red]APPLY[/red]" if apply else "[green]DRY-RUN (Safe)[/green]"
    console.print(
        Panel(
            f"[bold cyan]AgentScan Automated Self-Healing[/bold cyan]\n"
            f"Target: [underline]{resolved_path}[/underline]\n"
            f"Findings evaluated: [yellow]{len(findings)}[/yellow]  |  Actions planned: [green]{plan.total_actions}[/green]\n"
            f"Mode: [bold]{mode_label}[/bold]",
            title="[bold blue]Self-Healing Engine[/bold blue]",
        )
    )

    if not plan.actions:
        console.print(
            "[green]No automated remediation actions required. Codebase is clean![/green]"
        )
        return

    table = Table(title="Remediation Plan", show_lines=True)
    table.add_column("Finding ID", style="cyan", no_wrap=True)
    table.add_column("Action Kind", style="magenta", no_wrap=True)
    table.add_column("Target Path")
    table.add_column("Diff Status")

    for action in plan.actions:
        diff_status = "Modified" if action.before != action.after else "Unchanged"
        table.add_row(
            action.finding_id,
            action.kind,
            action.path,
            diff_status,
        )
    console.print(table)

    patch_content = generate_unified_patch(plan, base_dir=resolved_path)

    if patch_out is not None and patch_content:
        patch_out.parent.mkdir(parents=True, exist_ok=True)
        patch_out.write_text(patch_content, encoding="utf-8")
        console.print(f"[green]Unified git patch written to:[/green] [cyan]{patch_out}[/cyan]")

    if apply:
        engine.apply(plan)
        console.print(
            f"[bold green]Successfully applied {plan.applied_count} automated fix actions to disk.[/bold green]"
        )
    else:
        console.print(
            "[yellow]Dry-run complete: no files were modified. Re-run with --apply to commit changes to disk.[/yellow]"
        )


@app.command(name="heal-server")
def heal_server_command(
    host: str = typer.Option(  # noqa: B008
        "127.0.0.1", "--host", help="Host interface to bind on."
    ),
    port: int = typer.Option(  # noqa: B008
        8766, "--port", "-p", help="Port to bind on."
    ),
) -> None:
    """Start the AgentScan self-healing webhook receiver server."""
    from agentscan.remediation.webhook_receiver import run_heal_server

    run_heal_server(host=host, port=port)
