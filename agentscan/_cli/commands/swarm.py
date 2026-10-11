# agentscan/cli/commands/swarm.py
#
# 'agentscan swarm' command — multi-agent swarm orchestration.

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import typer
from rich.panel import Panel
from rich.table import Table

from agentscan._cli._shared import _SEVERITY_COLOURS, _confirm_exploit_mode, app, console


@app.command(name="swarm")
def swarm(  # noqa: PLR0913
    target: str = typer.Argument(..., help="The HTTP endpoint of the AI agent to red-team."),
    team: str = typer.Option(
        "trio",
        "--team",
        "-t",
        help="Swarm team preset ('trio', 'agency', 'stealth') or path to a custom YAML team profile.",
    ),
    model: str | None = typer.Option(
        None,
        "--model",
        "-m",
        help="Optional ollama/MODEL or external provider/MODEL; default is deterministic.",
    ),
    data_classification: str = typer.Option(
        "sensitive",
        "--data-classification",
        help="sensitive (default) or non_sensitive. External analysis requires explicit non_sensitive designation.",
    ),
    rounds: int | None = typer.Option(
        None,
        "--rounds",
        "-r",
        help="Maximum collaborative execution rounds across agents.",
    ),
    output: Path | None = typer.Option(  # noqa: B008
        None,
        "--output",
        "-o",
        help="Write SwarmReport JSON to this file.",
    ),
    offline: bool = typer.Option(
        False,
        "--offline",
        help="Run swarm in deterministic offline heuristic mode without external LLM API calls.",
    ),
    verbose: bool = typer.Option(
        True,
        "--verbose/--quiet",
        "-v/-q",
        help="Print agent turns, blackboard intelligence, and findings live.",
    ),
) -> None:
    """Run collaborative multi-agent red-team swarms against an AI agent."""
    _confirm_exploit_mode()

    from agentscan.core.models import Target
    from agentscan.swarm.coordinator import SwarmCoordinator
    from agentscan.swarm.presets import resolve_team

    try:
        team_cfg = resolve_team(team).model_copy(deep=True)
    except Exception as e:
        console.print(f"[bold red]Error loading swarm team:[/bold red] {e}")
        raise typer.Exit(code=1) from None

    if rounds is not None:
        team_cfg.max_rounds = rounds

    from agentscan.core.ai_client import AIClientError
    from agentscan.core.external_analysis import validate_analysis_selection

    offline = offline or model is None
    analysis_mode = (
        "deterministic"
        if offline
        else "local"
        if (model or "").startswith("ollama/")
        else "external"
    )
    if data_classification not in {"sensitive", "non_sensitive"}:
        raise typer.BadParameter("--data-classification must be sensitive or non_sensitive.")
    try:
        validate_analysis_selection(analysis_mode, data_classification, model or "")
    except AIClientError as exc:
        raise typer.BadParameter(str(exc)) from None
    mode_label = "OFFLINE (Heuristic)" if offline else (model or team_cfg.default_model)
    console.print(
        Panel(
            f"[bold cyan]AgentScan Swarm[/bold cyan] — [yellow]{team_cfg.name}[/yellow]\n"
            f"Strategy: [green]{team_cfg.strategy.value}[/green]  |  "
            f"Agents: [magenta]{len(team_cfg.agents)}[/magenta]  |  "
            f"Rounds: [cyan]{team_cfg.max_rounds}[/cyan]  |  "
            f"Mode: [bold]{mode_label}[/bold]\n"
            f"Target: [underline]{target}[/underline]",
            title="[bold red]Swarm Red-Team Session[/bold red]",
        )
    )

    coordinator = SwarmCoordinator(
        team_config=team_cfg,
        model_override=model,
        offline=offline,
    )
    target_obj = Target(
        url=target,
        analysis_mode=analysis_mode,
        local_model=(model or "ollama/llama3.2") if analysis_mode == "local" else "ollama/llama3.2",
        external_model=(model or "") if analysis_mode == "external" else "",
        data_classification=data_classification,
    )

    def _on_turn(round_num: int, agent_name: str, record: Any) -> None:
        if not verbose:
            return
        role_style = (
            "cyan"
            if record.agent_role.value == "RECON"
            else "yellow"
            if record.agent_role.value == "BYPASS"
            else "red"
        )
        status_icon = (
            "[bold green][INTEL][/bold green]" if record.extracted_intel else "[dim][PROBE][/dim]"
        )
        console.print(
            f"[dim]R{round_num}[/dim] [{role_style}][{agent_name} ({record.agent_role.value})][/{role_style}] {status_icon} "
            f"Prompt: [italic]{record.prompt[:80]}...[/italic]"
        )
        if record.extracted_intel:
            for item in record.extracted_intel:
                console.print(f"    [green]+ Intel [{item.key}]:[/green] {str(item.value)[:120]}")
        if record.finding:
            console.print(
                f"    [bold red]FINDING:[/bold red] [{record.finding.severity.value}] {record.finding.attack_name}"
            )

    report = asyncio.run(coordinator.run_swarm(target_obj, callback=_on_turn))

    # Print Summary Table
    score_text = f"{report.score}/100" if report.score is not None else "N/A"
    console.print(
        f"\n[bold]Swarm Execution Complete[/bold] — Score: [bold cyan]{score_text}[/bold cyan]"
    )
    console.print(f"Total Turns: {len(report.turns)}  |  Findings: {len(report.findings)}")

    if report.findings:
        table = Table(title="Swarm Vulnerability Findings", show_lines=True)
        table.add_column("Attack ID", style="cyan", no_wrap=True)
        table.add_column("Severity", no_wrap=True)
        table.add_column("Description")
        for f in report.findings:
            sev = f.severity.value
            col = _SEVERITY_COLOURS.get(sev, "white")
            table.add_row(f.attack_id, f"[{col}]{sev}[/{col}]", f.description)
        console.print(table)
    else:
        console.print("No findings recorded. Review the executed turns and assessment scope.")

    if output is not None:
        output.write_text(json.dumps(report.model_dump(mode="json"), indent=2), encoding="utf-8")
        console.print(f"Swarm report written to [cyan]{output}[/cyan]")
