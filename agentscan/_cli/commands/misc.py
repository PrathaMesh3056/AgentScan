# agentscan/cli/commands/misc.py
#
# Miscellaneous commands: fix, list-attacks, watch, export-guardrails,
# mcp-serve, calibrate, init, benchmark, verify-claims, ui, compliance, verify,
# and the api sub-app commands (api serve, api worker).

from __future__ import annotations

import asyncio
import contextlib
import difflib
import json
from pathlib import Path

import typer
from rich import print as rprint
from rich.panel import Panel
from rich.table import Table

from agentscan._cli._preflight import bounded_error_detail, require_browser_runtime
from agentscan._cli._shared import (
    api_app,
    app,
    console,
)
from agentscan.core.models import Finding
from agentscan.core.scorer import score_band

# ── calibrate ─────────────────────────────────────────────────────────────────


@app.command()
def calibrate(
    attacker_model: str = typer.Option(
        ...,
        "--attacker-model",
        help="Installed offline Ollama model for synthetic protocol controls.",
    ),
    attacker_goal: str | None = typer.Option(
        None, "--attacker-goal", help="Optional objective for the synthetic generation control."
    ),
) -> None:
    """Run synthetic offline local model protocol controls; detection accuracy is not measured."""
    from agentscan.core.ai_client import AIClientError
    from agentscan.core.calibration import run_calibration
    from agentscan.core.external_analysis import validate_analysis_selection

    try:
        validate_analysis_selection("local", "sensitive", attacker_model)
    except AIClientError as error:
        raise typer.BadParameter(str(error)) from None

    console.print(f"Running synthetic offline controls for [cyan]{attacker_model}[/cyan]...")
    result = asyncio.run(run_calibration(attacker_model, attacker_goal=attacker_goal))
    if result.passed:
        console.print(f"[green][PASS] local synthetic controls passed[/green] — {result.detail}")
        console.print(
            "These controls check protocol behavior. Independent detection calibration is still required."
        )
    else:
        console.print(
            f"[bold red][FAIL] local synthetic controls failed[/bold red] — {result.detail}"
        )
        console.print(
            "[yellow]Review local model availability and control results before model-assisted assessment.[/yellow]"
        )
        raise typer.Exit(1)


# ── init ──────────────────────────────────────────────────────────────────────


@app.command()
def init(
    url: str = typer.Argument(
        ..., help="URL of the chat API endpoint, or the page with the widget."
    ),
    output: Path = typer.Option(  # noqa: B008
        Path("target.yaml"), "--output", "-o", help="Where to write the discovered profile."
    ),
    http: bool = typer.Option(False, "--http", help="Only probe as an HTTP JSON API (no browser)."),
    browser: bool = typer.Option(
        False, "--browser", help="Only drive a browser widget (skip the HTTP probe)."
    ),
    headed: bool = typer.Option(
        False, "--headed", help="Show the browser during widget discovery."
    ),
    no_exploit: bool = typer.Option(
        False, "--no-exploit", help="Set exploit:false in the generated profile."
    ),
) -> None:
    """Auto-discover a target (HTTP API or browser widget) and write a scan profile."""
    import yaml

    from agentscan.core.discovery import discover_http, discover_widget

    scan_settings = {
        "exploit": not no_exploit,
        "verbose": True,
        "transcript": "transcript.txt",
        "output": "report.html",
    }
    profile: dict | None = None

    # 1. Try the HTTP JSON API path first (no browser) unless --browser was given.
    if not browser:
        console.print(f"Probing [cyan]{url}[/cyan] as an HTTP chat API…")
        api = asyncio.run(discover_http(url))
        if api is not None:
            default_ok = api["message_path"] == "message" and api["response_path"].split(".")[
                -1
            ] in ("response", "text", "message", "output", "content", "raw")
            profile = {"url": url}
            if not default_ok:
                profile["request_template"] = {
                    "method": "POST",
                    "url": url,
                    "json_body": api["json_body"],
                    "message_path": api["message_path"],
                    "response_path": api["response_path"],
                }
            profile.update(scan_settings)
            console.print("[green]Found an HTTP chat API![/green] (no browser needed)")
            console.print(f"  message field: [yellow]{api['message_path']}[/yellow]")
            console.print(
                f"  reply field:   [yellow]{api['response_path']}[/yellow]"
                + ("  [dim](streaming/SSE)[/dim]" if api["streaming"] else "")
            )

    # 2. Fall back to a browser widget unless --http restricts us to the API path.
    if profile is None and not http:
        require_browser_runtime()
        console.print("Opening a browser to look for a chat widget…")
        try:
            cfg = asyncio.run(discover_widget(url, headless=not headed))
        except Exception as error:
            console.print(
                f"[red]Browser discovery failed:[/red] {bounded_error_detail(error)}. "
                "Confirm Playwright and Chromium are installed (python -m playwright install "
                "chromium) and that the URL is reachable."
            )
            raise typer.Exit(1) from None
        if cfg is not None:
            browser_block = {
                k: v
                for k, v in {
                    "open_selector": cfg.open_selector,
                    "input_selector": cfg.input_selector,
                    "response_selector": cfg.response_selector,
                    "send_selector": cfg.send_selector,
                }.items()
                if v
            }
            profile = {"url": url, "browser": browser_block, **scan_settings}
            console.print("[green]Found a chat widget![/green]")
            console.print(f"  input:    [yellow]{cfg.input_selector}[/yellow]")
            console.print(f"  response: [yellow]{cfg.response_selector}[/yellow]")
            if cfg.open_selector:
                console.print(f"  open:     [yellow]{cfg.open_selector}[/yellow]")

    if profile is None:
        console.print(
            "[red]Couldn't auto-detect the agent.[/red] Try a different URL, [bold]--headed[/bold] "
            "to watch the browser, or write the profile by hand (see the manual)."
        )
        raise typer.Exit(1)

    output.write_text(yaml.safe_dump(profile, sort_keys=False), encoding="utf-8")
    console.print(f"\nProfile written to [cyan]{output}[/cyan]. Now run:")
    console.print(f"  [bold]agentscan scan -c {output}[/bold]")


# ── benchmark ─────────────────────────────────────────────────────────────────


@app.command()
def benchmark() -> None:
    """Run a synthetic ATK-028 canary-disclosure smoke check on three local fixtures."""
    from agentscan.core.benchmark import discriminates, run_benchmark

    console.print(
        "Synthetic ATK-028 canary disclosure: three local fixtures, no independent accuracy claim."
    )
    rows = asyncio.run(run_benchmark())

    table = Table(title="AgentScan Benchmark — reference agents", show_lines=True)
    table.add_column("Reference agent", style="cyan")
    table.add_column("Expectation")
    table.add_column("Findings", justify="right")
    table.add_column("Score", justify="right")
    table.add_column("Status / coverage")
    for r in rows:
        band = score_band(r.score)
        value = f"{r.score}/100" if r.score is not None else "N/A"
        table.add_row(
            r.name,
            r.expectation,
            str(r.findings),
            f"{value}  [{band}]",
            f"{r.assessment_status} {r.tests_evaluated}/{r.tests_selected}",
        )
    console.print(table)

    if discriminates(rows):
        console.print(
            "[green][PASS] the synthetic canary-disclosure fixtures rank correctly.[/green]"
        )
    else:
        console.print(
            "[bold red][FAIL] synthetic canary ordering or coverage is incomplete.[/bold red]"
        )
        raise typer.Exit(1)


# ── verify-claims ─────────────────────────────────────────────────────────────


@app.command(name="verify-claims")
def verify_claims(
    receipt: Path = typer.Option(  # noqa: B008
        Path("benchmarks/receipts/reference_runs.json"),
        "--receipt",
        "-r",
        help="Path to committed benchmark receipt JSON to verify against.",
    ),
) -> None:
    """Deterministically verify benchmark claims against committed run receipts (no network required)."""
    import json as _json

    from agentscan.core.benchmark import BenchmarkRow, discriminates

    if not receipt.exists():
        console.print(
            f"[bold red]Receipt not found:[/bold red] {receipt}\n"
            "Generate one first with: uv run python benchmarks/run_benchmarks.py --save-receipt <file>"
        )
        raise typer.Exit(code=1)

    data = _json.loads(receipt.read_text(encoding="utf-8"))
    console.print(f"\n[bold cyan]AgentScan Verify-Claims[/bold cyan] — Receipt: {receipt}\n")

    all_passed = True
    for run in data.get("runs", []):
        rows = [
            BenchmarkRow(
                name=r["name"],
                expectation=r["expectation"],
                findings=r["findings"],
                score=r["score"],
            )
            for r in run.get("rows", [])
        ]
        passed = discriminates(rows)
        if not passed:
            all_passed = False
        status = "[green]PASS[/green]" if passed else "[bold red]FAIL[/bold red]"
        console.print(f"  Iteration {run['iteration']}: {status} ({run['duration_seconds']}s)")

    if all_passed:
        console.print(
            "\n[bold green][VERIFIED] All committed benchmark claims pass deterministically.[/bold green]\n"
        )
    else:
        console.print(
            "\n[bold red][FAILED] One or more committed claims do not verify. "
            "Re-run benchmarks and update the receipt.[/bold red]\n"
        )
        raise typer.Exit(code=1)


# ── ui ────────────────────────────────────────────────────────────────────────


@app.command()
def ui(
    report: Path | None = typer.Option(  # noqa: B008
        None, "--report", help="Scan JSON report (ScanReport) to display."
    ),
    identity: Path | None = typer.Option(  # noqa: B008
        None,
        "--identity",
        help="Directory of *.agent.json manifests for the RBAC graph view.",
    ),
    host: str = typer.Option("127.0.0.1", "--host", help="Bind address."),
    port: int = typer.Option(8765, "--port", help="Bind port."),
    token: str | None = typer.Option(
        None,
        "--token",
        envvar="AGENTSCAN_UI_TOKEN",
        help="Security token required to access the dashboard and APIs.",
    ),
) -> None:
    """Serve a local dashboard for graphs, trajectory/SSP, and traffic (no SaaS)."""
    from agentscan.ui.app import create_app, serve_app

    if host == "0.0.0.0":
        console.print(
            "[bold yellow]WARNING: Binding to 0.0.0.0 exposes the dashboard to all network interfaces. "
            "Ensure firewall rules or --token authentication are configured.[/bold yellow]"
        )

    try:
        dashboard = create_app(report, identity, token=token)
    except RuntimeError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1) from None

    def announce_bound(display_host: str, bound_port: int) -> None:
        console.print(f"AgentScan UI: [cyan]http://{display_host}:{bound_port}[/cyan]")
        if token:
            console.print("[dim]Authentication token enabled for dashboard access.[/dim]")

    try:
        serve_app(dashboard, host=host, port=port, on_bound=announce_bound)
    except RuntimeError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1) from None


# ── fix ───────────────────────────────────────────────────────────────────────


@app.command()
def fix(
    target: Path = typer.Argument(  # noqa: B008
        ...,
        help="Path to a scan report JSON, or project directory to audit & fix.",
    ),
    apply: bool = typer.Option(
        False,
        "--apply",
        help="Apply the proposed remediation changes to disk (default is dry-run).",
    ),
    kind: str | None = typer.Option(
        None,
        "--kind",
        help="Comma-separated fix kinds to run: pin_bump, ast_patch, identity_shrink, guardrails.",
    ),
    output: Path | None = typer.Option(  # noqa: B008
        None,
        "--output",
        help="Write planned/applied FixPlan to a JSON file.",
    ),
    pr: bool = typer.Option(
        False,
        "--pr",
        help="Commit fixes to a new Git branch and open a GitHub pull request via gh CLI (requires --apply).",
    ),
    branch: str | None = typer.Option(
        None,
        "--branch",
        help="Optional custom branch name for the pull request.",
    ),
    base: str = typer.Option(
        "main",
        "--base",
        help="Target base branch for GitHub pull request (default: main).",
    ),
) -> None:
    """Plan and apply safe remediations for AgentScan findings."""
    from rich.syntax import Syntax

    from agentscan.remediation.engine import RemediationEngine

    findings: list[Finding] = []
    root_path = target
    if target.is_file() and target.suffix == ".json":
        try:
            data = json.loads(target.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                raw_findings = data.get("findings", [])
                for rf in raw_findings:
                    with contextlib.suppress(Exception):
                        findings.append(Finding.model_validate(rf))
            root_path = target.parent
        except Exception as e:
            console.print(f"[red]Failed to load report from {target}: {e}[/red]")
            raise typer.Exit(1) from None
    else:
        from agentscan.identity.orchestrator import run_identity_audit
        from agentscan.supply_chain.config_auditor import scan_config as _scan_cfg
        from agentscan.supply_chain.dep_scanner import scan_dependencies
        from agentscan.supply_chain.mcp_auditor import scan_mcp_configs
        from agentscan.supply_chain.secret_scanner import scan_secrets as _scan_sec

        f_deps, _ = scan_dependencies(str(target))
        f_cfg, _ = _scan_cfg(str(target))
        f_sec, _ = _scan_sec(str(target))
        f_mcp, _ = scan_mcp_configs(str(target))
        id_rep = run_identity_audit(str(target))

        findings.extend(f_deps + f_cfg + f_sec + f_mcp + id_rep.findings)
        root_path = target

    kinds_list = [k.strip() for k in kind.split(",") if k.strip()] if kind else None
    engine = RemediationEngine(root_path)
    plan = engine.plan(findings, kinds=kinds_list)

    if not plan.actions:
        console.print("[green]No remediations needed or applicable.[/green]")
        return

    console.print(f"Planned [bold cyan]{len(plan.actions)}[/bold cyan] remediation action(s):\n")

    for i, action in enumerate(plan.actions, 1):
        console.print(
            f"[bold]{i}. [{action.kind.upper()}][/bold] Finding [cyan]{action.finding_id}[/cyan] -> [dim]{action.path}[/dim]"
        )
        diff_lines = list(
            difflib.unified_diff(
                action.before.splitlines(keepends=True),
                action.after.splitlines(keepends=True),
                fromfile=f"a/{Path(action.path).name}",
                tofile=f"b/{Path(action.path).name}",
            )
        )
        if diff_lines:
            diff_text = "".join(diff_lines)
            console.print(Syntax(diff_text, "diff", theme="monokai", line_numbers=False))
        else:
            console.print("  [dim](New file to be created)[/dim]")
        console.print()

    if apply:
        if pr:
            from agentscan.remediation.git_pr import GitPRAutomator

            automator = GitPRAutomator(repo_path=root_path)
            try:
                branch_name = automator.commit_fix_plan(plan, branch_name=branch)
                console.print(
                    f"[bold green]Successfully applied {plan.applied_count} remediation(s) to disk.[/bold green]"
                )
                console.print(
                    f"[bold cyan]Created Git branch and committed fixes:[/bold cyan] {branch_name}"
                )
                pr_body = automator.generate_pr_body(plan)
                finding_keys = ", ".join(sorted({a.finding_id for a in plan.actions}))
                pr_title = f"fix(agentscan): remediate {finding_keys}"
                pr_url = automator.create_pr(
                    branch_name=branch_name,
                    base=base,
                    title=pr_title,
                    body=pr_body,
                    push=True,
                )
                if pr_url:
                    console.print(f"[bold green]Pull request opened:[/bold green] {pr_url}")
                else:
                    console.print(
                        "[yellow]Pull request could not be opened automatically (gh CLI unavailable or error). Branch remains committed locally.[/yellow]"
                    )
            except Exception as e:
                console.print(f"[red]Git PR automation failed: {e}[/red]")
                raise typer.Exit(1) from None
        else:
            applied_count = plan.apply()
            console.print(
                f"[bold green]Successfully applied {applied_count} remediation(s) to disk.[/bold green]"
            )
    else:
        if pr:
            console.print(
                "[yellow]Warning: --pr requires --apply to commit fixes. No changes were written or committed.[/yellow]"
            )
        else:
            console.print(
                "[yellow]Dry-run mode: no files modified. Pass --apply to write changes to disk.[/yellow]"
            )

    if output:
        output.write_text(plan.model_dump_json(indent=2), encoding="utf-8")
        console.print(f"FixPlan written to [cyan]{output}[/cyan]")


# ── list-attacks ──────────────────────────────────────────────────────────────


@app.command("list-attacks")
def list_attacks() -> None:
    """List all registered attack modules."""
    from agentscan.attacks.registry import registry

    registry.load_all()

    modules = registry.get_all()

    table = Table(title="AgentScan Attack Modules", show_lines=True)
    table.add_column("Attack ID", style="cyan", no_wrap=True)
    table.add_column("Name", style="bold", no_wrap=True)
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


# ── watch ─────────────────────────────────────────────────────────────────────


@app.command()
def watch(
    url: str = typer.Argument(..., help="Target agent URL to monitor."),
    interval: int = typer.Option(60, "--interval", "-i", help="Polling interval in seconds."),
    iterations: int = typer.Option(
        1, "--iterations", "-n", help="Number of check cycles (default: 1)."
    ),
    webhook: str | None = typer.Option(
        None, "--webhook", "-w", help="Webhook URL for alert dispatch (Slack/Discord)."
    ),
    canary: str | None = typer.Option(
        None, "--canary", "-c", help="Custom canary token string to verify."
    ),
) -> None:
    """Run continuous monitoring sentinel against an agent endpoint."""
    from agentscan.core.connectors import HttpJsonConnector
    from agentscan.core.models import Target
    from agentscan.sentinel.watcher import ContinuousWatcher

    target = Target(url=url)
    watcher = ContinuousWatcher(
        target=target,
        interval_seconds=interval,
        max_iterations=iterations,
        webhook_url=webhook,
        canary_token=canary,
    )

    console.print(f"[bold cyan]AgentScan Sentinel[/bold cyan] monitoring [green]{url}[/green]")
    console.print(f"Canary Token: [yellow]{watcher.canary_sentinel.canary_token}[/yellow]")
    if webhook:
        console.print(f"Alert Webhook: [dim]{webhook}[/dim]")

    connector = HttpJsonConnector(target)

    def _on_iter(num: int, findings: list[Finding]) -> None:
        if findings:
            console.print(
                f"Cycle {num}: [bold red]ALERT[/bold red] - {len(findings)} finding(s) detected!"
            )
        else:
            console.print(
                f"Cycle {num}: [bold green]PASS[/bold green] - Canary secure, 0 findings."
            )

    findings = asyncio.run(watcher.run_loop(connector, callback=_on_iter))
    if findings:
        console.print(
            f"\n[bold red]Sentinel detected {len(findings)} vulnerability/leakage event(s).[/bold red]"
        )
    else:
        console.print("\n[bold green]Sentinel completed cleanly with 0 regressions.[/bold green]")


# ── export-guardrails ─────────────────────────────────────────────────────────


@app.command(name="export-guardrails")
def export_guardrails(
    target_format: str = typer.Option(
        "litellm", "--format", "-f", help="Gateway format: 'litellm', 'cloudflare', or 'bedrock'."
    ),
    output: Path = typer.Option(  # noqa: B008
        ..., "--output", "-o", help="File to write exported guardrail configuration."
    ),
) -> None:
    """Export AgentScan threat defenses to LiteLLM, Cloudflare AI Gateway, or AWS Bedrock."""
    from agentscan.reporting.gateway_exporter import (
        export_bedrock_guardrails,
        export_cloudflare_guardrails,
        export_litellm_guardrails,
    )

    fmt = target_format.lower()
    if fmt == "litellm":
        export_litellm_guardrails(output_path=output)
    elif fmt == "cloudflare":
        export_cloudflare_guardrails(output_path=output)
    elif fmt == "bedrock":
        export_bedrock_guardrails(output_path=output)
    else:
        console.print(
            f"[red]Unknown format '{target_format}'. Supported: 'litellm', 'cloudflare', 'bedrock'.[/red]"
        )
        raise typer.Exit(1)

    console.print(
        f"[bold green]Exported {fmt.upper()} guardrails to [cyan]{output}[/cyan][/bold green]"
    )


# ── mcp-serve ─────────────────────────────────────────────────────────────────


@app.command(name="mcp-serve")
def mcp_serve() -> None:
    """Run native Model Context Protocol (MCP) JSON-RPC server over stdio."""
    from agentscan.mcp.server import run_mcp_server

    run_mcp_server()


# ── compliance ────────────────────────────────────────────────────────────────


@app.command(name="compliance")
def compliance_command(
    report_file: Path = typer.Argument(..., help="Path to input scan or audit JSON report."),  # noqa: B008
    framework: str = typer.Option(  # noqa: B008
        "eu-ai-act",
        "--framework",
        "-f",
        help="Target compliance framework: 'eu-ai-act' or 'nist-ai-rmf'.",
    ),
    output: Path | None = typer.Option(  # noqa: B008
        None, "--output", "-o", help="Output path for compliance report."
    ),
    format: str = typer.Option(  # noqa: B008
        "markdown", "--format", help="Output format: 'json' or 'markdown'."
    ),
) -> None:
    """Evaluate scan results against enterprise regulatory frameworks (EU AI Act, NIST AI RMF)."""
    from agentscan.reporting.compliance_pack import (
        evaluate_eu_ai_act,
        evaluate_iso_42001,
        evaluate_mitre_atlas,
        evaluate_nist_ai_rmf,
    )

    if not report_file.exists():
        console.print(f"[bold red]Error: Report file not found:[/bold red] {report_file}")
        raise typer.Exit(code=1)

    try:
        data = json.loads(report_file.read_text(encoding="utf-8"))
    except Exception as e:
        console.print(f"[bold red]Failed to parse report file:[/bold red] {e}")
        raise typer.Exit(code=1) from None

    raw_findings = (
        data.get("findings", [])
        if isinstance(data, dict)
        else (data if isinstance(data, list) else [])
    )

    norm_fw = framework.lower().strip()
    if norm_fw in ("eu-ai-act", "eu_ai_act", "eu"):
        comp_report = evaluate_eu_ai_act(raw_findings)
    elif norm_fw in ("nist-ai-rmf", "nist_ai_rmf", "nist"):
        comp_report = evaluate_nist_ai_rmf(raw_findings)
    elif norm_fw in ("mitre-atlas", "mitre_atlas", "mitre", "atlas"):
        comp_report = evaluate_mitre_atlas(raw_findings)
    elif norm_fw in ("iso-42001", "iso_42001", "iso"):
        comp_report = evaluate_iso_42001(raw_findings)
    else:
        console.print(
            f"[bold red]Unsupported compliance framework:[/bold red] {framework}. "
            "Choose 'eu-ai-act', 'nist-ai-rmf', 'mitre-atlas', or 'iso-42001'."
        )
        raise typer.Exit(code=1)

    status_color = (
        "green"
        if comp_report.overall_status.value == "COMPLIANT"
        else "yellow"
        if comp_report.overall_status.value == "PARTIALLY_COMPLIANT"
        else "red"
    )
    console.print(
        Panel(
            f"[bold cyan]Enterprise Compliance Assessment[/bold cyan] — [yellow]{comp_report.framework.value.upper()}[/yellow]\n"
            f"Overall Status: [{status_color}][bold]{comp_report.overall_status.value}[/bold][/{status_color}]\n"
            f"Compliance Score: [bold cyan]{comp_report.compliance_score if comp_report.compliance_score is not None else 'N/A'}[/bold cyan]\n"
            f"Mapped security findings: [bold]{len(comp_report.findings)}[/bold]",
            title="[bold blue]Regulatory Compliance Pack[/bold blue]",
        )
    )

    table = Table(title=f"{comp_report.framework.value.upper()} Section Breakdown", show_lines=True)
    table.add_column("Section / Function", style="cyan", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("Findings", no_wrap=True)
    table.add_column("Description")

    for sec_id, sec_data in comp_report.evaluated_sections.items():
        st = sec_data.get("status", "NOT_ASSESSED")
        cnt = str(sec_data.get("finding_count", 0))
        st_color = (
            "green" if st == "COMPLIANT" else "yellow" if st == "PARTIALLY_COMPLIANT" else "red"
        )
        table.add_row(
            sec_id,
            f"[{st_color}]{st}[/{st_color}]",
            cnt,
            sec_data.get("description", ""),
        )
    console.print(table)

    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        if format.lower() == "json":
            output.write_text(
                json.dumps(comp_report.model_dump(mode="json"), indent=2),
                encoding="utf-8",
            )
        else:
            output.write_text(comp_report.to_markdown(), encoding="utf-8")
        console.print(f"Compliance report exported to [cyan]{output}[/cyan]")


# ── verify ────────────────────────────────────────────────────────────────────


@app.command(name="verify")
def verify_command(
    report_file: Path = typer.Argument(  # noqa: B008
        ..., help="Path to input scan or audit JSON report."
    ),
    certificate_file: Path | None = typer.Option(  # noqa: B008
        None,
        "--certificate",
        "-c",
        help="Path to external cryptographic certificate JSON. If omitted, checks report's embedded 'certificate' field.",
    ),
    sign: bool = typer.Option(  # noqa: B008
        False,
        "--sign",
        "-s",
        help="Generate and embed/save a cryptographic audit verification certificate.",
    ),
    key: str | None = typer.Option(  # noqa: B008
        None,
        "--key",
        "-k",
        help="Optional secret key for HMAC signature generation or verification.",
    ),
    output: Path | None = typer.Option(  # noqa: B008
        None,
        "--output",
        "-o",
        help="Path to save the signed report or standalone certificate.",
    ),
) -> None:
    """Verify cryptographic audit integrity and tamper-evidence of AgentScan reports."""
    from agentscan.reporting.audit_verifier import sign_audit_report, verify_audit_certificate

    if not report_file.exists():
        console.print(f"[bold red]Error: Report file not found:[/bold red] {report_file}")
        raise typer.Exit(code=1)

    try:
        report_data = json.loads(report_file.read_text(encoding="utf-8"))
    except Exception as e:
        console.print(f"[bold red]Failed to parse report file:[/bold red] {e}")
        raise typer.Exit(code=1) from None

    if not isinstance(report_data, dict):
        console.print("[bold red]Error: Report must be a valid JSON object dictionary.[/bold red]")
        raise typer.Exit(code=1)

    if sign:
        try:
            cert = sign_audit_report(report_data, secret_key=key)
        except ValueError as exc:
            console.print(f"[red]{exc}[/red]")
            raise typer.Exit(code=1) from exc
        console.print(
            Panel(
                f"[bold green]Report Cryptographically Certified[/bold green]\n"
                f"Algorithm: [cyan]{cert['algorithm']}[/cyan]\n"
                f"SHA-256 Digest: [yellow]{cert['report_sha256']}[/yellow]\n"
                f"HMAC Signature: [magenta]{cert['signature']}[/magenta]\n"
                f"Issued At: [dim]{cert['issued_at']}[/dim]",
                title="[bold blue]Audit Certificate Generator[/bold blue]",
            )
        )

        if output is not None:
            output.parent.mkdir(parents=True, exist_ok=True)
            if output.suffix.lower() == ".cert" or "cert" in output.name.lower():
                output.write_text(json.dumps(cert, indent=2), encoding="utf-8")
                console.print(f"Certificate written to [cyan]{output}[/cyan]")
            else:
                report_data["certificate"] = cert
                output.write_text(json.dumps(report_data, indent=2), encoding="utf-8")
                console.print(f"Signed report written to [cyan]{output}[/cyan]")
        else:
            report_data["certificate"] = cert
            report_file.write_text(json.dumps(report_data, indent=2), encoding="utf-8")
            console.print(f"Certificate embedded directly into [cyan]{report_file}[/cyan]")
        return

    # Verification Mode
    cert_to_verify = None
    if certificate_file is not None:
        if not certificate_file.exists():
            console.print(f"[bold red]Certificate file not found:[/bold red] {certificate_file}")
            raise typer.Exit(code=1)
        try:
            cert_to_verify = json.loads(certificate_file.read_text(encoding="utf-8"))
        except Exception as e:
            console.print(f"[bold red]Failed to parse certificate file:[/bold red] {e}")
            raise typer.Exit(code=1) from None
    else:
        cert_to_verify = report_data.get("certificate")

    if not cert_to_verify:
        console.print(
            "[bold red]Error:[/bold red] No certificate found. Provide --certificate <file> or use --sign to certify."
        )
        raise typer.Exit(code=1)

    is_valid, reason = verify_audit_certificate(report_data, cert_to_verify, secret_key=key)

    if is_valid:
        console.print(
            Panel(
                f"[bold green]CRYPTOGRAPHIC AUDIT VERIFICATION PASSED[/bold green]\n"
                f"Algorithm: [cyan]{cert_to_verify.get('algorithm', 'HMAC-SHA256')}[/cyan]\n"
                f"Report SHA-256: [yellow]{cert_to_verify.get('report_sha256')}[/yellow]\n"
                f"Integrity Status: [bold green]UNCOMPROMISED (Tamper-Evident)[/bold green]\n"
                f"Issued At: [dim]{cert_to_verify.get('issued_at', 'Unknown')}[/dim]",
                title="[bold green]Audit Verifier: Valid[/bold green]",
            )
        )
    else:
        console.print(
            Panel(
                f"[bold red]CRYPTOGRAPHIC AUDIT VERIFICATION FAILED[/bold red]\n"
                f"Reason: [bold yellow]{reason}[/bold yellow]\n"
                f"Integrity Status: [bold red]TAMPERED OR INVALID SIGNATURE[/bold red]",
                title="[bold red]Audit Verifier: Integrity Breach[/bold red]",
            )
        )
        raise typer.Exit(code=1)


# ── api serve ─────────────────────────────────────────────────────────────────


@api_app.command("serve")
def api_serve(
    host: str = typer.Option("0.0.0.0", help="Bind host"),
    port: int = typer.Option(8080, help="Bind port"),
    workers: int = typer.Option(1, help="Number of uvicorn workers"),
    reload: bool = typer.Option(False, help="Enable hot reload (dev only)"),
) -> None:
    """Start the AgentScan REST API server."""
    try:
        import uvicorn
    except ImportError:
        rprint("[red]uvicorn is not installed. Run: uv sync --extra api[/red]")
        raise SystemExit(1) from None
    rprint(f"[green]Starting AgentScan API on {host}:{port}[/green]")
    uvicorn.run(
        "agentscan.api.server:app",
        host=host,
        port=port,
        workers=workers,
        reload=reload,
    )


# ── api worker ────────────────────────────────────────────────────────────────


@api_app.command("worker")
def api_worker(
    deep: bool = typer.Option(False, help="Run as a DEEP (GPU) worker"),
) -> None:
    """Start a background scan worker that processes jobs from Redis Streams."""
    import asyncio as _asyncio
    import os as _os

    if deep:
        _os.environ["AGENTSCAN_DEEP_WORKER"] = "true"
    rprint("[green]Starting AgentScan scan worker...[/green]")
    from agentscan.api.worker import worker_loop

    _asyncio.run(worker_loop())
