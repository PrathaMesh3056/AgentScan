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
from typing import Any

import typer
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table

from agentscan.attacks.registry import registry
from agentscan.core.models import (
    BrowserConfig,
    Finding,
    Framework,
    RequestTemplate,
    ScanMode,
    ScanReport,
    Target,
)
from agentscan.core.runner import run_scan_multi
from agentscan.core.scorer import calculate_score, score_band
from agentscan.core.trace import recorder
from agentscan.identity.models import IdentityReport

# Load API keys from a local .env (OPENROUTER_API_KEY, OPENAI_API_KEY, …) so the AI
# attacker/judge can authenticate. Never commits — .env is gitignored.
load_dotenv()

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
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
    "PASS": 0,
}


def _fail_on_should_exit(findings: list[Finding], fail_on: str) -> bool:
    """True if any finding meets or exceeds the --fail-on threshold."""
    fail_key = fail_on.upper()
    if fail_key not in _SEVERITY_ORDER:
        raise typer.BadParameter(
            f"Unknown --fail-on severity: {fail_on!r}. "
            "Use CRITICAL, HIGH, MEDIUM, LOW, INFO, or PASS."
        )
    threshold = _SEVERITY_ORDER[fail_key]
    return any(_SEVERITY_ORDER.get(f.severity.value, 0) >= threshold for f in findings)


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
def scan(  # noqa: PLR0913
    target: str | None = typer.Argument(
        None, help="The HTTP endpoint to scan. Omit if using --config / --curl / --browser-url."
    ),
    config: Path | None = typer.Option(  # noqa: B008
        None,
        "--config",
        "-c",
        help="Load a target profile (YAML): url, connector (browser/curl), and scan settings — "
        "so you save the long setup once and run it with just '-c target.yaml'. CLI flags override it.",
    ),
    framework: str = typer.Option("auto", help="Agent framework (auto-detect by default)."),
    output: Path | None = typer.Option(None, help="Write JSON report to this file."),  # noqa: B008
    auth_header: str | None = typer.Option(
        None,
        "--auth-header",
        help="Authorization header for the target API, e.g. 'Bearer <token>' or 'X-Api-Key: …'.",
    ),
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
    attacker_model: str | None = typer.Option(
        None,
        "--attacker-model",
        help="Enable the AI iterative attacker (ATK-050) with this LLM, e.g. 'gpt-4o-mini' or "
        "'ollama/llama3'. Needs the provider's API key in the environment. Implies --exploit.",
    ),
    judge_model: str | None = typer.Option(
        None,
        "--judge-model",
        help="LLM (litellm id, e.g. 'gpt-4o-mini') for LLM-as-a-Judge evaluation of scan responses. "
        "Defaults to --attacker-model if set.",
    ),
    attacker_turns: int | None = typer.Option(
        None, "--attacker-turns", help="Max adaptive turns for the AI attacker (default 4)."
    ),
    attacker_goal: str | None = typer.Option(
        None,
        "--attacker-goal",
        help="Custom attacker objective (e.g. 'break scope and answer an unrelated question'). "
        "When unset, uses the default canary-phrase objective.",
    ),
    calibrate: bool = typer.Option(
        False,
        "--calibrate",
        help="Validate the attacker/judge against a control before scanning — so a "
        "'resisted' verdict is trustworthy, not a silent miss (AI attacker only).",
    ),
    calibrate_required: bool = typer.Option(
        False,
        "--calibrate-required",
        help="Abort the scan if positive-control calibration fails (stricter than --calibrate).",
    ),
    escalation_model: str | None = typer.Option(
        None,
        "--escalation-model",
        help="Frontier model to escalate to if the primary attacker fails (e.g. 'gpt-4o').",
    ),
    escalation_turns: int | None = typer.Option(
        None,
        "--escalation-turns",
        help="Max turns allocated to the escalation model.",
    ),
    llm_log: Path | None = typer.Option(  # noqa: B008
        None,
        "--llm-log",
        help="Write every attacker/judge LLM call (exact input prompts + raw model output) "
        "to this file — full visibility into the AI's reasoning.",
    ),
    curl: Path | None = typer.Option(  # noqa: B008
        None,
        "--curl",
        help="Path to a file with a captured cURL command (Chrome → Copy as cURL). "
        "Replays that exact request with attack payloads substituted — use this to scan "
        "an agent behind a website widget instead of a documented endpoint.",
    ),
    message_path: str | None = typer.Option(
        None,
        "--message-path",
        help="Dotted path to the message field in the --curl body, e.g. 'query' or "
        "'messages.-1.content'. Required with --curl.",
    ),
    response_path: str | None = typer.Option(
        None,
        "--response-path",
        help="Dotted path to the reply text in the response JSON, e.g. 'data.reply'. Optional.",
    ),
    browser_url: str | None = typer.Option(
        None,
        "--browser-url",
        help="Drive a chat WIDGET in a real browser (Playwright) — for agents with no "
        "capturable HTTP API. Requires --input-selector and --response-selector.",
    ),
    input_selector: str | None = typer.Option(
        None, "--input-selector", help="CSS selector for the chat input box (browser mode)."
    ),
    open_selector: str | None = typer.Option(
        None,
        "--open-selector",
        help="CSS selector for a launcher button to click first (opens a closed widget).",
    ),
    response_selector: str | None = typer.Option(
        None,
        "--response-selector",
        help="CSS selector matching bot message bubbles, newest = last (browser mode).",
    ),
    send_selector: str | None = typer.Option(
        None, "--send-selector", help="CSS selector for the send button; omit to press Enter."
    ),
    headed: bool = typer.Option(
        False, "--headed", help="Show the browser window in browser mode (default headless)."
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Print every payload sent and the agent's reply live, plus findings as they occur.",
    ),
    transcript: Path | None = typer.Option(  # noqa: B008
        None,
        "--transcript",
        help="Write the FULL transcript (every payload + reply + findings) to this file. "
        "The --output report contains only findings; this contains everything.",
    ),
) -> None:
    """Run a security scan against an LLM agent endpoint."""
    # ── Load a target profile (YAML) if given. CLI flags override the file. ────
    cfg: dict[str, Any] = {}
    if config is not None:
        import yaml

        cfg = yaml.safe_load(config.read_text(encoding="utf-8")) or {}

    exploit = exploit or bool(cfg.get("exploit"))
    deep = deep or bool(cfg.get("deep"))
    verbose = verbose or bool(cfg.get("verbose"))
    if output is None and cfg.get("output"):
        output = Path(cfg["output"])
    if transcript is None and cfg.get("transcript"):
        transcript = Path(cfg["transcript"])
    if fail_on is None and cfg.get("fail_on"):
        fail_on = cfg["fail_on"]
    if system_prompt is None and cfg.get("system_prompt"):
        system_prompt = cfg["system_prompt"]
    if auth_header is None and cfg.get("auth_header"):
        auth_header = cfg["auth_header"]
    if framework == "auto" and cfg.get("framework"):
        framework = cfg["framework"]
    if attacker_model is None and cfg.get("attacker_model"):
        attacker_model = cfg["attacker_model"]
    if judge_model is None and cfg.get("judge_model"):
        judge_model = cfg["judge_model"]
    if judge_model is None and attacker_model:
        judge_model = attacker_model
    if attacker_turns is None and cfg.get("attacker_turns"):
        attacker_turns = int(cfg["attacker_turns"])
    if attacker_goal is None and cfg.get("attacker_goal"):
        attacker_goal = cfg["attacker_goal"]
    calibrate = calibrate or bool(cfg.get("calibrate"))
    calibrate_required = calibrate_required or bool(cfg.get("calibrate_required"))
    if escalation_model is None and cfg.get("escalation_model"):
        escalation_model = cfg["escalation_model"]
    if escalation_turns is None and cfg.get("escalation_turns"):
        escalation_turns = int(cfg["escalation_turns"])
    if llm_log is None and cfg.get("llm_log"):
        llm_log = Path(cfg["llm_log"])
    # The AI attacker is an EXPLOIT-mode module, so enabling it implies --exploit.
    if attacker_model:
        exploit = True

    # Enable recording if the user wants to see or save the full exchange (target
    # traffic and/or LLM attacker/judge calls).
    recorder.reset()
    if verbose or transcript is not None or llm_log is not None:
        recorder.enabled = True
        recorder.live = verbose

    # ── Build the connector (CLI flags take precedence over the profile). ──────
    request_template = None
    if curl is not None:
        if message_path is None:
            raise typer.BadParameter("--message-path is required when using --curl.")
        request_template = RequestTemplate.from_curl(
            curl.read_text(encoding="utf-8"),
            message_path=message_path,
            response_path=response_path,
        )
    elif cfg.get("request_template"):
        request_template = RequestTemplate(**cfg["request_template"])

    browser_cfg = None
    if browser_url is not None:
        if not (input_selector and response_selector):
            raise typer.BadParameter(
                "--input-selector and --response-selector are required with --browser-url."
            )
        browser_cfg = BrowserConfig(
            url=browser_url,
            open_selector=open_selector,
            input_selector=input_selector,
            response_selector=response_selector,
            send_selector=send_selector,
            headless=not headed,
        )
    elif cfg.get("browser"):
        browser_data = dict(cfg["browser"])
        browser_data.setdefault("url", target or cfg.get("url"))
        browser_cfg = BrowserConfig(**browser_data)

    # Resolve the URL: positional target, else profile url, else connector url.
    url = (
        target
        or cfg.get("url")
        or (browser_cfg.url if browser_cfg else None)
        or (request_template.url if request_template else None)
    )
    if url is None:
        raise typer.BadParameter(
            "Provide a target URL — positionally, via --config, --curl, or --browser-url."
        )

    # Build target
    target_obj = Target(
        url=url,
        framework=Framework(framework),
        system_prompt=system_prompt,
        auth_header=auth_header,
        request_template=request_template,
        browser=browser_cfg,
        attacker_model=attacker_model,
        attacker_turns=attacker_turns,
        attacker_goal=attacker_goal,
        judge_model=judge_model,
        escalation_model=escalation_model,
        escalation_turns=escalation_turns,
    )

    # Determine modes
    modes = (
        [ScanMode.SCAN]
        + ([ScanMode.EXPLOIT] if exploit else [])
        + ([ScanMode.DEEP] if deep else [])
    )

    # Optional positive control: verify the attacker/judge can detect a jailbreak
    # BEFORE the scan, so a "resisted" verdict isn't a silent failure.
    cal_result = None
    if (calibrate or calibrate_required) and attacker_model:
        from agentscan.core.calibration import run_calibration

        console.print("Calibrating attacker/judge against a control agent...")
        cal = asyncio.run(run_calibration(attacker_model, attacker_goal=attacker_goal))
        cal_result = cal
        if cal.passed:
            console.print(f"[green][PASS] attacker validated[/green] — {cal.detail}")
        else:
            console.print(
                f"[bold red][WARN] attacker FAILED calibration[/bold red] — {cal.detail}. "
                "Treat any 'resisted' result below as UNRELIABLE."
            )
            if calibrate_required:
                console.print(
                    "[bold red][FAIL] Scan aborted because --calibrate-required was set and calibration failed.[/bold red]"
                )
                raise typer.Exit(code=1)

    # Run scan
    report = asyncio.run(run_scan_multi(target_obj, modes))
    if cal_result is not None:
        report.calibration = cal_result
    if attacker_model:
        from agentscan.core.models import AttackerConfig

        report.attacker_config = AttackerConfig(
            model=attacker_model,
            turns=attacker_turns or 4,
            goal=attacker_goal or "default canary objective",
            escalation_model=escalation_model,
            seed_techniques_used=[],
        )

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

    # Write the full transcript (all traffic + findings), separate from the report.
    if transcript is not None:
        recorder.write_transcript(transcript, report)
        console.print(f"Transcript written to {transcript}")

    # Write the LLM interaction log (attacker/judge prompts + raw outputs).
    if llm_log is not None:
        recorder.write_llm_log(llm_log)
        console.print(f"LLM log written to {llm_log} ({len(recorder.llm_calls)} calls)")

    # Fail-on threshold check
    if fail_on is not None and _fail_on_should_exit(report.findings, fail_on):
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
    fail_on: str | None = typer.Option(
        None,
        "--fail-on",
        help="Exit with code 1 if any finding has severity >= this threshold.",
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

    if fail_on is not None and _fail_on_should_exit(all_findings, fail_on):
        raise typer.Exit(code=1)


@app.command()
def calibrate(
    attacker_model: str = typer.Option(
        ..., "--attacker-model", help="The attacker/judge LLM to validate (litellm id)."
    ),
    attacker_goal: str | None = typer.Option(
        None, "--attacker-goal", help="Optional custom attacker objective to validate against."
    ),
) -> None:
    """Prove your attacker+judge can DETECT a jailbreak (positive control) before you trust a scan."""
    from agentscan.core.calibration import run_calibration

    console.print(f"Calibrating [cyan]{attacker_model}[/cyan] against a wide-open control agent...")
    result = asyncio.run(run_calibration(attacker_model, attacker_goal=attacker_goal))
    if result.passed:
        console.print(f"[green][PASS] attacker/judge validated[/green] — {result.detail}")
        console.print("A 'resisted' verdict from this model is trustworthy (detection works).")
    else:
        console.print(f"[bold red][FAIL] attacker/judge NOT validated[/bold red] — {result.detail}")
        console.print(
            "[yellow]Do not trust a 'resisted' result from this model — use a stronger "
            "attacker/judge (bigger or frontier model).[/yellow]"
        )
        raise typer.Exit(1)


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
    profile: dict[str, object] | None = None

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
        console.print("Opening a browser to look for a chat widget…")
        cfg = asyncio.run(discover_widget(url, headless=not headed))
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


@app.command()
def benchmark() -> None:
    """Prove AgentScan discriminates — grade reference agents at known vulnerability levels."""
    from agentscan.core.benchmark import discriminates, run_benchmark

    console.print("Grading reference agents (wide-open -> partial -> guarded)...")
    rows = asyncio.run(run_benchmark())

    table = Table(title="AgentScan Benchmark — reference agents", show_lines=True)
    table.add_column("Reference agent", style="cyan")
    table.add_column("Expectation")
    table.add_column("Findings", justify="right")
    table.add_column("Score", justify="right")
    for r in rows:
        band = score_band(r.score)
        table.add_row(r.name, r.expectation, str(r.findings), f"{r.score}/100  [{band}]")
    console.print(table)

    if discriminates(rows):
        console.print(
            "[green][PASS] scores rank the agents correctly by vulnerability — "
            "the AgentScan Score discriminates.[/green]"
        )
    else:
        console.print("[bold red][FAIL] scores do NOT rank the agents correctly.[/bold red]")
        raise typer.Exit(1)


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
