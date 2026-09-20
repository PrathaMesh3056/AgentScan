# agentscan/cli.py
#
# CLI entry point for AgentScan.
#
# Commands:
#   agentscan scan   <target> [--framework auto] [--output report.json] [--fail-on CRITICAL]
#                             [--mutate]
#   agentscan audit  <path>   [--scan-deps] [--scan-config] [--scan-secrets]
#                             [--scan-typo] [--scan-mcp] [--scan-identity]
#                             [--scan-semgrep] [--aibom]
#   agentscan ui [--report report.json] [--identity manifests/]
#   agentscan list-attacks
#
# Uses Typer for argument parsing and Rich for coloured terminal output.

from __future__ import annotations

import asyncio
import contextlib
import difflib
import json
from pathlib import Path
from typing import Any

import typer
from dotenv import load_dotenv
from rich import print as rprint
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
    SspClass,
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

api_app = typer.Typer(help="AgentScan REST API server commands.")
app.add_typer(api_app, name="api")

console = Console()


def _version_callback(value: bool) -> None:
    if value:
        import importlib.metadata

        try:
            ver = importlib.metadata.version("agentscan")
        except Exception:
            ver = "0.1.0-alpha"
        console.print(f"AgentScan v{ver}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool | None = typer.Option(
        None,
        "--version",
        "-v",
        help="Show AgentScan version and exit.",
        callback=_version_callback,
        is_eager=True,
    ),
) -> None:
    """AgentScan — Open-source security scanner for AI agents."""
    pass


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

_SSP_GLOSS: dict[SspClass, str] = {
    SspClass.SERVANT: "explicit tool use only",
    SspClass.STALKER: "unsolicited read-only / probe actions",
    SspClass.PREDATOR: "autonomous side-effecting actions",
}


def _format_ssp_class(ssp: SspClass | None) -> str:
    if ssp is None:
        return "Unknown"
    label = ssp.value.title()
    gloss = _SSP_GLOSS.get(ssp, "")
    return f"{label} ({gloss})" if gloss else label


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


def _confirm_exploit_mode() -> None:
    """Require explicit consent before running exploit-grade attack payloads."""
    import sys

    from rich import print as rprint
    from rich.prompt import Confirm

    if not sys.stdin.isatty():
        return

    rprint(
        "\n[bold red]⚠  EXPLOIT / DEEP MODE WARNING[/bold red]\n"
        "This scan will send destructive-grade payloads (privilege escalation,\n"
        "data exfiltration, system command injection) to the target agent.\n"
        "[bold]Only run this against systems you own or have written permission to test.[/bold]\n"
    )
    try:
        confirmed = Confirm.ask(
            "I confirm this is an authorized security test and I accept full responsibility",
            default=False,
        )
    except (EOFError, KeyboardInterrupt):
        confirmed = False
    if not confirmed:
        rprint("[yellow]Scan cancelled.[/yellow]")
        raise SystemExit(0)


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
    mutate: bool = typer.Option(
        False,
        "--mutate",
        help="Expand SCAN YAML payloads with Base64, leetspeak, ZWSP, token-split, "
        "homoglyph, and wrap variants.",
    ),
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
        help="Path to a file with a captured cURL command (Chrome -> Copy as cURL). "
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
    trajectory_log: Path | None = typer.Option(  # noqa: B008
        None,
        "--trajectory-log",
        help="Write structured attack execution trajectories and multi-turn traces (JSON/JSONL) "
        "for offline analysis, RLHF safety tuning, and compliance audits.",
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
    mutate = mutate or bool(cfg.get("mutate"))
    verbose = verbose or bool(cfg.get("verbose"))
    if output is None and cfg.get("output"):
        output = Path(cfg["output"])
    if transcript is None and cfg.get("transcript"):
        transcript = Path(cfg["transcript"])
    if trajectory_log is None and cfg.get("trajectory_log"):
        trajectory_log = Path(cfg["trajectory_log"])
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
    if verbose or transcript is not None or llm_log is not None or trajectory_log is not None:
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
        mutate=mutate,
    )

    # Determine modes
    modes = (
        [ScanMode.SCAN]
        + ([ScanMode.EXPLOIT] if exploit else [])
        + ([ScanMode.DEEP] if deep else [])
    )

    if exploit or deep:
        _confirm_exploit_mode()

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
    console.print(f"SSP class: {_format_ssp_class(report.ssp_class)}")

    # Write JSON output
    if output is not None:
        write_report(report, output)
        console.print(f"Report written to {output}")

    # Write the full transcript (all traffic + findings), separate from the report.
    if transcript is not None:
        recorder.write_transcript(transcript, report)
        console.print(f"Transcript written to {transcript}")

    # Write structured attack execution trajectory (JSON/JSONL)
    if trajectory_log is not None:
        recorder.write_trajectory_log(trajectory_log, report)
        console.print(f"Trajectory log written to {trajectory_log}")

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

    all_findings: list[Finding] = []
    total_checks = 0

    # ── Lazy imports (keep startup fast when only `scan` is used) ─────────────
    if run_all or scan_deps:
        from agentscan.supply_chain.dep_scanner import scan_dependencies

        f, c = scan_dependencies(path, offline=offline, show_transitive=show_transitive)
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

    if run_all or scan_frameworks:
        from agentscan.supply_chain.framework_auditor import scan_frameworks as _scan_fw

        f, c = _scan_fw(path)
        all_findings.extend(f)
        total_checks += c

    if scan_semgrep:
        from agentscan.supply_chain.semgrep_auditor import scan_semgrep as _scan_sg

        f, c = _scan_sg(path, rules_path=rules, fallback_to_native=True)
        all_findings.extend(f)
        total_checks += c

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
        console.print("[green]No issues found.[/green]")

    # ── Score ──────────────────────────────────────────────────────────────────
    score = calculate_score(all_findings, max(total_checks, 1))
    band = score_band(score)
    console.print(f"\nAgentScan Audit Score: {score}/100  [{band}]")

    # ── JSON output ────────────────────────────────────────────────────────────
    if output is not None and output != aibom_path:
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

    console.print(f"AgentScan UI: [cyan]http://{host}:{port}[/cyan]")
    if token:
        console.print("[dim]Authentication token enabled for dashboard access.[/dim]")
    try:
        serve_app(dashboard, host=host, port=port)
    except RuntimeError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1) from None


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
        applied_count = plan.apply()
        console.print(
            f"[bold green]Successfully applied {applied_count} remediation(s) to disk.[/bold green]"
        )
    else:
        console.print(
            "[yellow]Dry-run mode: no files modified. Pass --apply to write changes to disk.[/yellow]"
        )

    if output:
        output.write_text(plan.model_dump_json(indent=2), encoding="utf-8")
        console.print(f"FixPlan written to [cyan]{output}[/cyan]")


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
    import asyncio

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


@app.command(name="mcp-serve")
def mcp_serve() -> None:
    """Run native Model Context Protocol (MCP) JSON-RPC server over stdio."""
    from agentscan.mcp.server import run_mcp_server

    run_mcp_server()


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
        help="Default LLM model identifier for swarm agents (e.g. 'gpt-4o-mini', 'ollama/llama3').",
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
    import asyncio
    import json

    from rich.panel import Panel

    from agentscan.core.models import Target
    from agentscan.swarm.coordinator import SwarmCoordinator
    from agentscan.swarm.presets import resolve_team

    try:
        team_cfg = resolve_team(team)
    except Exception as e:
        console.print(f"[bold red]Error loading swarm team:[/bold red] {e}")
        raise typer.Exit(code=1) from None

    if rounds is not None:
        team_cfg.max_rounds = rounds

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
    target_obj = Target(url=target)

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
                f"    [bold red]!! COMPROMISE DETECTED:[/bold red] [{record.finding.severity.value}] {record.finding.attack_name}"
            )

    report = asyncio.run(coordinator.run_swarm(target_obj, callback=_on_turn))

    # Print Summary Table
    console.print(
        f"\n[bold]Swarm Execution Complete[/bold] — Score: [bold cyan]{report.score}/100[/bold cyan]"
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
        console.print("[green]Target resisted all multi-agent swarm vectors.[/green]")

    if output is not None:
        output.write_text(json.dumps(report.model_dump(mode="json"), indent=2), encoding="utf-8")
        console.print(f"Swarm report written to [cyan]{output}[/cyan]")


# ── Self-Healing Commands ─────────────────────────────────────────────────────


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
    import json

    from rich.panel import Panel

    from agentscan.core.models import Finding
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
        "127.0.0.1", "--host", "-h", help="Host interface to bind on."
    ),
    port: int = typer.Option(  # noqa: B008
        8766, "--port", "-p", help="Port to bind on."
    ),
) -> None:
    """Start the AgentScan self-healing webhook receiver server."""
    from agentscan.remediation.webhook_receiver import run_heal_server

    run_heal_server(host=host, port=port)


# ── Compliance & Verification Commands ────────────────────────────────────────


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
    import json

    from rich.panel import Panel

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
            f"Compliance Score: [bold cyan]{comp_report.compliance_score:.1f}/100[/bold cyan]\n"
            f"Gaps / Non-Compliant Items: [bold]{len(comp_report.findings)}[/bold]",
            title="[bold blue]Regulatory Compliance Pack[/bold blue]",
        )
    )

    table = Table(title=f"{comp_report.framework.value.upper()} Section Breakdown", show_lines=True)
    table.add_column("Section / Function", style="cyan", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("Findings", no_wrap=True)
    table.add_column("Description")

    for sec_id, sec_data in comp_report.evaluated_sections.items():
        st = sec_data.get("status", "COMPLIANT")
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
    import json

    from rich.panel import Panel

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
        cert = sign_audit_report(report_data, secret_key=key)
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


if __name__ == "__main__":
    app()
