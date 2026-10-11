# agentscan/cli/commands/scan.py
#
# 'agentscan scan' command — security scan against an LLM agent endpoint.

from __future__ import annotations

import asyncio
from collections.abc import Callable
from functools import wraps
from pathlib import Path
from typing import Any

import typer
from rich.table import Table

from agentscan._cli._shared import (
    _SEVERITY_COLOURS,
    _confirm_exploit_mode,
    _fail_on_should_exit,
    _format_ssp_class,
    app,
    console,
    write_report,
)
from agentscan.core.context import ScanContext, active_context, begin_scan_context
from agentscan.core.models import (
    BrowserConfig,
    Framework,
    RequestTemplate,
    ScanMode,
    ScanReport,
    Target,
)
from agentscan.core.scorer import score_band
from agentscan.core.trace import recorder


def _isolated_scan_configuration[**P, R](command: Callable[P, R]) -> Callable[P, R]:
    """Keep CLI transcript settings local and restore caller state on every exit."""

    @wraps(command)
    def wrapped(*args: P.args, **kwargs: P.kwargs) -> R:
        token = active_context.set(None)
        try:
            begin_scan_context()
            return command(*args, **kwargs)
        finally:
            active_context.reset(token)

    return wrapped


@app.command()
@_isolated_scan_configuration
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
    analysis_mode: str | None = typer.Option(
        None,
        "--analysis",
        help="deterministic (default), local, or external. External analysis requires non-sensitive designation.",
    ),
    local_model: str = typer.Option(
        "ollama/llama3.2",
        "--local-model",
        help="Installed offline model used with --analysis local.",
    ),
    external_model: str | None = typer.Option(
        None,
        "--external-model",
        help="Provider/model for --analysis external, e.g. gemini/MODEL_ID. Configure its key locally.",
    ),
    data_classification: str | None = typer.Option(
        None,
        "--data-classification",
        help="sensitive (default) or non_sensitive. External models may receive only designated non-sensitive scans.",
    ),
    attacker_model: str | None = typer.Option(
        None,
        "--attacker-model",
        help="Attacker model compatible with selected local or external analysis. Implies --exploit.",
    ),
    judge_model: str | None = typer.Option(
        None,
        "--judge-model",
        help="Judge model compatible with selected local or external analysis.",
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
        help="Run a synthetic offline local model protocol smoke check before scanning. Does not measure detection accuracy.",
    ),
    calibrate_required: bool = typer.Option(
        False,
        "--calibrate-required",
        help="Abort the scan if positive-control calibration fails (stricter than --calibrate).",
    ),
    escalation_model: str | None = typer.Option(
        None,
        "--escalation-model",
        help="Escalation model compatible with the selected local or external analysis mode.",
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
    completion_selector: str | None = typer.Option(
        None,
        "--completion-selector",
        help="CSS marker on/inside the newest completed browser reply.",
    ),
    allow_unverified_completion: bool = typer.Option(
        False,
        "--allow-unverified-completion",
        help="Explicitly accept browser text-stability heuristic.",
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
    recorder.enabled = bool(
        verbose or transcript is not None or llm_log is not None or trajectory_log is not None
    )
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
            completion_selector=completion_selector,
            allow_unverified_completion=allow_unverified_completion,
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

    # External analysis is opt-in, with an explicit classification for this scan.
    from agentscan.core.ai_client import AIClientError
    from agentscan.core.external_analysis import validate_analysis_selection

    explicit_analysis = analysis_mode is not None or "analysis_mode" in cfg
    analysis_mode = analysis_mode or cfg.get("analysis_mode") or "deterministic"
    external_model = external_model or cfg.get("external_model") or ""
    data_classification = data_classification or cfg.get("data_classification") or "sensitive"
    if data_classification not in {"sensitive", "non_sensitive"}:
        raise typer.BadParameter("--data-classification must be sensitive or non_sensitive.")
    if external_model and analysis_mode != "external":
        raise typer.BadParameter("--external-model requires --analysis external.")
    if analysis_mode == "deterministic" and (attacker_model or judge_model or escalation_model):
        if explicit_analysis:
            raise typer.BadParameter("Role model selection requires local or external analysis.")
        if all(
            selected is None or selected.startswith("ollama/")
            for selected in (attacker_model, judge_model, escalation_model)
        ):
            analysis_mode = "local"
            local_model = judge_model or attacker_model or escalation_model or local_model
        else:
            raise typer.BadParameter("External role models require --analysis external.")
    if analysis_mode == "external" and not external_model:
        external_model = judge_model or attacker_model or escalation_model or ""
    if (calibrate or calibrate_required) and analysis_mode != "local":
        raise typer.BadParameter(
            "Calibration is a synthetic offline local model smoke check; use --analysis local."
        )
    try:
        validate_analysis_selection(
            analysis_mode,
            data_classification,
            external_model if analysis_mode == "external" else local_model,
        )
        for selected in (attacker_model, judge_model, escalation_model):
            if selected:
                validate_analysis_selection(analysis_mode, data_classification, selected)
    except AIClientError as exc:
        raise typer.BadParameter(str(exc)) from None
    if cfg.get("indirect_adapter") not in (None, "document_v1"):
        raise typer.BadParameter(
            "indirect_adapter must be document_v1 or omitted from the profile."
        )
    target_obj = Target(
        analysis_mode=analysis_mode,
        local_model=local_model,
        external_model=external_model,
        data_classification=data_classification,
        canary_token=cfg.get("canary_token"),
        indirect_adapter=cfg.get("indirect_adapter"),
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

    # Local synthetic controls check protocol behavior only, not detector accuracy.
    cal_result = None
    if calibrate or calibrate_required:
        from agentscan.core.calibration import run_calibration

        console.print("Running a synthetic offline local model protocol smoke check...")
        cal = asyncio.run(
            run_calibration(attacker_model or local_model, attacker_goal=attacker_goal)
        )
        cal_result = cal
        if cal.passed:
            console.print(f"[green][PASS] local synthetic controls passed[/green] — {cal.detail}")
        else:
            console.print(
                f"[bold red][WARN] local synthetic controls failed[/bold red] — {cal.detail}. "
                "Model-assisted assessment may be unavailable."
            )
            if calibrate_required:
                console.print(
                    "[bold red][FAIL] Scan aborted because --calibrate-required was set and calibration failed.[/bold red]"
                )
                raise typer.Exit(code=1)

    # Run scan
    # Import via agentscan.cli so that `patch("agentscan.cli.run_scan_multi")` works in tests.
    import agentscan.cli as _cli_mod

    async def _run_and_capture_context() -> tuple[ScanReport, ScanContext | None]:
        result = await _cli_mod.run_scan_multi(target_obj, modes)
        return result, active_context.get()

    # ContextVar assignments made in asyncio.run's task do not propagate back
    # to this synchronous caller. Export using the completed scan's context.
    report, completed_context = asyncio.run(_run_and_capture_context())
    if completed_context is not None:
        active_context.set(completed_context)
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
        console.print("No findings were recorded in the evaluated tests.")

    # Print score
    band = score_band(report.score) if report.status == "COMPLETE" else report.status
    score_val = report.score if report.score is not None else "N/A"
    console.print(f"\nAgentScan Score: {score_val}/100  [{band}]")
    console.print(
        f"Status: {report.status}; evaluated {report.tests_run}/{report.tests_selected} selected tests"
    )
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
