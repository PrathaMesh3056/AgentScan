# agentscan/_cli/_shared.py
#
# Shared helpers, constants, and the Typer app object used across all CLI submodules.
# Import this from every commands/*.py file.

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from agentscan.core.models import Finding, SspClass

# ── Application Instance ──────────────────────────────────────────────────────

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
            ver = "0.2.0"
        typer.echo(ver)
        raise typer.Exit()


@app.callback()
def main_callback(
    version: bool | None = typer.Option(
        None,
        "--version",
        "-V",
        callback=_version_callback,
        is_eager=True,
        help="Show the version and exit.",
    ),
) -> None:
    """AgentScan: Enterprise-grade security scanner and capability firewall for AI agents."""
    pass


# ── Severity Display Colours ──────────────────────────────────────────────────

_SEVERITY_COLOURS: dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "dim",
    "INFO": "dim",
    "PASS": "green",
}

# ── Severity Ordering for --fail-on ──────────────────────────────────────────

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


# ── Helper Functions ──────────────────────────────────────────────────────────


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


def write_report(report: Any, output_path: Path) -> None:
    """Write a ScanReport or IdentityReport to disk in the appropriate format."""
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


_EXPLOIT_CONSENT_ENV = "AGENTSCAN_EXPLOIT_CONSENT"


def _exploit_consent_from_env() -> bool:
    """Return True only when the environment grants unambiguous exploit consent.

    ``AGENTSCAN_EXPLOIT_CONSENT=1`` is the only affirmative value. Explicit
    negatives (0/false/no/off) mean no consent; any other value is ambiguous and
    refused rather than guessed.
    """
    raw = os.environ.get(_EXPLOIT_CONSENT_ENV)
    if raw is None:
        return False
    value = raw.strip().lower()
    if value == "" or value in {"0", "false", "no", "off"}:
        return False
    if value == "1":
        return True
    raise typer.BadParameter(
        f"{_EXPLOIT_CONSENT_ENV} must be exactly '1' to grant exploit consent; "
        f"refusing ambiguous value {raw!r}."
    )


def _stdin_is_interactive() -> bool:
    """True only when stdin is a real interactive terminal.

    ``sys.stdin.isatty()`` is not sufficient on Windows: the NUL device used by
    ``subprocess.DEVNULL`` is a character device and reports ``isatty() == True``
    even though no human can answer a prompt. Require a real console handle there.
    """
    import sys

    try:
        if not sys.stdin.isatty():
            return False
    except (AttributeError, OSError, ValueError):
        return False
    if os.name != "nt":
        return True
    try:
        import ctypes
        import msvcrt
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        get_console_mode = kernel32.GetConsoleMode
        get_console_mode.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        get_console_mode.restype = wintypes.BOOL
        handle = msvcrt.get_osfhandle(sys.stdin.fileno())
        mode = wintypes.DWORD()
        if not get_console_mode(wintypes.HANDLE(handle), ctypes.byref(mode)):
            return False
    except (AttributeError, OSError, ValueError):
        # In-memory streams used by tests have no OS handle; trust isatty().
        return True
    return True


def _confirm_exploit_mode(
    *,
    authorized: bool = False,
    require_non_tty_consent: bool = False,
) -> bool:
    """Require explicit consent before running exploit-grade attack payloads.

    Interactive terminals keep the default confirmation prompt. Non-interactive
    callers that set ``require_non_tty_consent`` must supply ``--authorized`` or
    ``AGENTSCAN_EXPLOIT_CONSENT=1``; otherwise the command is refused before any
    request reaches the target. Returns True when consent was affirmatively
    granted.
    """
    from rich import print as rprint
    from rich.prompt import Confirm

    if require_non_tty_consent:
        # Explicit flag wins without consulting the environment; otherwise the
        # environment must be unambiguous.
        explicit_consent = authorized or _exploit_consent_from_env()
    else:
        # Legacy callers (swarm) do not consume the scan consent mechanism.
        explicit_consent = authorized

    if not _stdin_is_interactive():
        if not require_non_tty_consent:
            # Legacy callers (swarm) keep their historical non-interactive behavior.
            return explicit_consent
        if not explicit_consent:
            rprint(
                "\n[bold red]EXPLOIT / DEEP MODE REFUSED[/bold red]\n"
                "Standard input is not an interactive terminal and no explicit consent was given.\n"
                "Refusing before any request is sent to the target.\n"
                "Re-run with [bold]--authorized[/bold] or set "
                "[bold]AGENTSCAN_EXPLOIT_CONSENT=1[/bold] only after confirming you own "
                "or have written permission to test the target.\n"
            )
            raise typer.Exit(code=2)
        source = "--authorized" if authorized else _EXPLOIT_CONSENT_ENV
        rprint(
            f"[yellow]EXPLOIT / DEEP consent acknowledged via {source} "
            "(non-interactive run).[/yellow]"
        )
        return True

    rprint(
        "\n[bold red]WARNING: EXPLOIT / DEEP MODE[/bold red]\n"
        "This scan will send destructive-grade payloads (privilege escalation,\n"
        "data exfiltration, system command injection) to the target agent.\n"
        "[bold]Only run this against systems you own or have written permission to test.[/bold]\n"
    )
    if explicit_consent:
        rprint("[green]Explicit consent provided; skipping the interactive confirmation.[/green]")
        return True
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
    return True
