# agentscan/_cli/_shared.py
#
# Shared helpers, constants, and the Typer app object used across all CLI submodules.
# Import this from every commands/*.py file.

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
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


_REPORT_OUTPUT_SUFFIXES = frozenset({".json", ".html", ".pdf", ".sarif"})
_SUPPORTED_REPORT_FORMATS = ", ".join(sorted(_REPORT_OUTPUT_SUFFIXES))


def validate_report_output(output_path: Path) -> None:
    """Fail fast when a report destination or format is unusable."""
    output_path = Path(output_path)
    suffix = output_path.suffix
    if suffix.lower() not in _REPORT_OUTPUT_SUFFIXES:
        raise typer.BadParameter(
            f"Unsupported output format for {output_path}: {suffix or '<none>'!r}. "
            f"Supported formats: {_SUPPORTED_REPORT_FORMATS}."
        )

    parent = output_path.parent
    if not parent.exists():
        raise typer.BadParameter(
            f"Output directory does not exist: {parent} (output path: {output_path})."
        )
    if not parent.is_dir():
        raise typer.BadParameter(
            f"Output parent is not a directory: {parent} (output path: {output_path})."
        )
    if output_path.is_dir():
        raise typer.BadParameter(
            f"Output path is an existing directory: {output_path}. Choose a file path."
        )


@contextmanager
def _temporary_output_file(output_path: Path) -> Iterator[Path]:
    """Yield a sibling temporary file and atomically move it into place on success."""
    descriptor, temp_name = tempfile.mkstemp(
        prefix=f".{output_path.name}.", suffix=".tmp", dir=output_path.parent
    )
    os.close(descriptor)
    temp_path = Path(temp_name)
    try:
        yield temp_path
        os.replace(temp_path, output_path)
    finally:
        temp_path.unlink(missing_ok=True)


def _write_text_atomic(output_path: Path, text: str) -> None:
    with _temporary_output_file(output_path) as temp_path:
        temp_path.write_text(text, encoding="utf-8")


def write_report(report: Any, output_path: Path) -> None:
    """Write a ScanReport or IdentityReport to disk atomically in the appropriate format."""
    output_path = Path(output_path)
    validate_report_output(output_path)
    ext = output_path.suffix.lower()
    if ext == ".json":
        data = report.to_dict() if hasattr(report, "to_dict") else report.model_dump(mode="json")
        _write_text_atomic(output_path, json.dumps(data, indent=2))
    elif ext == ".html":
        from agentscan.reporting.html_report import render_html_report

        html = render_html_report(report)
        _write_text_atomic(output_path, html)
    elif ext == ".pdf":
        from agentscan.reporting.pdf_report import render_pdf_report

        with _temporary_output_file(output_path) as temp_path:
            render_pdf_report(report, temp_path)
    elif ext == ".sarif":
        from agentscan.reporting.sarif_report import to_sarif

        data = to_sarif(report)
        _write_text_atomic(output_path, json.dumps(data, indent=2))
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
