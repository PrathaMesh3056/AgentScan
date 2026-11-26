# tests/test_docs_consistency.py
#
# Copy-paste and registry-derived checks for issue #47: help text, manual and
# runtime behavior must agree.

from __future__ import annotations

import re
from functools import cache
from pathlib import Path

import pytest
from typer.testing import CliRunner

from agentscan.attacks.registry import registry
from agentscan.cli import app
from agentscan.core.models import ScanMode
from agentscan.mcp.server import TOOLS_METADATA

ROOT = Path(__file__).resolve().parents[1]
DOCS = [
    ROOT / "README.md",
    ROOT / "docs" / "START_HERE.md",
    ROOT / "docs" / "AgentScan_Manual.md",
]
SCHEMES = (
    "http://",
    "https://",
    "ws://",
    "wss://",
    "mcp://stdio",
    "mcp+stdio://",
    "mcp+sse://",
    "mcp+sses://",
)
FORMATS = (".json", ".html", ".pdf", ".sarif")
GROUPS = {"api"}

runner = CliRunner()


def _normalise(text: str) -> str:
    return re.sub(r"\s+", " ", text)


@cache
def _help(args: tuple[str, ...]) -> str | None:
    result = runner.invoke(app, [*args, "--help"])
    if result.exit_code != 0:
        return None
    return _normalise(result.output)


def _logical_commands(path: Path):
    """Yield executable lines from fenced blocks, joining backslash continuations."""
    text = path.read_text(encoding="utf-8")
    for block in re.findall(r"```[a-zA-Z0-9_-]*\n(.*?)```", text, re.S):
        without_comments = re.sub(r"[ \t]+#[^\n]*", "", block)
        joined = re.sub(r"\\\s*\n", " ", without_comments)
        for line in joined.splitlines():
            line = line.strip()
            if "agentscan" in line:
                yield line


def _documented_flags(rest: str) -> list[str]:
    return re.findall(r"(?<!\w)(--[a-z][a-z0-9-]*)", rest)


@pytest.mark.parametrize("doc", DOCS, ids=lambda path: path.name)
def test_documented_commands_and_options_are_copy_pasteable(doc: Path) -> None:
    command_re = re.compile(r"(?:^|\s)agentscan(?:\.cli)?\s+([a-z][a-z0-9-]*)")
    checked = 0
    for line in _logical_commands(doc):
        match = command_re.search(line)
        if match is None:
            continue
        checked += 1
        command = match.group(1)
        args = [command]
        rest = line[match.end() :]
        if command in GROUPS:
            subcommand = re.match(r"\s+([a-z][a-z0-9-]*)", rest)
            assert subcommand is not None, f"{doc.name}: {line!r} is missing a subcommand"
            args.append(subcommand.group(1))
        help_text = _help(tuple(args))
        assert help_text is not None, f"{doc.name}: undocumented command {args!r} in {line!r}"
        for flag in _documented_flags(rest):
            assert flag in help_text, (
                f"{doc.name}: {flag} is not in `agentscan {' '.join(args)} --help`"
            )
    assert checked >= 5, f"{doc.name}: copy-paste check found too few executable examples"


def test_scan_help_matches_supported_targets_formats_and_profile_blocks() -> None:
    help_text = _help(("scan",))
    assert help_text is not None
    for scheme in SCHEMES:
        assert scheme in help_text
    for report_format in FORMATS:
        assert report_format in help_text
    assert "request_template" in help_text
    assert "browser" in help_text
    assert "connector (browser/curl)" not in help_text


def test_audit_help_matches_report_formats() -> None:
    help_text = _help(("audit",))
    assert help_text is not None
    for report_format in FORMATS:
        assert report_format in help_text


def test_compliance_help_lists_all_supported_frameworks() -> None:
    help_text = _help(("compliance",))
    assert help_text is not None
    for framework in ("eu-ai-act", "nist-ai-rmf", "mitre-atlas", "iso-42001"):
        assert framework in help_text


def test_verify_claims_help_documents_receipt_and_failure() -> None:
    help_text = _help(("verify-claims",))
    assert help_text is not None
    assert "--receipt" in help_text
    assert "reference_runs.json" in help_text
    assert "exits 1" in help_text


def test_list_attacks_reports_registry_counts() -> None:
    registry.load_all()
    modules = registry.get_all()
    result = runner.invoke(app, ["list-attacks"])
    assert result.exit_code == 0
    output = _normalise(result.output)
    assert f"{len(modules)} registered modules" in output
    for mode in ScanMode:
        assert f"{len(registry.get_by_mode(mode))} {mode.value}" in output
    assert "23 registered modules" not in output


def test_mcp_metadata_derives_attack_count_instead_of_hardcoding() -> None:
    metadata = next(item for item in TOOLS_METADATA if item["name"] == "agentscan_list_attacks")
    description = metadata["description"]
    assert "registered" in description
    assert re.search(r"\b\d+\b", description) is None


def test_manual_documents_exit_status_and_verify_claims() -> None:
    manual = (ROOT / "docs" / "AgentScan_Manual.md").read_text(encoding="utf-8")
    assert "#### Exit status" in manual
    exit_section = manual.split("#### Exit status", 1)[1].split("> [!WARNING]", 1)[0]
    for code in ("0", "1", "2", "3"):
        assert f"| `{code}` |" in exit_section
    assert "agentscan verify-claims" in manual
    assert "benchmarks/receipts/reference_runs.json" in manual


def test_manual_target_reference_lists_every_supported_scheme() -> None:
    manual = (ROOT / "docs" / "AgentScan_Manual.md").read_text(encoding="utf-8")
    for scheme in SCHEMES:
        assert scheme in manual


def test_guides_do_not_use_a_live_third_party_target() -> None:
    for doc in DOCS:
        text = doc.read_text(encoding="utf-8").lower()
        assert "bitinfusion" not in text, f"{doc.name} still references a live third-party target"
