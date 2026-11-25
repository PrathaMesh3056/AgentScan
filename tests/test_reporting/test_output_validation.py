# tests/test_reporting/test_output_validation.py
#
# Regression tests for QA-044: report destinations must be validated before
# scan/audit work starts, and report writes must not leave partial artifacts.

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
import typer
from typer.testing import CliRunner

from agentscan._cli._shared import validate_report_output, write_report
from agentscan.cli import app
from agentscan.core.models import Framework, ScanMode, ScanReport

runner = CliRunner()


def _report() -> ScanReport:
    report = ScanReport(
        target_url="http://127.0.0.1:9/chat",
        scan_mode=ScanMode.SCAN,
        framework=Framework.AUTO,
    )
    report.complete(100)
    return report


@pytest.mark.parametrize(
    "suffix",
    [".json", ".JSON", ".html", ".HTML", ".pdf", ".sarif", ".SARIF"],
)
def test_validate_report_output_accepts_supported_suffixes(tmp_path: Path, suffix: str) -> None:
    validate_report_output(tmp_path / f"report{suffix}")


def test_validate_report_output_rejects_missing_parent(tmp_path: Path) -> None:
    with pytest.raises(typer.BadParameter, match="Output directory does not exist"):
        validate_report_output(tmp_path / "missing-dir" / "report.json")


def test_validate_report_output_rejects_non_directory_parent(tmp_path: Path) -> None:
    parent = tmp_path / "not-a-directory"
    parent.write_text("x", encoding="utf-8")

    with pytest.raises(typer.BadParameter, match="not a directory"):
        validate_report_output(parent / "report.json")


def test_validate_report_output_rejects_existing_directory(tmp_path: Path) -> None:
    destination = tmp_path / "report.json"
    destination.mkdir()

    with pytest.raises(typer.BadParameter, match="existing directory"):
        validate_report_output(destination)


@pytest.mark.parametrize("name", ["report.txt", "report", "report.csv"])
def test_validate_report_output_rejects_unsupported_suffix(tmp_path: Path, name: str) -> None:
    with pytest.raises(typer.BadParameter) as excinfo:
        validate_report_output(tmp_path / name)

    message = str(excinfo.value)
    assert "Unsupported output format" in message
    assert "Supported formats: .html, .json, .pdf, .sarif" in message


def test_scan_rejects_missing_output_parent_before_scanning(tmp_path: Path) -> None:
    output = tmp_path / "missing-dir" / "report.json"
    with patch("agentscan.cli.run_scan_multi", new_callable=AsyncMock) as scanner:
        result = runner.invoke(app, ["scan", "http://127.0.0.1:9/chat", "--output", str(output)])

    assert result.exit_code == 2
    assert "Output directory does not exist" in result.output
    scanner.assert_not_called()
    assert not output.exists()


def test_scan_rejects_existing_directory_output_before_scanning(tmp_path: Path) -> None:
    output = tmp_path / "report.json"
    output.mkdir()
    with patch("agentscan.cli.run_scan_multi", new_callable=AsyncMock) as scanner:
        result = runner.invoke(app, ["scan", "http://127.0.0.1:9/chat", "--output", str(output)])

    assert result.exit_code == 2
    assert "existing directory" in result.output
    scanner.assert_not_called()


def test_scan_rejects_unsupported_output_suffix_before_scanning(tmp_path: Path) -> None:
    output = tmp_path / "report.txt"
    with patch("agentscan.cli.run_scan_multi", new_callable=AsyncMock) as scanner:
        result = runner.invoke(app, ["scan", "http://127.0.0.1:9/chat", "--output", str(output)])

    assert result.exit_code == 2
    assert "Unsupported output format" in result.output
    scanner.assert_not_called()
    assert not output.exists()


def test_audit_rejects_missing_output_parent_before_work(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _unexpected_scan(*args: object, **kwargs: object) -> None:
        raise AssertionError("audit scanners must not run after output validation fails")

    monkeypatch.setattr("agentscan.supply_chain.config_auditor.scan_config", _unexpected_scan)
    output = tmp_path / "missing-dir" / "report.json"

    result = runner.invoke(app, ["audit", str(tmp_path), "--scan-config", "--output", str(output)])

    assert result.exit_code == 2
    assert "Output directory does not exist" in result.output
    assert not output.exists()


@pytest.mark.parametrize("suffix", [".JSON", ".SARIF"])
def test_write_report_accepts_uppercase_suffix(tmp_path: Path, suffix: str) -> None:
    output = tmp_path / f"report{suffix}"

    write_report(_report(), output)

    assert output.exists()
    data = json.loads(output.read_text(encoding="utf-8"))
    if suffix.lower() == ".json":
        assert data["target_url"]
    else:
        assert data["version"] == "2.1.0"


def test_scan_writes_uppercase_json_output(tmp_path: Path) -> None:
    output = tmp_path / "report.JSON"
    with patch(
        "agentscan.cli.run_scan_multi", new_callable=AsyncMock, return_value=_report()
    ) as scanner:
        result = runner.invoke(app, ["scan", "http://127.0.0.1:9/chat", "--output", str(output)])

    assert result.exit_code == 0, result.output
    scanner.assert_awaited_once()
    assert json.loads(output.read_text(encoding="utf-8"))["target_url"]


def test_write_report_leaves_no_partial_file_when_rendering_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "report.pdf"

    def _fail_after_partial_write(report: ScanReport, path: Path) -> None:
        Path(path).write_bytes(b"%PDF-partial")
        raise RuntimeError("simulated PDF render failure")

    monkeypatch.setattr(
        "agentscan.reporting.pdf_report.render_pdf_report", _fail_after_partial_write
    )

    with pytest.raises(RuntimeError, match="simulated PDF render failure"):
        write_report(_report(), output)

    assert not output.exists()
    assert list(tmp_path.iterdir()) == []
