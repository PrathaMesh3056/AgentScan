# tests/test_cli_error_quality.py
#
# Regression tests for issue #43: expected operator mistakes must become bounded,
# actionable CLI errors that name the input field/path and never leak a traceback.

from __future__ import annotations

import codecs
import json
import re
from pathlib import Path

import pytest
import typer
from typer.testing import CliRunner

from agentscan._cli._shared import write_report
from agentscan.cli import app
from agentscan.core.models import Framework, ScanMode, ScanReport

runner = CliRunner()


def _write_bom_json(path: Path, data: object) -> None:
    path.write_bytes(codecs.BOM_UTF8 + json.dumps(data).encode("utf-8"))


def _compact(value: str) -> str:
    # Rich/Typer wraps long paths inside the error panel, inserting ANSI resets and
    # a box border between the wrapped segments. Compare without styling or
    # whitespace/borders so a wrapped path still counts as named.
    text = re.sub(r"\x1b\[[0-9;]*m", "", value)
    return "".join(ch for ch in text if not ch.isspace() and ch not in "│┃").lower()


def _assert_bounded(result, *needles: str) -> None:
    output = _compact(result.output)
    assert "traceback(mostrecentcalllast)" not in output
    for needle in needles:
        assert _compact(needle) in output, result.output


def _profile(tmp_path: Path, body: str, name: str = "target.yaml") -> Path:
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")
    return path


class TestScanProfileErrors:
    def test_missing_profile_names_the_path(self, tmp_path: Path) -> None:
        missing = tmp_path / "missing-target.yaml"
        result = runner.invoke(app, ["scan", "--config", str(missing)])
        assert result.exit_code == 2
        _assert_bounded(result, str(missing), "not found")

    def test_malformed_profile_names_path_and_yaml_location(self, tmp_path: Path) -> None:
        profile = _profile(tmp_path, "url: http://127.0.0.1:9/chat\nframework: [\n")
        result = runner.invoke(app, ["scan", "--config", str(profile)])
        assert result.exit_code == 2
        _assert_bounded(result, str(profile), "not valid YAML", "line ", "column")

    def test_non_mapping_profile_is_bounded(self, tmp_path: Path) -> None:
        profile = _profile(tmp_path, "- one\n- two\n")
        result = runner.invoke(app, ["scan", "--config", str(profile)])
        assert result.exit_code == 2
        _assert_bounded(result, str(profile), "must be a YAML mapping")

    def test_invalid_framework_names_field_and_choices(self, tmp_path: Path) -> None:
        profile = _profile(
            tmp_path,
            "url: http://127.0.0.1:9/chat\nframework: definitely-not-a-framework\n",
        )
        result = runner.invoke(app, ["scan", "--config", str(profile)])
        assert result.exit_code == 2
        _assert_bounded(result, "framework", "must be one of", "langchain")

    def test_invalid_attacker_turns_names_field(self, tmp_path: Path) -> None:
        profile = _profile(
            tmp_path,
            "url: http://127.0.0.1:9/chat\nattacker_turns: many\n",
        )
        result = runner.invoke(app, ["scan", "--config", str(profile)])
        assert result.exit_code == 2
        _assert_bounded(result, "attacker_turns", "must be an integer", "'many'")

    def test_invalid_request_template_names_nested_field(self, tmp_path: Path) -> None:
        profile = _profile(
            tmp_path,
            "url: http://127.0.0.1:9/chat\n"
            "request_template:\n"
            "  message_path: messages.-1.content\n",
        )
        result = runner.invoke(app, ["scan", "--config", str(profile)])
        assert result.exit_code == 2
        _assert_bounded(result, "request_template.url", "Invalid field")


class TestScanCurlErrors:
    def test_missing_curl_capture_names_path(self, tmp_path: Path) -> None:
        missing = tmp_path / "capture.curl"
        result = runner.invoke(
            app,
            ["scan", "--curl", str(missing), "--message-path", "message"],
        )
        assert result.exit_code == 2
        _assert_bounded(result, str(missing), "cURL capture file not found")

    def test_malformed_curl_capture_is_bounded(self, tmp_path: Path) -> None:
        capture = tmp_path / "capture.curl"
        capture.write_text(
            "curl http://127.0.0.1:9/chat -H 'Content-Type: application/json' --data 'not-json'\n",
            encoding="utf-8",
        )
        result = runner.invoke(
            app,
            ["scan", "--curl", str(capture), "--message-path", "message"],
        )
        assert result.exit_code == 2
        _assert_bounded(
            result,
            str(capture),
            "cURL capture file could not be parsed",
            "--message-path",
        )


class TestJsonReportErrors:
    def test_compliance_accepts_bom_prefixed_report(self, tmp_path: Path) -> None:
        report = tmp_path / "report.json"
        _write_bom_json(report, {"findings": []})
        result = runner.invoke(app, ["compliance", str(report)])
        assert result.exit_code == 0, result.output
        assert "Compliance" in result.output

    def test_compliance_malformed_report_names_path_and_location(self, tmp_path: Path) -> None:
        report = tmp_path / "report.json"
        report.write_text('{"findings": [\n', encoding="utf-8")
        result = runner.invoke(app, ["compliance", str(report)])
        assert result.exit_code == 2
        _assert_bounded(result, str(report), "not valid JSON", "line ", "column")

    def test_verify_claims_malformed_receipt_is_bounded(self, tmp_path: Path) -> None:
        receipt = tmp_path / "receipt.json"
        receipt.write_text("{definitely not json\n", encoding="utf-8")
        result = runner.invoke(app, ["verify-claims", "--receipt", str(receipt)])
        assert result.exit_code == 2
        _assert_bounded(result, str(receipt), "not valid JSON", "line ", "column")

    def test_heal_accepts_bom_prefixed_report(self, tmp_path: Path) -> None:
        project = tmp_path / "project"
        project.mkdir()
        report = tmp_path / "report.json"
        _write_bom_json(report, {"findings": []})
        result = runner.invoke(app, ["heal", str(project), "--report", str(report)])
        assert result.exit_code == 0, result.output
        assert "No automated remediation actions required" in result.output

    def test_verify_accepts_bom_prefixed_report(self, tmp_path: Path) -> None:
        report = tmp_path / "report.json"
        _write_bom_json(report, {"score": 100, "findings": []})
        result = runner.invoke(
            app,
            ["verify", str(report), "--sign", "--key", "A" * 32],
        )
        assert result.exit_code == 0, result.output
        assert "Report Cryptographically Certified" in result.output

    def test_fix_accepts_bom_prefixed_report(self, tmp_path: Path) -> None:
        report = tmp_path / "report.json"
        _write_bom_json(report, {"findings": []})
        result = runner.invoke(app, ["fix", str(report)])
        assert result.exit_code == 0, result.output
        assert "No remediations needed or applicable" in result.output


class TestOptionalDependencyErrors:
    def test_pdf_output_without_optional_dependency_is_bounded(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def missing_pdf_dependency(*_args: object, **_kwargs: object) -> None:
            raise RuntimeError(
                "PDF report generation requires the 'pdf' extra: pip install 'agentscan[pdf]'"
            )

        monkeypatch.setattr(
            "agentscan.reporting.pdf_report.render_pdf_report", missing_pdf_dependency
        )
        report = ScanReport(
            target_url="http://127.0.0.1:9/chat",
            scan_mode=ScanMode.SCAN,
            framework=Framework.AUTO,
        )
        report.complete(100)
        output = tmp_path / "report.pdf"
        with pytest.raises(typer.BadParameter) as excinfo:
            write_report(report, output)
        message = str(excinfo.value)
        assert str(output) in message
        assert "agentscan[pdf]" in message
        assert "Traceback" not in message


class TestMissingPathErrors:
    def test_audit_missing_path_is_bounded(self, tmp_path: Path) -> None:
        missing = tmp_path / "not-a-project"
        result = runner.invoke(app, ["audit", str(missing)])
        assert result.exit_code == 2
        _assert_bounded(result, str(missing), "Audit path does not exist")

    def test_fix_missing_path_is_bounded(self, tmp_path: Path) -> None:
        missing = tmp_path / "not-a-report.json"
        result = runner.invoke(app, ["fix", str(missing)])
        assert result.exit_code == 2
        _assert_bounded(result, str(missing), "Fix target does not exist")

    def test_audit_missing_rules_file_is_bounded(self, tmp_path: Path) -> None:
        project = tmp_path / "project"
        project.mkdir()
        missing = tmp_path / "rules.yaml"
        result = runner.invoke(
            app,
            ["audit", str(project), "--scan-semgrep", "--rules", str(missing)],
        )
        assert result.exit_code == 2
        _assert_bounded(result, str(missing), "Semgrep rules file not found")
