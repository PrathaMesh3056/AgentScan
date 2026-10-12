# tests/test_e2e.py
#
# End-to-end integration tests for AgentScan CLI:
# - Mocked HTTP scan against a controlled target
# - SARIF report generation & schema verification
# - Incomplete-coverage exit precedence and preserved findings/exports
# - --transcript generation and redaction verification

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import respx
from typer.testing import CliRunner

from agentscan.cli import app

runner = CliRunner()


def _assert_incomplete_coverage(report: dict) -> None:
    assert report["status"] == "INCONCLUSIVE"
    assert report["score"] is None
    assert 0 < report["tests_run"] < report["tests_selected"]
    assert any(
        outcome["status"] in {"INCONCLUSIVE", "SKIPPED"} for outcome in report["module_outcomes"]
    )


class TestEndToEndScan:
    @respx.mock
    def test_e2e_scan_generates_valid_sarif(self, tmp_path: Path) -> None:
        """Verify full scan workflow generates valid SARIF 2.1.0 report."""
        sarif_out = tmp_path / "results.sarif"

        respx.post("http://e2e-agent.test/chat").mock(
            return_value=httpx.Response(
                200,
                json={
                    "response": "I cannot fulfill this request. I only answer product questions."
                },
            )
        )

        result = runner.invoke(
            app,
            [
                "scan",
                "http://e2e-agent.test/chat",
                "--output",
                str(sarif_out),
            ],
        )

        assert result.exit_code == 3, f"CLI output: {result.output}"
        assert sarif_out.exists()

        data = json.loads(sarif_out.read_text(encoding="utf-8"))
        assert data.get("version") == "2.1.0"
        assert "$schema" in data
        assert "runs" in data and len(data["runs"]) > 0
        driver = data["runs"][0]["tool"]["driver"]
        assert driver["name"] == "AgentScan"
        _assert_incomplete_coverage(data["runs"][0]["properties"]["agentscanAssessment"])
        assert data["runs"][0]["invocations"][0]["executionSuccessful"] is False

    @respx.mock
    def test_e2e_incomplete_coverage_keeps_findings_and_takes_exit_precedence(
        self, tmp_path: Path
    ) -> None:
        """Incomplete full-suite coverage takes exit precedence over severity findings."""
        # Mock target that naively complies, triggering findings
        respx.post("http://e2e-vulnerable.test/chat").mock(
            side_effect=lambda request: httpx.Response(
                200,
                json={"response": f"Sure! As instructed: {request.content.decode('utf-8')}"},
            )
        )

        # The echo target supplies no private reference or document adapter.
        # Some modules still evaluate and retain findings, without complete coverage.
        normal_output = tmp_path / "normal.json"
        res_normal = runner.invoke(
            app, ["scan", "http://e2e-vulnerable.test/chat", "--output", str(normal_output)]
        )
        assert res_normal.exit_code == 3
        normal_report = json.loads(normal_output.read_text(encoding="utf-8"))
        _assert_incomplete_coverage(normal_report)
        assert normal_report["findings"]

        # --fail-on remains distinct from incomplete-assessment exit semantics.
        fail_output = tmp_path / "fail-on.json"
        res_fail = runner.invoke(
            app,
            [
                "scan",
                "http://e2e-vulnerable.test/chat",
                "--fail-on",
                "low",
                "--output",
                str(fail_output),
            ],
        )
        assert res_fail.exit_code == 3
        fail_report = json.loads(fail_output.read_text(encoding="utf-8"))
        _assert_incomplete_coverage(fail_report)
        assert fail_report["findings"]
        assert any(
            finding["severity"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
            for finding in fail_report["findings"]
        )

    @respx.mock
    def test_e2e_transcript_and_redaction(self, tmp_path: Path) -> None:
        """Verify --transcript captures traffic and redacts sensitive credentials."""
        transcript_path = tmp_path / "scan_traffic.txt"
        from agentscan.core.context import active_context
        from agentscan.core.trace import recorder

        previous_context = active_context.get()
        previous_recording = recorder.enabled

        # Mock target replying with an echo including an API key
        respx.post("http://e2e-secret.test/chat").mock(
            return_value=httpx.Response(
                200,
                json={
                    "response": "Using api_key: sk-1234567890abcdef1234567890 and Bearer secret-token-abc-12345"
                },
            )
        )

        result = runner.invoke(
            app,
            [
                "scan",
                "http://e2e-secret.test/chat",
                "--transcript",
                str(transcript_path),
            ],
        )

        assert result.exit_code == 3
        assert transcript_path.exists()
        content = transcript_path.read_text(encoding="utf-8")
        assert "AgentScan Transcript" in content
        assert "<< REPLY" in content and "Using api_key:" in content
        assert "Status: INCONCLUSIVE" in content
        assert "Score: unavailable" in content
        assert "ASSESSMENT COVERAGE" in content
        assert "Provision a confidential canary" in content
        assert "resisted every payload" not in content
        # Ensure credentials were redacted
        assert "sk-1234567890abcdef1234567890" not in content
        assert "secret-token-abc-12345" not in content
        assert "[REDACTED]" in content
        assert active_context.get() is previous_context
        assert recorder.enabled is previous_recording

    @respx.mock
    @pytest.mark.parametrize("credential", ["local-private-Qz82tP", "abc"])
    def test_cli_transcript_redacts_bare_known_credentials_of_any_evidence_length(
        self, tmp_path: Path, credential: str
    ) -> None:
        from agentscan.core.context import active_context
        from agentscan.core.trace import recorder

        previous_context = active_context.get()
        previous_recording = recorder.enabled
        transcript = tmp_path / "known-credential.txt"
        respx.post("http://e2e-known-private.test/chat").mock(
            return_value=httpx.Response(
                200, json={"response": f"Bare protected value: {credential}"}
            )
        )
        result = runner.invoke(
            app,
            [
                "scan",
                "http://e2e-known-private.test/chat",
                "--system-prompt",
                f'API_TOKEN = "{credential}"',
                "--transcript",
                str(transcript),
            ],
        )
        assert result.exit_code == 3
        content = transcript.read_text(encoding="utf-8")
        assert "<< REPLY" in content
        assert "Status: INCONCLUSIVE" in content
        assert "Score: unavailable" in content
        assert "ASSESSMENT COVERAGE" in content
        assert "Bare protected value: [REDACTED]" in content
        assert credential not in content
        assert active_context.get() is previous_context
        assert recorder.enabled is previous_recording
