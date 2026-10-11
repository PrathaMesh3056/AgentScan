# tests/test_e2e.py
#
# End-to-end integration tests for AgentScan CLI:
# - Live HTTP scan against mock target
# - SARIF report generation & schema verification
# - --fail-on exit code behavior
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

        assert result.exit_code == 0, f"CLI output: {result.output}"
        assert sarif_out.exists()

        data = json.loads(sarif_out.read_text(encoding="utf-8"))
        assert data.get("version") == "2.1.0"
        assert "$schema" in data
        assert "runs" in data and len(data["runs"]) > 0
        driver = data["runs"][0]["tool"]["driver"]
        assert driver["name"] == "AgentScan"

    @respx.mock
    def test_e2e_fail_on_threshold(self) -> None:
        """Verify --fail-on triggers non-zero exit code when matching findings exist."""
        # Mock target that naively complies, triggering findings
        respx.post("http://e2e-vulnerable.test/chat").mock(
            side_effect=lambda request: httpx.Response(
                200,
                json={"response": f"Sure! As instructed: {request.content.decode('utf-8')}"},
            )
        )

        # 1. Without --fail-on, exits 0
        res_normal = runner.invoke(app, ["scan", "http://e2e-vulnerable.test/chat"])
        assert res_normal.exit_code == 0

        # 2. With --fail-on low, exits 1 because vulnerabilities were found
        res_fail = runner.invoke(
            app,
            [
                "scan",
                "http://e2e-vulnerable.test/chat",
                "--fail-on",
                "low",
            ],
        )
        assert res_fail.exit_code == 1

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

        assert result.exit_code == 0
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
        assert result.exit_code == 0
        content = transcript.read_text(encoding="utf-8")
        assert "<< REPLY" in content
        assert "Bare protected value: [REDACTED]" in content
        assert credential not in content
        assert active_context.get() is previous_context
        assert recorder.enabled is previous_recording
