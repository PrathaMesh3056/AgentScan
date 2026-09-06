# tests/test_cli.py
#
# Tests for agentscan/cli.py — scan command, --fail-on, and list-attacks.
# Uses typer.testing.CliRunner with respx to mock HTTP calls.

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from typer.testing import CliRunner

from agentscan.cli import app
from agentscan.core.models import (
    CalibrationResult,
    Finding,
    Framework,
    ScanMode,
    ScanReport,
    Severity,
)

runner = CliRunner()


def _make_report(findings: list[Finding], score: int) -> ScanReport:
    """Create a completed ScanReport for mocking."""
    report = ScanReport(
        target_url="http://test-agent.example.com/chat",
        scan_mode=ScanMode.SCAN,
        framework=Framework.AUTO,
        findings=findings,
    )
    report.complete(score)
    return report


def _make_finding(severity: Severity, attack_id: str = "ATK-001") -> Finding:
    return Finding(
        attack_id=attack_id,
        attack_name="Direct Prompt Injection",
        severity=severity,
        owasp_id="LLM01",
        description="Target accepted prompt injection payload and followed injected instruction.",
    )


class TestScanCommand:
    def test_scan_exit_code_zero(self) -> None:
        """scan command against a mocked target exits with code 0 and shows score."""
        report = _make_report(
            findings=[_make_finding(Severity.MEDIUM)],
            score=80,
        )
        with patch("agentscan.cli.run_scan_multi", new_callable=AsyncMock, return_value=report):
            result = runner.invoke(app, ["scan", "http://test-agent.example.com/chat"])

        assert result.exit_code == 0
        assert "AgentScan Score" in result.output
        assert "80/100" in result.output

    def test_fail_on_critical_exits_1(self) -> None:
        """--fail-on CRITICAL with a critical finding exits with code 1."""
        report = _make_report(
            findings=[_make_finding(Severity.CRITICAL)],
            score=10,
        )
        with patch("agentscan.cli.run_scan_multi", new_callable=AsyncMock, return_value=report):
            result = runner.invoke(
                app,
                ["scan", "http://test-agent.example.com/chat", "--fail-on", "CRITICAL"],
            )

        assert result.exit_code == 1

    def test_fail_on_info_does_not_exit_on_pass(self) -> None:
        """--fail-on INFO must not treat PASS findings as a CI failure."""
        report = _make_report(
            findings=[_make_finding(Severity.PASS)],
            score=100,
        )
        with patch("agentscan.cli.run_scan_multi", new_callable=AsyncMock, return_value=report):
            result = runner.invoke(
                app,
                ["scan", "http://test-agent.example.com/chat", "--fail-on", "INFO"],
            )
        assert result.exit_code == 0

    def test_fail_on_unknown_severity_errors(self) -> None:
        """Unknown --fail-on values must error instead of defaulting to rank 0."""
        report = _make_report(findings=[_make_finding(Severity.PASS)], score=100)
        with patch("agentscan.cli.run_scan_multi", new_callable=AsyncMock, return_value=report):
            result = runner.invoke(
                app,
                ["scan", "http://test-agent.example.com/chat", "--fail-on", "NOPE"],
            )
        assert result.exit_code != 0
        assert "Unknown --fail-on" in (result.output or "") or result.exception is not None

    def test_scan_passes_auth_header_to_target(self) -> None:
        report = _make_report(findings=[], score=100)
        with patch(
            "agentscan.cli.run_scan_multi", new_callable=AsyncMock, return_value=report
        ) as mock_run:
            result = runner.invoke(
                app,
                [
                    "scan",
                    "http://test-agent.example.com/chat",
                    "--auth-header",
                    "Bearer sk-test",
                ],
            )
        assert result.exit_code == 0
        target_obj, _ = mock_run.call_args[0]
        assert target_obj.auth_header == "Bearer sk-test"

    def test_scan_no_exploit_flag_does_not_output_atk014(self) -> None:
        """scan without --exploit outputs only SCAN-mode findings."""
        report = _make_report(
            findings=[_make_finding(Severity.HIGH, "ATK-001")],
            score=50,
        )
        with patch("agentscan.cli.run_scan_multi", new_callable=AsyncMock, return_value=report):
            result = runner.invoke(app, ["scan", "http://test-agent.example.com/chat"])

        assert result.exit_code == 0
        assert "ATK-001" in result.output
        assert "ATK-014" not in result.output

    def test_scan_exploit_flag_outputs_atk014(self) -> None:
        """scan --exploit --system-prompt "..." against a leaking target output contains ATK-014."""
        report = _make_report(
            findings=[
                _make_finding(Severity.HIGH, "ATK-001"),
                _make_finding(Severity.CRITICAL, "ATK-014"),
            ],
            score=0,
        )
        with patch("agentscan.cli.run_scan_multi", new_callable=AsyncMock, return_value=report):
            result = runner.invoke(
                app,
                [
                    "scan",
                    "http://test-agent.example.com/chat",
                    "--exploit",
                    "--system-prompt",
                    "secret",
                ],
            )

        assert result.exit_code == 0
        assert "ATK-001" in result.output
        assert "ATK-014" in result.output

    def test_scan_output_html_writes_valid_file(self, tmp_path) -> None:
        """scan --output report.html writes valid HTML and exits 0."""
        report = _make_report([_make_finding(Severity.HIGH)], 50)
        out = tmp_path / "report.html"
        with patch("agentscan.cli.run_scan_multi", new_callable=AsyncMock, return_value=report):
            result = runner.invoke(
                app, ["scan", "http://test-agent.example.com/chat", "--output", str(out)]
            )

        assert result.exit_code == 0
        assert out.exists()
        assert "<!DOCTYPE html>" in out.read_text()

    def test_scan_output_sarif_writes_valid_file(self, tmp_path) -> None:
        """scan --output report.sarif writes valid SARIF JSON and exits 0."""
        report = _make_report([_make_finding(Severity.HIGH)], 50)
        out = tmp_path / "report.sarif"
        with patch("agentscan.cli.run_scan_multi", new_callable=AsyncMock, return_value=report):
            result = runner.invoke(
                app, ["scan", "http://test-agent.example.com/chat", "--output", str(out)]
            )

        assert result.exit_code == 0
        assert out.exists()
        content = out.read_text()
        assert '"version": "2.1.0"' in content
        assert '"$schema"' in content

    @pytest.mark.slow
    def test_scan_deep_includes_deep_mode(self) -> None:
        """scan --deep correctly includes DEEP mode in the built modes list."""
        report = _make_report([], 100)
        with patch(
            "agentscan.cli.run_scan_multi", new_callable=AsyncMock, return_value=report
        ) as mock_run:
            result = runner.invoke(app, ["scan", "http://test-agent.example.com/chat", "--deep"])

        assert result.exit_code == 0
        mock_run.assert_called_once()
        _, modes_arg = mock_run.call_args[0]
        assert ScanMode.DEEP in modes_arg

    def test_scan_with_attacker_goal_and_escalation_options(self) -> None:
        """scan passes attacker-goal, escalation-model, and escalation-turns to Target."""
        report = _make_report([], 100)
        with patch(
            "agentscan.cli.run_scan_multi", new_callable=AsyncMock, return_value=report
        ) as mock_run:
            result = runner.invoke(
                app,
                [
                    "scan",
                    "http://test-agent.example.com/chat",
                    "--attacker-model",
                    "gpt-4o-mini",
                    "--attacker-goal",
                    "bypass scope constraints",
                    "--escalation-model",
                    "gpt-4o",
                    "--escalation-turns",
                    "3",
                ],
            )

        assert result.exit_code == 0
        mock_run.assert_called_once()
        target_obj, _ = mock_run.call_args[0]
        assert target_obj.attacker_model == "gpt-4o-mini"
        assert target_obj.attacker_goal == "bypass scope constraints"
        assert target_obj.escalation_model == "gpt-4o"
        assert target_obj.escalation_turns == 3

    def test_scan_calibrate_required_abort_on_failure(self) -> None:
        """--calibrate-required aborts the scan with exit code 1 when calibration fails."""
        mock_cal = CalibrationResult(passed=False, detail="Model is too weak")
        with patch(
            "agentscan.core.calibration.run_calibration",
            new_callable=AsyncMock,
            return_value=mock_cal,
        ):
            result = runner.invoke(
                app,
                [
                    "scan",
                    "http://test-agent.example.com/chat",
                    "--attacker-model",
                    "gpt-4o-mini",
                    "--calibrate-required",
                ],
            )

        assert result.exit_code == 1
        assert "Scan aborted because --calibrate-required was set" in result.output

    def test_yaml_calibrate_true_runs_calibration(self, tmp_path: Path) -> None:
        """target.yaml calibrate: true must run positive-control calibration."""
        cfg = tmp_path / "target.yaml"
        cfg.write_text(
            "url: http://test-agent.example.com/chat\n"
            "calibrate: true\n"
            "attacker_model: gpt-4o-mini\n",
            encoding="utf-8",
        )
        report = _make_report([], 100)
        mock_cal = CalibrationResult(passed=True, detail="Control detected")
        with (
            patch(
                "agentscan.core.calibration.run_calibration",
                new_callable=AsyncMock,
                return_value=mock_cal,
            ) as cal,
            patch("agentscan.cli.run_scan_multi", new_callable=AsyncMock, return_value=report),
        ):
            result = runner.invoke(app, ["scan", "-c", str(cfg)])
        assert result.exit_code == 0
        cal.assert_called_once()
        assert "attacker validated" in result.output

    def test_scan_calibrate_required_proceeds_on_success(self) -> None:
        """--calibrate-required proceeds with scan when calibration passes."""
        report = _make_report([], 100)
        mock_cal = CalibrationResult(passed=True, detail="Control detected")
        with (
            patch(
                "agentscan.core.calibration.run_calibration",
                new_callable=AsyncMock,
                return_value=mock_cal,
            ),
            patch(
                "agentscan.cli.run_scan_multi",
                new_callable=AsyncMock,
                return_value=report,
            ),
        ):
            result = runner.invoke(
                app,
                [
                    "scan",
                    "http://test-agent.example.com/chat",
                    "--attacker-model",
                    "gpt-4o-mini",
                    "--calibrate-required",
                ],
            )

        assert result.exit_code == 0
        assert "attacker validated" in result.output
        assert report.calibration == mock_cal
        assert report.attacker_config is not None
        assert report.attacker_config.model == "gpt-4o-mini"

    def test_calibrate_command_with_attacker_goal(self) -> None:
        """calibrate command accepts optional --attacker-goal."""
        mock_cal = CalibrationResult(passed=True, detail="Validated with custom goal")
        with patch(
            "agentscan.core.calibration.run_calibration",
            new_callable=AsyncMock,
            return_value=mock_cal,
        ) as mock_run:
            result = runner.invoke(
                app,
                [
                    "calibrate",
                    "--attacker-model",
                    "gpt-4o-mini",
                    "--attacker-goal",
                    "exfiltrate data",
                ],
            )

        assert result.exit_code == 0
        mock_run.assert_called_once_with("gpt-4o-mini", attacker_goal="exfiltrate data")


class TestListAttacks:
    def test_scan_config_profile_builds_browser_target(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        """A YAML profile supplies the url, browser selectors, and exploit flag."""
        profile = tmp_path / "target.yaml"
        profile.write_text(
            "url: http://widget.local/\n"
            "browser:\n"
            "  input_selector: '#msg'\n"
            "  response_selector: '.bot'\n"
            "  open_selector: '#launch'\n"
            "exploit: true\n",
            encoding="utf-8",
        )
        report = _make_report(findings=[], score=100)
        with patch(
            "agentscan.cli.run_scan_multi", new_callable=AsyncMock, return_value=report
        ) as m:
            result = runner.invoke(app, ["scan", "-c", str(profile)])

        assert result.exit_code == 0
        target_obj, modes = m.call_args[0][0], m.call_args[0][1]
        assert target_obj.url == "http://widget.local"  # validator strips trailing slash
        assert target_obj.browser is not None
        assert target_obj.browser.input_selector == "#msg"
        assert target_obj.browser.open_selector == "#launch"
        assert ScanMode.EXPLOIT in modes  # exploit: true from the profile

    def test_list_attacks_shows_atk001(self) -> None:
        """list-attacks output contains ATK-001."""
        result = runner.invoke(app, ["list-attacks"])
        assert result.exit_code == 0
        assert "ATK-001" in result.output
        assert "Direct Prompt Injection" in result.output
        assert "LLM01" in result.output


class TestAuditCommand:
    def test_audit_scan_deps_vulnerable_fixture(self) -> None:
        """audit --scan-deps against vulnerable_requirements.txt fixture produces SC-001 in output."""
        fixture_dir = "tests/fixtures/supply_chain"
        result = runner.invoke(app, ["audit", fixture_dir, "--scan-deps"])
        assert result.exit_code == 0
        assert "SC-001" in result.output

    def test_audit_fail_on_high_exits_1_when_cve_found(self) -> None:
        fixture_dir = "tests/fixtures/supply_chain"
        result = runner.invoke(app, ["audit", fixture_dir, "--scan-deps", "--fail-on", "HIGH"])
        assert result.exit_code == 1

    def test_audit_scan_identity_demo_agents(self) -> None:
        """audit --scan-identity against demo-agents fixture produces ID- findings in output."""
        fixture_dir = "tests/fixtures/demo-agents"
        result = runner.invoke(app, ["audit", fixture_dir, "--scan-identity"])
        assert result.exit_code == 0
        # The demo-agents fixture produces ID-005 (shared credential) and others
        assert "ID-" in result.output

    def test_audit_no_flags_runs_all_categories(self) -> None:
        """audit with no flags runs all six scanners and shows a score."""
        fixture_dir = "tests/fixtures/supply_chain"
        result = runner.invoke(app, ["audit", fixture_dir])
        assert result.exit_code == 0
        assert "Audit Score" in result.output
