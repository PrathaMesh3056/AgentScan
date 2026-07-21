# tests/test_cli.py
#
# Tests for agentscan/cli.py — scan command, --fail-on, and list-attacks.
# Uses typer.testing.CliRunner with respx to mock HTTP calls.

from __future__ import annotations

from unittest.mock import AsyncMock, patch

from typer.testing import CliRunner

from agentscan.cli import app
from agentscan.core.models import Finding, Framework, ScanMode, ScanReport, Severity

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
        with patch("agentscan.cli.run_scan", new_callable=AsyncMock, return_value=report):
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
        with patch("agentscan.cli.run_scan", new_callable=AsyncMock, return_value=report):
            result = runner.invoke(
                app,
                ["scan", "http://test-agent.example.com/chat", "--fail-on", "CRITICAL"],
            )

        assert result.exit_code == 1


class TestListAttacks:
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
