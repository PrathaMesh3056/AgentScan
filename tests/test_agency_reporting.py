"""Agency claims cross the real client, runner and CLI/report boundaries."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import pytest
import respx
from typer.testing import CliRunner

from agentscan.attacks.base import AttackModule
from agentscan.attacks.registry import AttackRegistry
from agentscan.attacks.scan.excessive_agency import ExcessiveAgencyModule
from agentscan.cli import app
from agentscan.core.context import active_context
from agentscan.core.models import Finding, ScanMode, ScanReport, Severity, Target
from agentscan.core.runner import run_scan
from agentscan.reporting.sarif_report import to_sarif


@pytest.mark.parametrize("reply", [{"choices": [None]}, {"choices": [{"message": "invalid"}]}])
async def test_malformed_choices_reach_inventory_through_real_http_client(reply):
    registry = AttackRegistry()
    registry.register(ExcessiveAgencyModule())
    registry._loaded = True
    previous = active_context.get()
    try:
        with patch("agentscan.core.runner.registry", registry), respx.mock() as router:
            route = router.post("http://agency.invalid/chat").respond(200, json=reply)
            report = await run_scan(Target(url="http://agency.invalid/chat"))
        assert route.call_count == 10
        assert report.status == "INCONCLUSIVE"
        assert report.assessment_scope == "agency_proposal_inventory"
        assert report.tests_run == 0 and report.score is None and report.ssp_class is None
        assert report.findings == []
        observations = report.module_outcomes[0]["observations"]
        assert len(observations) == 10
        assert all(item["malformed_proposal_count"] == 1 for item in observations)
    finally:
        active_context.set(previous)


async def test_mixed_scan_withholds_claim_based_ssp_and_preserves_independent_findings():
    class IndependentControl(AttackModule):
        attack_id = "ATK-AGENCY-CONTROL"
        attack_name = "Independent fixture evidence"
        owasp_id = "LLM06"

        async def run(self, target: Target) -> list[Finding]:
            return [self.make_finding(Severity.HIGH, "Independent controlled finding")]

    registry = AttackRegistry()
    registry.register(ExcessiveAgencyModule())
    registry.register(IndependentControl())
    registry._loaded = True
    previous = active_context.get()
    try:
        with patch("agentscan.core.runner.registry", registry), respx.mock() as router:
            router.post("http://agency.invalid/chat").respond(
                200,
                json={
                    "response": "Target reported completion only.",
                    "tool_calls": [{"name": "delete_unrelated_side_effect", "executed": True}],
                },
            )
            report = await run_scan(Target(url="http://agency.invalid/chat"))
        assert report.status == "INCONCLUSIVE" and report.assessment_scope == "mixed"
        assert len(report.trajectory) == 10
        assert report.ssp_class is None
        assert report.tests_run == 1 and report.score is None
        assert [finding.attack_id for finding in report.findings] == ["ATK-AGENCY-CONTROL"]
    finally:
        active_context.set(previous)


def test_cli_preserves_agency_scope_diagnostics_and_export_before_exit_three(tmp_path):
    report = ScanReport(
        target_url="http://agency.invalid/chat",
        scan_mode=ScanMode.SCAN,
        assessment_scope="agency_proposal_inventory",
        tests_selected=10,
        module_outcomes=[
            {
                "module_id": "ATK-013",
                "assessment_scope": "agency_proposal_inventory",
                "selected_tests": 10,
                "executed_tests": 0,
                "status": "INCONCLUSIVE",
                "reason": "Independent policy and effects are unavailable.",
                "observations": [{"variant_id": "EXA-001", "reported_proposal_count": 1}],
            }
        ],
    )
    report.complete(None, status="INCONCLUSIVE")
    output = tmp_path / "agency-report.json"
    with patch("agentscan.cli.run_scan_multi", new_callable=AsyncMock, return_value=report):
        result = CliRunner().invoke(
            app, ["scan", report.target_url, "--output", str(output), "--fail-on", "HIGH"]
        )
    assert result.exit_code == 3, result.output
    assert "ATK-013: 1 bounded agency response observations" in result.output
    assert "Authorization, approval and actual tool effects are unassessed" in result.output
    assert "SSP class: Unknown" in result.output
    assert "Servant" not in result.output
    saved = json.loads(output.read_text(encoding="utf-8"))
    assert saved["assessment_scope"] == "agency_proposal_inventory"
    assert saved["findings"] == [] and saved["score"] is None and saved["ssp_class"] is None
    sarif = to_sarif(report)["runs"][0]
    assert sarif["results"] == []
    assessment = sarif["properties"]["agentscanAssessment"]
    assert assessment["scope"] == "agency_proposal_inventory"
    assert assessment["score"] is None
    assert assessment["module_outcomes"] == report.module_outcomes
