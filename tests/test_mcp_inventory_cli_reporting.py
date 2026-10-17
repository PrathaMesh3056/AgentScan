"""User-facing enrollment, exit codes and catalog-policy report boundaries."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from typer.testing import CliRunner

from agentscan.cli import app
from agentscan.core.mcp_inventory import McpInventoryBaseline
from agentscan.core.models import Finding, ScanMode, ScanReport, Severity
from agentscan.reporting.html_report import render_html_report
from agentscan.reporting.sarif_report import to_sarif

ENDPOINT = "mcp+sses://catalog-fixture.example/mcp"
HEADER_SECRET = "synthetic-enrollment-header-DO-NOT-DISPLAY"
runner = CliRunner()


def _baseline(**changes: Any) -> dict[str, Any]:
    return {
        "algorithm": "mcp-tool-json-sha256-v1",
        "endpoint": ENDPOINT,
        "tools": {},
        **changes,
    }


def _profile(tmp_path: Path, baseline: Any) -> Path:
    profile = tmp_path / "target.yaml"
    # JSON is also valid YAML and preserves explicit empty objects and scalars.
    profile.write_text(
        json.dumps(
            {
                "url": ENDPOINT,
                "analysis_mode": "deterministic",
                "auth_header": f"Bearer {HEADER_SECRET}",
                "mcp_inventory_baseline": baseline,
            }
        ),
        encoding="utf-8",
    )
    return profile


def _catalog_report(*, deviation: bool, status: str = "COMPLETE") -> ScanReport:
    findings = []
    if deviation:
        findings.append(
            Finding(
                attack_id="ATK-006",
                attack_name="MCP Shadow Server",
                severity=Severity.MEDIUM,
                owasp_id="LLM01",
                description="Catalog differs from the approved snapshot; execution is unassessed.",
                metadata={
                    "assessment_scope": "mcp_catalog_policy",
                    "deviation_counts": {"metadata_changed": 1},
                    "deviations": [
                        {
                            "name": "approved_lookup",
                            "kind": "metadata_changed",
                            "expected_sha256": "a" * 64,
                            "observed_sha256": "b" * 64,
                        }
                    ],
                    "tool_execution_verified": False,
                },
            ).model_dump(mode="json")
        )
    executed = int(status == "COMPLETE")
    report = ScanReport(
        target_url=ENDPOINT,
        scan_mode=ScanMode.SCAN,
        assessment_scope="mcp_catalog_policy",
        tests_selected=1,
        tests_run=executed,
        module_outcomes=[
            {
                "module_id": "ATK-006",
                "module_name": "MCP Shadow Server",
                "assessment_scope": "mcp_catalog_policy",
                "selected_tests": 1,
                "executed_tests": executed,
                "status": status,
                "catalog_findings": findings,
                "catalog_finding_count": len(findings),
                "reason": "One catalog snapshot; downstream execution remains unassessed.",
            }
        ],
    )
    report.complete(None, status=status)
    return report


@pytest.mark.parametrize(
    ("tools", "deviation", "status", "threshold", "expected_exit"),
    [
        ({}, False, "COMPLETE", "MEDIUM", 0),
        ({"approved_lookup": "a" * 64}, True, "COMPLETE", "MEDIUM", 1),
        ({}, True, "COMPLETE", "HIGH", 0),
        ({}, False, "INCONCLUSIVE", "MEDIUM", 3),
        ({}, True, "INCONCLUSIVE", "MEDIUM", 3),
    ],
)
def test_catalog_profile_round_trip_and_policy_exit_export(
    tmp_path: Path,
    tools: dict[str, str],
    deviation: bool,
    status: str,
    threshold: str,
    expected_exit: int,
) -> None:
    profile = _profile(tmp_path, _baseline(tools=tools))
    output = tmp_path / "catalog-report.json"
    report = _catalog_report(deviation=deviation, status=status)
    with patch("agentscan.cli.run_scan_multi", new_callable=AsyncMock, return_value=report) as work:
        result = runner.invoke(
            app,
            ["scan", "--config", str(profile), "--output", str(output), "--fail-on", threshold],
        )

    assert result.exit_code == expected_exit, result.output
    work.assert_awaited_once()
    target, modes = work.await_args.args
    assert isinstance(target.mcp_inventory_baseline, McpInventoryBaseline)
    assert target.mcp_inventory_baseline.model_dump() == _baseline(tools=tools)
    assert target.url == ENDPOINT
    assert target.auth_header == f"Bearer {HEADER_SECRET}"
    assert modes == [ScanMode.SCAN]
    assert HEADER_SECRET not in result.output
    assert "AgentScan Score" not in result.output
    assert "overall agent security is unassessed" in result.output
    if deviation:
        assert "MCP Catalog Policy Deviations" in result.output
        assert "MEDIUM" in result.output
    else:
        assert "No catalog deviations recorded" in result.output
    exported = json.loads(output.read_text(encoding="utf-8"))
    assert exported["assessment_scope"] == "mcp_catalog_policy"
    assert exported["status"] == status and exported["score"] is None
    assert exported["findings"] == []
    assert exported["module_outcomes"][0]["catalog_finding_count"] == int(deviation)


@pytest.mark.parametrize(
    "baseline",
    [
        _baseline(algorithm="unapproved-algorithm"),
        _baseline(tools={"approved_lookup": "not-a-sha256"}),
        _baseline(endpoint="mcp+sses://another-fixture.example/mcp"),
        _baseline(endpoint=f"mcp+sses://{HEADER_SECRET}@catalog-fixture.example/mcp"),
        _baseline(unapproved_field=HEADER_SECRET),
        _baseline(tools={"approved_lookup": "A" * 64}),
        17,
        "not-an-enrollment-object",
    ],
)
def test_bad_baseline_is_a_safe_field_error_before_work(tmp_path: Path, baseline: Any) -> None:
    profile = _profile(tmp_path, baseline)
    with patch("agentscan.cli.run_scan_multi", new_callable=AsyncMock) as work:
        result = runner.invoke(app, ["scan", "--config", str(profile)])
    assert result.exit_code == 2, result.output
    assert "mcp_inventory_baseline" in result.output
    assert HEADER_SECRET not in result.output
    work.assert_not_called()


@pytest.mark.parametrize(
    "flags",
    [
        ["--exploit"],
        ["--deep"],
        ["--mutate"],
        ["--analysis", "local"],
        ["--analysis", "external", "--external-model", "gemini/synthetic-model"],
        ["--calibrate"],
        ["--calibrate-required"],
        ["--attacker-model", "ollama/synthetic-model"],
        ["--judge-model", "ollama/synthetic-model"],
        ["--escalation-model", "ollama/synthetic-model"],
    ],
)
def test_catalog_profile_rejects_active_or_model_modes_without_work(
    tmp_path: Path, flags: list[str]
) -> None:
    profile = _profile(tmp_path, _baseline())
    with patch("agentscan.cli.run_scan_multi", new_callable=AsyncMock) as work:
        result = runner.invoke(app, ["scan", "--config", str(profile), *flags], input="")
    assert result.exit_code == 2, result.output
    assert "mcp_inventory_baseline" in result.output and "catalog-only" in result.output
    assert HEADER_SECRET not in result.output
    assert "Do you" not in result.output and "Are you" not in result.output
    work.assert_not_called()


def test_report_formats_preserve_policy_scope_and_escape_catalog_content() -> None:
    report = _catalog_report(deviation=True)
    finding = report.module_outcomes[0]["catalog_findings"][0]
    finding["description"] = "<script>description-marker</script>"
    deviation = finding["metadata"]["deviations"][0]
    for key, marker in (
        ("name", "name-marker"),
        ("expected_sha256", "expected-hash-marker"),
        ("observed_sha256", "observed-hash-marker"),
    ):
        deviation[key] = f"<script>{marker}</script>"

    exported = json.loads(report.model_dump_json())
    assert exported["score"] is None and exported["findings"] == []
    assert exported["module_outcomes"] == report.module_outcomes

    sarif_run = to_sarif(report)["runs"][0]
    assert sarif_run["results"] == []
    assert sarif_run["tool"]["driver"]["rules"] == []
    assessment = sarif_run["properties"]["agentscanAssessment"]
    assert assessment["scope"] == "mcp_catalog_policy" and assessment["score"] is None
    assert assessment["module_outcomes"] == report.module_outcomes

    rendered = render_html_report(report)
    assert "MCP catalog policy comparison" in rendered
    assert "excluded from overall agent-security scoring" in rendered
    assert (
        "Tool execution, endpoint migration and later metadata changes remain unassessed"
        in rendered
    )
    assert "<script>" not in rendered
    for marker in (
        "description-marker",
        "name-marker",
        "expected-hash-marker",
        "observed-hash-marker",
    ):
        assert f"&lt;script&gt;{marker}&lt;/script&gt;" in rendered
    assert "Zero Vulnerabilities" not in rendered
    assert "100/100" not in rendered
