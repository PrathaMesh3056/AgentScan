# tests/test_reporting/test_audit_surfaces.py
#
# QA-036 regression tests: the CLI, MCP server and dashboard must describe the
# same static audit identically, must keep scanner failures visible instead of
# aborting the run, and must not turn a partial clean run into a full claim.

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from agentscan.cli import app
from agentscan.core.models import ScanMode, ScanReport
from agentscan.core.scorer import score_band
from agentscan.mcp.server import process_jsonrpc_message
from agentscan.reporting.audit_runner import run_static_audit
from agentscan.reporting.html_report import render_html_report

runner = CliRunner()

SELECTION = ("scan_config", "scan_secrets", "scan_identity")
ALL_CHECKS = (
    "scan_deps",
    "scan_config",
    "scan_secrets",
    "scan_typo",
    "scan_mcp",
    "scan_identity",
    "scan_frameworks",
    "scan_semgrep",
)


@pytest.fixture
def audit_fixture(tmp_path: Path) -> Path:
    (tmp_path / "app.py").write_text(
        "import os\n\nBASE_URL = 'https://example.test'\n", encoding="utf-8"
    )
    (tmp_path / "parity_agent.agent.json").write_text(
        json.dumps(
            {
                "agent_id": "parity_agent",
                "declared_role": "unknown_parity_role",
                "credential_ref": "PARITY_CREDENTIAL_REF",
                "tools": [{"tool_name": "run_shell", "capability_scopes": ["execute_shell"]}],
            }
        ),
        encoding="utf-8",
    )
    return tmp_path


def _checks_payload(enabled: tuple[str, ...] = SELECTION) -> dict[str, bool]:
    return {key: key in enabled for key in ALL_CHECKS}


def _cli_payload(fixture: Path, output: Path) -> dict:
    result = runner.invoke(
        app,
        [
            "audit",
            str(fixture),
            "--scan-config",
            "--scan-secrets",
            "--scan-identity",
            "--output",
            str(output),
        ],
    )
    assert result.exit_code == 0, result.output
    return json.loads(output.read_text(encoding="utf-8"))


def _dashboard_payload(fixture: Path) -> dict:
    from fastapi.testclient import TestClient

    from agentscan.ui.app import create_app

    client = TestClient(create_app(None, None, project_root=fixture))
    assert client.get("/").status_code == 200
    response = client.post(
        "/api/audit",
        json={
            "path": ".",
            "offline": True,
            "show_transitive": False,
            **_checks_payload(),
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def _mcp_payload(fixture: Path, checks: list[str] | None = None) -> dict:
    request = {
        "jsonrpc": "2.0",
        "id": 36,
        "method": "tools/call",
        "params": {
            "name": "agentscan_audit",
            "arguments": {
                "path": str(fixture),
                "offline": True,
                "show_transitive": False,
                "checks": checks or list(SELECTION),
            },
        },
    }
    response = process_jsonrpc_message(request)
    assert response is not None
    assert response["result"].get("isError") is not True, response
    return json.loads(response["result"]["content"][0]["text"])


def _normalized(data: dict) -> dict:
    entries = data.get("coverage", data.get("audit_coverage", []))
    coverage = sorted(
        (item["module"], item["status"], item.get("checks_run", 0)) for item in entries
    )
    findings = sorted(item.get("attack_id") or item["id"] for item in data["findings"])
    # The CLI report keeps the historical identity_score field for the same value.
    score = data.get("score", data.get("identity_score"))
    return {
        "status": data["status"],
        "risk_band": data.get("risk_band", score_band(score)),
        "score": score,
        "assessment_label": data["assessment_label"],
        "scope_complete": data["scope_complete"],
        "module_errors": data["module_errors"],
        "checks": data.get("checks_run", data.get("total_checks")),
        "findings": findings,
        "coverage": coverage,
    }


def test_cli_mcp_and_dashboard_describe_the_same_partial_audit(
    audit_fixture: Path, tmp_path: Path
) -> None:
    # Keep the CLI report outside the audited directory so it cannot change the
    # dashboard/MCP scans that follow (the secrets scanner would read it).
    output_dir = tmp_path.parent / f"{tmp_path.name}-cli-report"
    output_dir.mkdir()
    cli = _normalized(_cli_payload(audit_fixture, output_dir / "audit.json"))
    dashboard = _normalized(_dashboard_payload(audit_fixture))
    mcp = _normalized(_mcp_payload(audit_fixture))

    assert cli == dashboard == mcp
    assert cli["status"] == "COMPLETE"
    assert cli["assessment_label"] == "Mixed Static Audit (Supply-Chain + Identity)"
    assert cli["scope_complete"] is False
    assert cli["score"] is not None
    assert len(cli["coverage"]) == len(ALL_CHECKS)
    assert {status for _, status, _ in cli["coverage"]} == {"COMPLETE", "SKIPPED"}


def test_cli_preserves_scanner_exception_as_module_error(
    audit_fixture: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*args: object, **kwargs: object) -> tuple[list, int]:
        raise RuntimeError("synthetic config scanner failure")

    monkeypatch.setattr("agentscan.supply_chain.config_auditor.scan_config", boom)
    output = tmp_path / "errored.json"

    result = runner.invoke(
        app,
        ["audit", str(audit_fixture), "--scan-config", "--output", str(output)],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["status"] == "INCONCLUSIVE"
    assert payload["identity_score"] is None
    error_entries = [entry for entry in payload["audit_coverage"] if entry["status"] == "ERROR"]
    assert error_entries and error_entries[0]["module"] == "config"
    assert "synthetic config scanner failure" in error_entries[0]["limitations"][0]
    assert payload["module_errors"][0]["error"].startswith("RuntimeError:")
    assert payload["scope_complete"] is False


def test_dashboard_preserves_scanner_exception_as_module_error(
    audit_fixture: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from fastapi.testclient import TestClient

    from agentscan.ui.app import create_app

    def boom(*args: object, **kwargs: object) -> tuple[list, int]:
        raise RuntimeError("synthetic config scanner failure")

    monkeypatch.setattr("agentscan.supply_chain.config_auditor.scan_config", boom)
    client = TestClient(
        create_app(None, None, project_root=audit_fixture),
        raise_server_exceptions=False,
    )
    assert client.get("/").status_code == 200

    response = client.post(
        "/api/audit",
        json={"path": ".", **_checks_payload(("scan_config",))},
    )

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["status"] == "INCONCLUSIVE"
    assert payload["score"] is None
    error_entries = [entry for entry in payload["coverage"] if entry["status"] == "ERROR"]
    assert error_entries and error_entries[0]["module"] == "config"
    assert "synthetic config scanner failure" in error_entries[0]["limitations"][0]
    assert payload["module_errors"][0]["module"] == "scan_config"


def test_mcp_preserves_scanner_exception_as_module_error(
    audit_fixture: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*args: object, **kwargs: object) -> tuple[list, int]:
        raise RuntimeError("synthetic config scanner failure")

    monkeypatch.setattr("agentscan.supply_chain.config_auditor.scan_config", boom)

    payload = _mcp_payload(audit_fixture, checks=["scan_config"])

    assert payload["status"] == "INCONCLUSIVE"
    assert payload["score"] is None
    error_entries = [entry for entry in payload["coverage"] if entry["status"] == "ERROR"]
    assert error_entries and error_entries[0]["module"] == "config"
    assert payload["module_errors"][0]["module"] == "scan_config"


def test_partial_clean_audit_html_is_qualified(audit_fixture: Path) -> None:
    run = run_static_audit(str(audit_fixture), ["scan_config"])
    assert run.findings == []
    assert run.status == "COMPLETE"
    assert run.score == 100

    html = render_html_report(run.to_identity_report())

    assert "Supply-Chain Static Audit Report" in html
    assert "AI Agent Identity &amp; RBAC Entitlement Audit Report" not in html
    assert "1 of 8 coverage entries assessed" in html
    assert "SKIPPED" in html
    assert "Zero Identity Vulnerabilities Detected" not in html
    assert "No Findings in the Assessed Modules" in html
    assert "not a clean bill of health" in html


def test_mixed_scan_scope_is_labeled_in_html() -> None:
    report = ScanReport(
        target_url="http://agent.example/chat",
        scan_mode=ScanMode.SCAN,
    )
    report.complete(90, tests_run=1)
    report.assessment_scope = "mixed"

    html = render_html_report(report)

    assert "SCAN Mode · Mixed scan scope" in html
    assert "module outcomes cover multiple modes" in html
