"""Capabilities must be honest and exports must use only the current report."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from agentscan.core.models import Finding, ScanMode, ScanReport, Severity

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient

from agentscan.ui.app import create_app
from agentscan.ui.routers import features
from agentscan.ui.state import state


@pytest.fixture
def client(tmp_path: Path):
    previous = (state.report, state.report_path)
    app = create_app(project_root=tmp_path)
    with TestClient(app) as instance:
        yield instance
    state.report, state.report_path = previous


def test_capabilities_do_not_probe_network_models_or_credentials(client, monkeypatch):
    checked = []

    def presence(module):
        checked.append(module)
        return object() if module == "playwright" else None

    monkeypatch.setattr(importlib.util, "find_spec", presence)
    monkeypatch.setenv("GEMINI_API_KEY", "synthetic-provider-key-must-not-appear")
    response = client.get("/api/features")
    assert response.status_code == 200
    body = response.json()
    runtime = {item["id"]: item for item in body["runtime"]}
    assert runtime["deep"]["missing_packages"] == ["torch", "transformers"]
    assert runtime["browser"]["installed"] is True
    assert not any(item["verified"] for item in runtime.values())
    assert checked == [
        "torch",
        "transformers",
        "playwright",
        "sentence_transformers",
        "weasyprint",
        "semgrep",
    ]
    assert body["analysis_policy"]["sensitive_modes"] == ["deterministic", "local"]
    assert "non_sensitive" in body["analysis_policy"]["external_requires"]
    assert "synthetic-provider-key" not in response.text
    assert body["report"]["available"] is False
    workflows = {item["id"]: item for item in body["workflows"]}
    assert workflows["profiles"]["surface"] == "terminal"
    assert workflows["browser_scan"]["surface"] == "terminal"


@pytest.mark.parametrize("error", [ImportError, ValueError, OSError])
def test_broken_optional_module_is_unavailable(monkeypatch, error):
    def broken(module):
        raise error("synthetic package metadata failure")

    monkeypatch.setattr(importlib.util, "find_spec", broken)
    assert features._module_available("torch") is False


@pytest.mark.parametrize("format", ["json", "sarif", "html"])
def test_download_without_report_is_actionable(client, format):
    response = client.get("/api/report/download", params={"format": format})
    assert response.status_code == 404
    assert "No scan report" in response.json()["field_errors"]["report"]


@pytest.mark.parametrize("format", ["pdf", "zip", "../report.json", "", "HTML"])
def test_download_rejects_unsupported_formats(client, format):
    response = client.get("/api/report/download", params={"format": format})
    assert response.status_code == 422
    assert "format" in response.json()["field_errors"]


def _report() -> ScanReport:
    report = ScanReport(
        target_url="http://agent.example/chat",
        scan_mode=ScanMode.SCAN,
        scan_id='unsafe/filename"\r\nheader',
        findings=[
            Finding(
                attack_id="ATK-001",
                attack_name="Direct Prompt Injection",
                severity=Severity.HIGH,
                owasp_id="LLM01",
                description='<script>alert("synthetic")</script>',
            )
        ],
        status="ERROR",
        score=None,
        tests_selected=3,
        module_errors=[{"module_id": "ATK-001", "error": "Target returned HTTP 401"}],
    )
    return report


@pytest.mark.parametrize("format", ["json", "sarif", "html"])
def test_download_preserves_failed_assessment_and_fixed_filename(client, format):
    state.report = _report()
    response = client.get("/api/report/download", params={"format": format})
    assert response.status_code == 200
    assert (
        response.headers["content-disposition"]
        == f'attachment; filename="agentscan-report.{format}"'
    )
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["cache-control"] == "no-store"
    if format == "json":
        report = response.json()
        assert report["status"] == "ERROR"
        assert report["score"] is None
        assert report["module_errors"][0]["error"] == "Target returned HTTP 401"
    elif format == "sarif":
        report = json.loads(response.text)
        assert report["version"] == "2.1.0"
        assert report["runs"][0]["results"][0]["ruleId"] == "ATK-001"
        assessment = report["runs"][0]["properties"]["agentscanAssessment"]
        assert assessment["status"] == "ERROR"
        assert assessment["module_errors"][0]["error"] == "Target returned HTTP 401"
        assert report["runs"][0]["invocations"][0]["executionSuccessful"] is False
    else:
        assert "sandbox" in response.headers["content-security-policy"]
        assert '<script>alert("synthetic")</script>' not in response.text
        assert "&lt;script&gt;" in response.text
        assert "<script src=" not in response.text
        assert 'href="https://' not in response.text
        assert 'src="https://' not in response.text


def test_download_requires_dashboard_authentication(tmp_path):
    with TestClient(create_app(token="synthetic-ui-token", project_root=tmp_path)) as client:
        assert client.get("/api/report/download").status_code == 401
        assert client.get("/api/features").status_code == 401


def test_html_download_includes_every_error_and_outcome_safely(client):
    report = _report()
    report.module_errors = [
        {
            "module_id": f"MODULE-{index}",
            "error": f"ERROR-MARKER-{index:02d} <img src=x onerror=alert(1)>",
        }
        for index in range(14)
    ]
    report.module_outcomes = [
        {
            "module_id": f"OUTCOME-{index:02d}",
            "status": "ERROR",
            "selected_tests": 1,
            "executed_tests": 0,
            "reason": "Target returned HTTP 401 <script>unsafe</script>",
        }
        for index in range(14)
    ]
    state.report = report
    response = client.get("/api/report/download", params={"format": "html"})
    assert response.status_code == 200
    assert "Recorded execution errors (14)" in response.text
    for index in range(14):
        assert f"ERROR-MARKER-{index:02d}" in response.text
        assert f"OUTCOME-{index:02d}" in response.text
    assert "<img src=x onerror=" not in response.text
    assert "&lt;img src=x onerror=" in response.text
    assert "<script>unsafe</script>" not in response.text
    assert "&lt;script&gt;unsafe&lt;/script&gt;" in response.text
    assert "This assessment is incomplete" in response.text
    assert "N/A" in response.text
