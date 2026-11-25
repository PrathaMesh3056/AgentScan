"""Issue #39: dashboard scan lifecycle, severity ordering and target authentication."""

from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agentscan.core.models import ScanMode, ScanReport
from agentscan.ui.app import create_app
from agentscan.ui.routers.scan import api_scan_cancel, api_start_scan
from agentscan.ui.state import state

ROOT = Path(__file__).resolve().parents[1]
STATIC_DIR = ROOT / "agentscan" / "ui" / "static"
ENDPOINT = "http://127.0.0.1:8081/chat"


@pytest.fixture(autouse=True)
def isolated_scan_state(monkeypatch):
    monkeypatch.setattr(state, "active_scan", None)
    monkeypatch.setattr(state, "scan_recorder", None)
    monkeypatch.setattr(state, "report", None)
    monkeypatch.setattr(state, "report_path", None)
    monkeypatch.setattr(state, "scan_status", {"status": "idle"})
    yield


@pytest.fixture
def client(tmp_path: Path):
    with TestClient(create_app(project_root=tmp_path), base_url="http://127.0.0.1:8765") as value:
        yield value


def make_report(target: str = ENDPOINT, scan_id: str = "prior-scan") -> ScanReport:
    report = ScanReport(
        target_url=target,
        scan_mode=ScanMode.SCAN,
        tests_selected=1,
        tests_run=1,
    )
    report.complete(None, status="COMPLETE")
    report.scan_id = scan_id
    return report


def run_node(script: str) -> None:
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is required for dashboard JavaScript contracts")
    result = subprocess.run(
        [node, "-e", script],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr or result.stdout


async def test_cancel_does_not_overwrite_idle_or_finished_state() -> None:
    idle = await api_scan_cancel()
    assert idle.status_code == 200
    idle_body = json.loads(idle.body)
    assert idle_body["cancelled"] is False
    assert idle_body["status"] == "idle"
    assert state.scan_status["status"] == "idle"

    state.scan_status = {"status": "completed", "scan_id": "finished-1", "progress": 100}
    finished = await api_scan_cancel()
    finished_body = json.loads(finished.body)
    assert finished_body["cancelled"] is False
    assert finished_body["status"] == "completed"
    assert state.scan_status["status"] == "completed"
    assert state.scan_status["scan_id"] == "finished-1"


def test_state_machine_rejects_illegal_transitions_and_is_idempotent() -> None:
    from agentscan.ui.state import ScanStateError

    with pytest.raises(ScanStateError):
        state.finish_scan("completed")

    state.begin_scan("scan-1", ENDPOINT, ["SCAN"])
    assert state.scan_status["status"] == "running"
    with pytest.raises(ScanStateError):
        state.begin_scan("scan-2", ENDPOINT, ["SCAN"])

    state.finish_scan(
        "completed",
        tests_run=1,
        tests_selected=1,
        findings_count=1,
        score=97,
        module_errors=[],
        module_outcomes=[],
        assessment_scope="target",
    )
    assert state.scan_status["status"] == "completed"
    assert state.scan_status["progress"] == 100
    assert state.scan_status["scan_id"] == "scan-1"
    assert state.scan_status["finished_at"]

    state.finish_scan("failed")
    assert state.scan_status["status"] == "completed"
    assert state.scan_status["scan_id"] == "scan-1"


async def test_running_and_failed_scans_retain_the_previous_report(monkeypatch, client) -> None:
    previous = make_report("http://127.0.0.1:8081/prior")
    state.report = previous
    blocker = asyncio.Event()

    async def blocked(target, modes):
        await blocker.wait()
        return make_report(scan_id="new-scan")

    monkeypatch.setattr("agentscan.core.runner.run_scan_multi", blocked)
    response = await api_start_scan({"target_url": ENDPOINT})
    assert response.status_code == 200
    assert state.report is previous
    assert client.get("/api/report").json()["scan_id"] == "prior-scan"

    await api_scan_cancel()
    task = state.active_scan
    with pytest.raises(asyncio.CancelledError):
        await task
    assert state.scan_status["status"] == "cancelled"
    assert state.report is previous

    async def boom(target, modes):
        raise RuntimeError("synthetic scan failure")

    monkeypatch.setattr("agentscan.core.runner.run_scan_multi", boom)
    assert (await api_start_scan({"target_url": ENDPOINT})).status_code == 200
    await state.active_scan
    assert state.scan_status["status"] == "failed"
    assert state.report is previous
    assert client.get("/api/report").json()["scan_id"] == "prior-scan"


async def test_target_auth_header_reaches_target_and_is_validated(monkeypatch) -> None:
    captured: dict[str, object] = {}

    async def run(target, modes):
        captured["target"] = target
        return make_report(scan_id="next-scan")

    monkeypatch.setattr("agentscan.core.runner.run_scan_multi", run)
    response = await api_start_scan(
        {
            "target_url": ENDPOINT,
            "auth_header": "Authorization: Bearer synthetic-loopback-token",
        }
    )
    assert response.status_code == 200
    await state.active_scan
    target = captured["target"]
    assert getattr(target, "auth_header", None) == "Authorization: Bearer synthetic-loopback-token"

    rejected = await api_start_scan(
        {"target_url": ENDPOINT, "auth_header": "Authorization: Bearer bad\nInjected: x"}
    )
    assert rejected.status_code == 400
    assert "auth_header" in json.loads(rejected.body)["field_errors"]


def test_scan_modal_exposes_target_auth_header_input() -> None:
    html = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    assert 'id="scan-auth-header"' in html
    assert "Target authentication header" in html


def test_form_validation_inventory_covers_target_auth_header() -> None:
    run_node(
        r"""
    const assert = require("node:assert/strict");
    const forms = require("./agentscan/ui/static/form-validation.js");
    const spec = forms.inventory().find(
      item => item.workflow === "scan" && item.field === "auth_header",
    );
    assert.ok(spec, "scan auth_header inventory entry");
    assert.ok(!forms.checkField(spec, "Authorization: Bearer synthetic-loopback-token").error);
    assert.ok(!forms.checkField(spec, "").error);
    assert.ok(forms.checkField(spec, "Authorization: Bearer bad\nInjected: x").error);
    assert.ok(forms.checkField(spec, "Bad Header: value").error);
    assert.ok(forms.checkField(spec, "Authorization:").error);
    """
    )


def test_findings_are_sorted_critical_first_with_stable_ties() -> None:
    run_node(
        r"""
    const assert = require("node:assert/strict");
    const dashboard = require("./agentscan/ui/static/dashboard.js");
    const findings = [
      {severity: "LOW", attack_id: "LOW-1"},
      {severity: "CRITICAL", attack_id: "CRIT-1"},
      {severity: "HIGH", attack_id: "HIGH-1"},
      {severity: "INFO", attack_id: "INFO-1"},
      {severity: "MEDIUM", attack_id: "MED-1"},
      {severity: "PASS", attack_id: "PASS-1"},
      {severity: "UNCLASSIFIED", attack_id: "UNK-1"},
      {severity: "CRITICAL", attack_id: "CRIT-2"},
    ];
    const ordered = dashboard.sortFindings(findings).map(item => item.attack_id);
    assert.deepEqual(ordered, [
      "CRIT-1", "CRIT-2", "HIGH-1", "MED-1", "LOW-1", "INFO-1", "PASS-1", "UNK-1",
    ]);
    assert.deepEqual(findings.map(item => item.attack_id), [
      "LOW-1", "CRIT-1", "HIGH-1", "INFO-1", "MED-1", "PASS-1", "UNK-1", "CRIT-2",
    ]);
    """
    )


def test_scan_status_view_and_progress_are_rehydratable() -> None:
    run_node(
        r"""
    const assert = require("node:assert/strict");
    const dashboard = require("./agentscan/ui/static/dashboard.js");
    const running = dashboard.scanStatusView("running");
    assert.equal(running.active, true);
    assert.equal(running.terminal, false);
    assert.equal(running.label, "RUNNING");
    const completed = dashboard.scanStatusView("completed");
    assert.equal(completed.active, false);
    assert.equal(completed.terminal, true);
    assert.equal(completed.tone, "complete");
    const future = dashboard.scanStatusView("queued");
    assert.equal(future.terminal, false);
    assert.equal(future.active, true);
    assert.equal(dashboard.scanProgressPercent({status: "running", tests_run: 2, tests_selected: 4}), 50);
    assert.equal(dashboard.scanProgressPercent({status: "completed", progress: 0}), 100);
    assert.equal(dashboard.scanProgressPercent({status: "running", progress: 120}), 100);
    assert.equal(dashboard.scanProgressPercent({status: "running", progress: -5}), 0);
    """
    )


def test_findings_views_use_critical_first_order() -> None:
    dashboard = (STATIC_DIR / "dashboard.js").read_text(encoding="utf-8")
    core = (STATIC_DIR / "dashboard-app-core.js").read_text(encoding="utf-8")
    renderers = (STATIC_DIR / "dashboard-app-renderers.js").read_text(encoding="utf-8")
    assert "sortFindings(findings).slice(0, 4)" in dashboard
    assert "DashboardSemantics.sortFindings(rawFindings.map(" in core
    assert "DashboardSemantics.sortFindings(findings).filter(" in renderers


def test_dashboard_boot_rehydrates_scan_state_and_keeps_prior_report() -> None:
    actions = (STATIC_DIR / "dashboard-app-actions.js").read_text(encoding="utf-8")
    assert "async function rehydrateScanState" in actions
    boot = actions[actions.index("window.addEventListener('DOMContentLoaded'") :]
    assert "rehydrateScanState()" in boot
    start_event = actions[
        actions.index("es.addEventListener('scan:start'") : actions.index(
            "es.addEventListener('scan:progress'"
        )
    ]
    assert "globalTelemetry.report = null" not in start_event
    assert "globalTelemetry.findings = []" not in start_event
