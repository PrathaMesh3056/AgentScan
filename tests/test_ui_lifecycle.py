"""Dashboard execution and filesystem boundary regressions."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

from agentscan.core.context import active_context, begin_scan_context
from agentscan.core.models import ScanMode, ScanReport
from agentscan.core.trace import recorder
from agentscan.ui.app import create_app
from agentscan.ui.routers.scan import api_scan_cancel, api_start_scan
from agentscan.ui.state import event_bus, state


@pytest.fixture(autouse=True)
def isolated_ui_state(monkeypatch):
    monkeypatch.setattr(state, "active_scan", None)
    monkeypatch.setattr(state, "scan_recorder", None)
    monkeypatch.setattr(state, "report", None)
    monkeypatch.setattr(state, "scan_status", {"status": "idle"})
    token = active_context.set(None)
    yield
    active_context.reset(token)


@pytest.mark.parametrize(
    ("report_status", "ui_status", "event_type"),
    [
        ("COMPLETE", "completed", "scan:complete"),
        ("INCONCLUSIVE", "inconclusive", "scan:inconclusive"),
        ("ERROR", "failed", "scan:error"),
    ],
)
async def test_scan_terminal_status_preserves_coverage_and_task_trace(
    monkeypatch, report_status: str, ui_status: str, event_type: str
) -> None:
    report = ScanReport(
        target_url="http://owned.example/chat",
        scan_mode=ScanMode.SCAN,
        tests_selected=4,
        tests_run=1,
        module_errors=[{"module_id": "ATK-001", "error": "synthetic dependency failure"}],
        module_outcomes=[{"module_id": "ATK-001", "status": "ERROR"}],
    )
    report.complete(None, status=report_status)
    task_recorder = None

    async def run(*args):
        nonlocal task_recorder
        context = begin_scan_context()
        context.recorder.enabled = True
        task_recorder = context.recorder
        return report

    monkeypatch.setattr("agentscan.core.runner.run_scan_multi", run)
    events = AsyncMock()
    monkeypatch.setattr(event_bus, "publish", events)
    response = await api_start_scan({"target_url": "http://owned.example/chat"})
    request_id = json.loads(response.body)["scan_id"]
    await state.active_scan
    assert state.scan_status["status"] == ui_status
    assert state.scan_status["scan_id"] == request_id == state.report.scan_id
    assert state.scan_status["tests_run"] == 1
    assert state.scan_status["tests_selected"] == 4
    assert state.scan_status["module_outcomes"] == report.module_outcomes
    assert state.scan_status["module_errors"] == report.module_errors
    terminal = events.call_args.args[0]
    assert terminal["type"] == event_type
    assert terminal["data"]["module_outcomes"] == report.module_outcomes
    assert state.scan_recorder is task_recorder
    assert recorder._get() is not task_recorder


async def test_overlapping_dashboard_scan_rejected_and_cancellation_sticks(monkeypatch) -> None:
    started = asyncio.Event()

    async def wait_for_cancel(*args):
        started.set()
        await asyncio.Future()

    monkeypatch.setattr("agentscan.core.runner.run_scan_multi", wait_for_cancel)
    old_report = ScanReport(target_url="http://prior.example", scan_mode=ScanMode.SCAN)
    state.report = old_report
    response = await api_start_scan({"target_url": "http://owned.example"})
    assert response.status_code == 200
    assert state.report is None
    await started.wait()
    duplicate = await api_start_scan({"target_url": "http://other.example"})
    assert duplicate.status_code == 409
    task = state.active_scan
    await api_scan_cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert state.scan_status["status"] == "cancelled"
    assert state.report is None


@pytest.mark.parametrize(
    "target", [None, ["http://owned.example"], "mcp://untrusted", "mcp+stdio://untrusted"]
)
async def test_dashboard_scan_rejects_invalid_and_command_targets(target) -> None:
    assert (await api_start_scan({"target_url": target})).status_code == 400
    assert state.active_scan is None


def test_all_dashboard_filesystem_endpoints_reject_sibling_root(tmp_path: Path) -> None:
    project = tmp_path / "project"
    sibling = tmp_path / "project-other"
    project.mkdir()
    sibling.mkdir()
    client = TestClient(create_app(project_root=project))
    client.get("/")
    for endpoint in (
        "/api/identity",
        "/api/rbac",
        "/api/aibom",
        "/api/aibom/download",
        "/api/dependencies/graph",
    ):
        assert client.get(endpoint, params={"path": str(sibling)}).status_code == 403
    assert client.post("/api/audit", json={"path": str(sibling)}).status_code == 403
    assert client.post("/api/audit", json={"path": {"untrusted": "type"}}).status_code == 400
    assert (
        client.post(
            "/api/mcp/invoke", json={"name": "audit", "arguments": {"path": str(sibling)}}
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/api/mcp/invoke",
            json={"name": "scan", "arguments": {"target_url": "mcp+stdio://untrusted"}},
        ).status_code
        == 400
    )


def test_certificate_configuration_errors_are_explicit(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("AGENTSCAN_HMAC_KEY", raising=False)
    client = TestClient(create_app(project_root=tmp_path))
    client.get("/")
    state.report = ScanReport(target_url="http://owned.example", scan_mode=ScanMode.SCAN)
    assert client.get("/api/certificate").status_code == 503
    assert client.post("/api/certificate", json={}).status_code == 503
    assert client.post("/api/certificate", json={"secret_key": "too-short"}).status_code == 400
    assert (
        client.post("/api/certificate", json={"secret_key": {"invalid": "type"}}).status_code == 400
    )
    key = "independent-ui-certificate-test-key-32-bytes"
    response = client.post("/api/certificate", json={"secret_key": key})
    assert response.status_code == 200
    result = client.post(
        "/api/verify-certificate", json={"certificate": response.json(), "secret_key": key}
    )
    assert result.status_code == 200 and result.json()["valid"] is True


def test_dashboard_static_audit_without_selected_checks_is_rejected(tmp_path: Path) -> None:
    client = TestClient(create_app(project_root=tmp_path))
    client.get("/")
    flags = {
        "scan_" + name: False
        for name in (
            "deps",
            "config",
            "secrets",
            "typo",
            "mcp",
            "identity",
            "frameworks",
            "semgrep",
        )
    }
    previous_report = state.audit_report
    response = client.post("/api/audit", json={"path": ".", **flags})
    assert response.status_code == 400
    result = response.json()
    assert "Select at least one" in result["field_errors"]["ruleset"]
    assert "score" not in result
    assert state.audit_report is previous_report
