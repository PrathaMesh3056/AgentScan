# tests/test_qa038_reliability.py
#
# Regressions for QA-038 (#38): bounded reliability and error handling.
# Each test pins one failure class: dashboard bind failures, wrong-typed profiles,
# missing Playwright, target HTTP/connection failures, and the cancel race.

from __future__ import annotations

import asyncio
import json
import socket
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from typer.testing import CliRunner

from agentscan.cli import app
from agentscan.core.models import ScanMode, ScanReport
from agentscan.ui import app as ui_app_module

runner = CliRunner()


@pytest.fixture(autouse=True)
def isolated_ui_state(monkeypatch) -> None:
    from agentscan.ui.state import state

    monkeypatch.setattr(state, "active_scan", None)
    monkeypatch.setattr(state, "scan_status", {"status": "idle"})
    monkeypatch.setattr(state, "report", None)


def _incomplete_report(*errors: str) -> ScanReport:
    report = ScanReport(target_url="http://127.0.0.1:9/chat", scan_mode=ScanMode.SCAN)
    report.module_errors = [
        {"module_id": "ATK-001", "module_name": "Direct Prompt Injection", "error": error}
        for error in errors
    ]
    report.complete(None, status="ERROR")
    return report


def _panel_text(output: str) -> str:
    """Join Rich panel text across wrapped lines so phrases stay assertable."""
    return " ".join(output.replace("\u2502", " ").split())


def _ui_client():
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from agentscan.ui.app import create_app

    client = TestClient(create_app())
    client.get("/")
    return client


# ── Dashboard bind failures ───────────────────────────────────────────────────


def test_occupied_dashboard_port_is_bounded_and_never_announced() -> None:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        result = runner.invoke(app, ["ui", "--port", str(port)])

    assert result.exit_code == 1
    assert "AgentScan UI:" not in result.output
    assert "already in use" in result.output
    assert "Traceback" not in result.output


def test_out_of_range_dashboard_port_is_bounded() -> None:
    result = runner.invoke(app, ["ui", "--port", "99999"])

    assert result.exit_code == 1
    assert "0-65535" in result.output
    assert "AgentScan UI:" not in result.output
    assert "Traceback" not in result.output


def test_serve_app_announces_the_actual_bound_port(monkeypatch) -> None:
    seen: dict[str, object] = {}

    def fake_run(self, sockets=None) -> None:
        seen["address"] = sockets[0].getsockname()[:2]

    monkeypatch.setattr("uvicorn.Server.run", fake_run)
    announced: list[tuple[str, int]] = []

    ui_app_module.serve_app(
        lambda scope, receive, send: None,
        host="127.0.0.1",
        port=0,
        on_bound=lambda host, port: announced.append((host, port)),
    )

    assert announced and announced[0][0] == "127.0.0.1"
    assert announced[0][1] == seen["address"][1] > 0


def test_bind_failure_never_announces_a_url(monkeypatch) -> None:
    announced: list[tuple[str, int]] = []

    def failing_bind(host: str, port: int) -> None:
        raise RuntimeError(
            f"Cannot start the dashboard on {host}:{port}: the port is already in use."
        )

    monkeypatch.setattr(ui_app_module, "bind_socket", failing_bind)
    with pytest.raises(RuntimeError, match="already in use"):
        ui_app_module.serve_app(
            lambda scope, receive, send: None,
            on_bound=lambda host, port: announced.append((host, port)),
        )
    assert announced == []


# ── Wrong-typed profiles ─────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ('url: http://127.0.0.1:9/chat\nbrowser: "yes"\n', "browser"),
        ("url: http://127.0.0.1:9/chat\nattacker_turns: many\n", "attacker_turns"),
        ("url: http://127.0.0.1:9/chat\nrequest_template: 5\n", "request_template"),
        ("url: http://127.0.0.1:9/chat\nframework: [a, b]\n", "framework"),
        ("url: http://127.0.0.1:9/chat\noutput: 123\n", "output"),
        ('url: http://127.0.0.1:9/chat\nexploit: "yes"\n', "exploit"),
        ("url: [a]\n", "url"),
        (
            "url: http://127.0.0.1:9/chat\nbrowser:\n  url: http://127.0.0.1:9/\n  input_selector: 5\n",
            "browser",
        ),
        ("url: http://127.0.0.1:9/chat\nrequest_template:\n  method: [POST]\n", "request_template"),
    ],
)
def test_wrong_typed_profile_value_is_bounded(tmp_path: Path, body: str, expected: str) -> None:
    profile = tmp_path / "profile.yaml"
    profile.write_text(body, encoding="utf-8")

    result = runner.invoke(app, ["scan", "--config", str(profile)])

    assert result.exit_code == 2
    assert expected in result.output
    assert "Traceback" not in result.output


def test_invalid_framework_value_is_bounded(tmp_path: Path) -> None:
    profile = tmp_path / "profile.yaml"
    profile.write_text(
        "url: http://127.0.0.1:9/chat\nframework: not-a-framework\n", encoding="utf-8"
    )

    result = runner.invoke(app, ["scan", "--config", str(profile)])

    assert result.exit_code == 2
    assert "framework must be one of" in result.output
    assert "Traceback" not in result.output


def test_valid_profile_still_scans(tmp_path: Path) -> None:
    profile = tmp_path / "profile.yaml"
    profile.write_text(
        'url: http://127.0.0.1:9/chat\nattacker_turns: "4"\nexploit: false\n',
        encoding="utf-8",
    )
    report = ScanReport(target_url="http://127.0.0.1:9/chat", scan_mode=ScanMode.SCAN)
    report.complete(100)

    with patch("agentscan.cli.run_scan_multi", new_callable=AsyncMock, return_value=report):
        result = runner.invoke(app, ["scan", "--config", str(profile)])

    assert result.exit_code == 0, result.output


# ── Missing Playwright ───────────────────────────────────────────────────────


def test_browser_scan_without_playwright_is_bounded(monkeypatch) -> None:
    monkeypatch.setattr("agentscan._cli._preflight.playwright_available", lambda: False)

    result = runner.invoke(
        app,
        [
            "scan",
            "--browser-url",
            "http://127.0.0.1:9/chat",
            "--input-selector",
            "#chat-input",
            "--response-selector",
            "#chat-response",
        ],
    )

    assert result.exit_code == 2
    assert "playwright install chromium" in _panel_text(result.output)
    assert "Traceback" not in result.output


def test_init_browser_without_playwright_is_bounded(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("agentscan._cli._preflight.playwright_available", lambda: False)
    output = tmp_path / "target.yaml"

    result = runner.invoke(
        app,
        ["init", "http://127.0.0.1:9/chat", "--browser", "--output", str(output)],
    )

    assert result.exit_code == 2
    assert "playwright install chromium" in _panel_text(result.output)
    assert not output.exists()


# ── Target HTTP and connection failures ──────────────────────────────────────


def test_target_500_guidance_is_bounded_and_keeps_exit_3() -> None:
    report = _incomplete_report(
        "Target returned HTTP 500",
        "Target returned HTTP 500",
        "Target returned HTTP 500",
    )

    with patch("agentscan.cli.run_scan_multi", new_callable=AsyncMock, return_value=report):
        result = runner.invoke(app, ["scan", "http://127.0.0.1:9/chat"])

    assert result.exit_code == 3
    assert "Target-side failure" in result.output
    assert "HTTP 500" in result.output
    assert "Assessment is incomplete" in result.output


def test_target_connection_guidance_is_bounded() -> None:
    report = _incomplete_report("Connection failed before a valid target response")

    with patch("agentscan.cli.run_scan_multi", new_callable=AsyncMock, return_value=report):
        result = runner.invoke(app, ["scan", "http://127.0.0.1:9/chat"])

    assert result.exit_code == 3
    assert "could not be reached" in result.output


def test_missing_playwright_failure_prints_install_guidance() -> None:
    report = _incomplete_report("No module named 'playwright'")

    with patch("agentscan.cli.run_scan_multi", new_callable=AsyncMock, return_value=report):
        result = runner.invoke(app, ["scan", "http://127.0.0.1:9/chat"])

    assert result.exit_code == 3
    assert "playwright install chromium" in result.output


def test_completed_scan_does_not_print_failure_guidance() -> None:
    report = _incomplete_report("Target returned HTTP 500")
    report.complete(90)

    with patch("agentscan.cli.run_scan_multi", new_callable=AsyncMock, return_value=report):
        result = runner.invoke(app, ["scan", "http://127.0.0.1:9/chat"])

    assert result.exit_code == 0
    assert "Target-side failure" not in result.output


# ── Cancel races ─────────────────────────────────────────────────────────────


def test_cancel_after_completion_keeps_terminal_status() -> None:
    from agentscan.ui.state import state

    client = _ui_client()
    state.scan_status = {"status": "completed", "score": 91, "progress": 100}

    response = client.post("/api/scan/cancel")

    assert response.status_code == 200
    assert response.json() == {"status": "completed", "cancelled": False}
    assert state.scan_status["status"] == "completed"


def test_cancel_when_idle_reports_idle() -> None:
    from agentscan.ui.state import state

    client = _ui_client()
    state.scan_status = {"status": "idle"}

    response = client.post("/api/scan/cancel")

    assert response.status_code == 200
    assert response.json() == {"status": "idle", "cancelled": False}
    assert state.scan_status["status"] == "idle"


async def test_cancel_running_scan_still_cancels_and_publishes() -> None:
    from agentscan.ui.routers.scan import api_scan_cancel
    from agentscan.ui.state import event_bus, state

    started = asyncio.Event()

    async def wait_for_cancel(*_args, **_kwargs) -> None:
        started.set()
        await asyncio.Future()

    task = asyncio.create_task(wait_for_cancel())
    await started.wait()
    state.active_scan = task
    state.scan_status = {"status": "running", "progress": 10}
    publish = AsyncMock()
    with patch.object(event_bus, "publish", publish):
        response = await api_scan_cancel()

    assert json.loads(response.body) == {"status": "cancelled", "cancelled": True}
    assert state.scan_status["status"] == "cancelled"
    publish.assert_awaited_once()
    with pytest.raises(asyncio.CancelledError):
        await task


async def test_cancel_with_finished_task_keeps_terminal_status() -> None:
    from agentscan.ui.routers.scan import api_scan_cancel
    from agentscan.ui.state import state

    async def finish() -> None:
        return None

    task = asyncio.create_task(finish())
    await task
    state.active_scan = task
    state.scan_status = {"status": "failed", "error_code": "TARGET_ERROR"}

    response = await api_scan_cancel()

    assert json.loads(response.body) == {"status": "failed", "cancelled": False}
    assert state.scan_status["status"] == "failed"
