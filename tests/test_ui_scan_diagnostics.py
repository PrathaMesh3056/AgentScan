"""Background scan and discovery failures must explain themselves without echoing secrets."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock

import httpx
import pytest

from agentscan.core.models import BrowserConfig, ScanMode, ScanReport
from agentscan.core.outcomes import TargetRequestError
from agentscan.ui.routers.scan import api_discovery, api_start_scan
from agentscan.ui.state import event_bus, state


@pytest.fixture(autouse=True)
def isolated_state(monkeypatch):
    monkeypatch.setattr(state, "active_scan", None)
    monkeypatch.setattr(state, "report", None)
    monkeypatch.setattr(state, "scan_status", {"status": "idle"})
    monkeypatch.setattr(state, "scan_recorder", None)


async def test_background_failure_has_safe_status_sse_and_correlated_reference(monkeypatch):
    secret = "synthetic-private-token-in-exception"
    failure = RuntimeError(f"Authorization: Bearer {secret}; https://private.example/{secret}")
    monkeypatch.setattr("agentscan.core.runner.run_scan_multi", AsyncMock(side_effect=failure))
    events = AsyncMock()
    logs = []
    monkeypatch.setattr(event_bus, "publish", events)
    monkeypatch.setattr("agentscan.ui.routers.scan.logger.error", lambda *args: logs.append(args))
    response = await api_start_scan({"target_url": "http://owned.example/chat"})
    scan_id = json.loads(response.body)["scan_id"]
    await state.active_scan
    status = state.scan_status
    assert status["status"] == "failed"
    assert status["score"] is None
    assert status["error_code"] == "UNEXPECTED_FAILURE"
    assert len(status["error_id"]) == 12
    event = events.call_args.args[0]
    assert event["type"] == "scan:error"
    assert event["data"]["scan_id"] == scan_id
    assert event["data"]["error_id"] == status["error_id"]
    assert logs[0][-1] == "RuntimeError"
    assert logs[0][-2] == status["error_id"]
    assert secret not in json.dumps({"status": status, "event": event, "logs": logs})
    assert state.report is None


@pytest.mark.parametrize("adapter,expected", [("none", None), ("document_v1", "document_v1")])
async def test_dashboard_document_adapter_selection_reaches_target(monkeypatch, adapter, expected):
    report = ScanReport(target_url="http://owned.example/chat", scan_mode=ScanMode.SCAN)
    report.complete(None, status="INCONCLUSIVE")
    work = AsyncMock(return_value=report)
    monkeypatch.setattr("agentscan.core.runner.run_scan_multi", work)
    response = await api_start_scan({"target_url": report.target_url, "indirect_adapter": adapter})
    assert response.status_code == 200
    task = state.active_scan
    assert task is not None
    await task
    assert work.await_args.args[0].indirect_adapter == expected


@pytest.mark.parametrize(
    ("failure", "code", "guidance"),
    [
        (
            TargetRequestError("Target returned HTTP 401"),
            "HTTP_401",
            "target authentication header",
        ),
        (httpx.ConnectError("secret connection URL"), "CONNECTION_FAILED", "service availability"),
        (httpx.ReadTimeout("private prompt secret"), "REQUEST_TIMEOUT", "timed out"),
    ],
)
async def test_known_background_failure_has_actionable_safe_guidance(
    monkeypatch, failure, code, guidance
):
    monkeypatch.setattr("agentscan.core.runner.run_scan_multi", AsyncMock(side_effect=failure))
    monkeypatch.setattr(event_bus, "publish", AsyncMock())
    await api_start_scan({"target_url": "http://owned.example/chat"})
    await state.active_scan
    assert state.scan_status["error_code"] == code
    assert guidance in state.scan_status["error"]
    assert "secret" not in state.scan_status["error"]


async def test_discovery_failure_explains_both_attempts_without_secrets(monkeypatch):
    secret = "synthetic-discovery-secret"
    monkeypatch.setattr(
        "agentscan.core.discovery.discover_http", AsyncMock(side_effect=RuntimeError(secret))
    )
    monkeypatch.setattr(
        "agentscan.core.discovery.discover_widget", AsyncMock(side_effect=RuntimeError(secret))
    )
    logs = []
    monkeypatch.setattr("agentscan.ui.routers.scan.logger.error", lambda *args: logs.append(args))
    response = await api_discovery({"url": "https://owned.example/chat"})
    body = json.loads(response.body)
    assert body["success"] is False
    assert body["profile"] is None
    assert body["yaml"] == ""
    assert body["endpoints"] == body["routes"] == []
    assert body["error_code"] == "DISCOVERY_NOT_DETECTED"
    assert {attempt["transport"] for attempt in body["attempts"]} == {"http", "browser"}
    assert all(attempt["status"] == "failed" for attempt in body["attempts"])
    assert body["errors"] == body["attempts"]
    assert body["error_id"] == body["attempts"][0]["error_id"]
    assert logs[0][-2] == body["error_id"]
    assert secret not in response.body.decode()
    assert secret not in repr(logs)


async def test_not_detected_discovery_does_not_claim_a_specific_http_failure(monkeypatch):
    monkeypatch.setattr("agentscan.core.discovery.discover_http", AsyncMock(return_value=None))
    browser = AsyncMock()
    monkeypatch.setattr("agentscan.core.discovery.discover_widget", browser)
    response = await api_discovery({"url": "https://owned.example/chat", "mode": "http"})
    body = json.loads(response.body)
    assert body["success"] is False
    assert len(body["attempts"]) == 1
    assert body["attempts"][0]["code"] == "HTTP_NOT_DETECTED"
    assert "cannot confirm the exact rejection reason" in body["attempts"][0]["message"]
    assert "HTTP 401" not in response.body.decode()
    browser.assert_not_called()


async def test_successful_browser_fallback_preserves_failed_http_attempt(monkeypatch):
    monkeypatch.setattr("agentscan.core.discovery.discover_http", AsyncMock(return_value=None))
    monkeypatch.setattr(
        "agentscan.core.discovery.discover_widget",
        AsyncMock(
            return_value=BrowserConfig(
                url="https://owned.example/chat",
                input_selector="#input",
                response_selector=".reply",
            )
        ),
    )
    response = await api_discovery({"url": "https://owned.example/chat"})
    body = json.loads(response.body)
    assert body["success"] is True
    assert [attempt["status"] for attempt in body["attempts"]] == ["failed", "success"]
    assert body["attempts"][1]["code"] == "BROWSER_DETECTED"
    assert len(body["errors"]) == 1
    assert "error" not in body


async def test_discovery_http_status_guidance_does_not_echo_url_or_body(monkeypatch):
    request = httpx.Request("POST", "https://private.example/key-secret")
    failure = httpx.HTTPStatusError(
        "raw-body-secret", request=request, response=httpx.Response(401, request=request)
    )
    monkeypatch.setattr("agentscan.core.discovery.discover_http", AsyncMock(side_effect=failure))
    response = await api_discovery({"url": "https://owned.example/chat", "mode": "http"})
    body = json.loads(response.body)
    assert body["attempts"][0]["code"] == "HTTP_401"
    assert "HTTP 401" in body["attempts"][0]["message"]
    assert "private.example" not in response.body.decode()
    assert "raw-body-secret" not in response.body.decode()


async def test_browser_missing_package_has_setup_guidance_without_exception_echo(monkeypatch):
    failure = ModuleNotFoundError("private-import-detail", name="playwright")
    monkeypatch.setattr("agentscan.core.discovery.discover_widget", AsyncMock(side_effect=failure))
    response = await api_discovery({"url": "https://owned.example/chat", "mode": "browser"})
    body = json.loads(response.body)
    assert body["attempts"][0]["code"] == "COMPONENT_UNAVAILABLE"
    assert "--extra browser" in body["attempts"][0]["message"]
    assert "--extra ui" in body["attempts"][0]["message"]
    assert "private-import-detail" not in response.body.decode()
