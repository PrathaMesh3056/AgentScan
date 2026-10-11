"""Prevent dashboard addresses being mistaken for agent targets, without network IO."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

from agentscan.core.models import ScanMode, ScanReport
from agentscan.ui.app import create_app
from agentscan.ui.security import dashboard_target_error
from agentscan.ui.state import state


@pytest.fixture
def dashboard_client(tmp_path, monkeypatch):
    monkeypatch.delenv("AGENTSCAN_UI_TOKEN", raising=False)
    monkeypatch.setattr(state, "active_scan", None)
    monkeypatch.setattr(state, "sentinel_task", None)
    monkeypatch.setattr(state, "scan_status", {"status": "idle"})
    monkeypatch.setattr(state, "report", None)
    with TestClient(create_app(project_root=tmp_path), base_url="http://127.0.0.1:8765") as client:
        assert client.get("/").status_code == 200
        yield client


@pytest.mark.parametrize(
    "endpoint",
    [
        "/api/scan",
        "/api/discovery",
        "/api/swarms/run",
        "/api/sentinel/probe",
        "/api/sentinel/start",
    ],
)
@pytest.mark.parametrize(
    "target",
    [
        "127.0.0.1:8765/chat",
        "http://localhost:8765/chat",
        "http://[::1]:8765/chat",
        "http://LOCALHOST.:8765/chat",
    ],
)
def test_self_target_fails_before_execution(dashboard_client, monkeypatch, endpoint, target):
    run = AsyncMock()
    monkeypatch.setattr("agentscan.core.runner.run_scan_multi", run)
    monkeypatch.setattr("agentscan.core.discovery.discover_http", run)
    monkeypatch.setattr("agentscan.swarm.coordinator.SwarmCoordinator.run_swarm", run)
    monkeypatch.setattr("agentscan.sentinel.watcher.ContinuousWatcher.run_iteration", run)
    monkeypatch.setattr("agentscan.sentinel.watcher.ContinuousWatcher.run_loop", run)
    response = dashboard_client.post(endpoint, json={"target_url": target})
    assert response.status_code == 400
    assert "dashboard, not an agent endpoint" in response.json()["error"]
    run.assert_not_called()
    assert state.active_scan is None
    assert state.sentinel_task is None


@pytest.mark.parametrize("name", ["scan", "agentscan_scan", "swarm", "agentscan_swarm"])
def test_dashboard_mcp_cannot_send_scan_to_itself(dashboard_client, monkeypatch, name):
    run = AsyncMock()
    monkeypatch.setattr("agentscan.core.runner.run_scan_multi", run)
    response = dashboard_client.post(
        "/api/mcp/invoke",
        json={"name": name, "arguments": {"target_url": "http://localhost:8765/chat"}},
    )
    assert response.status_code == 400
    assert "dashboard" in response.json()["error"]
    run.assert_not_called()


@pytest.mark.parametrize(
    "endpoint",
    [
        "/api/scan",
        "/api/discovery",
        "/api/swarms/run",
        "/api/sentinel/probe",
        "/api/sentinel/start",
    ],
)
@pytest.mark.parametrize("target", [None, "", "   "])
def test_no_target_means_no_default_dashboard_scan(dashboard_client, endpoint, target):
    response = dashboard_client.post(endpoint, json={"target_url": target})
    assert response.status_code == 400
    assert state.active_scan is None
    assert state.sentinel_task is None


@pytest.mark.parametrize(
    "target",
    ["http://127.0.0.1:8000/chat", "http://localhost:8766/chat", "mcp+sses://agent.example/mcp"],
)
def test_other_agent_port_preserves_body_and_startup(dashboard_client, monkeypatch, target):
    report = ScanReport(target_url=target, scan_mode=ScanMode.SCAN)
    run = AsyncMock(return_value=report)
    monkeypatch.setattr("agentscan.core.runner.run_scan_multi", run)
    response = dashboard_client.post(
        "/api/scan", json={"target_url": target, "analysis_mode": "deterministic", "concurrency": 2}
    )
    assert response.status_code == 200
    assert response.json()["target"] == target
    assert state.scan_status["target"] == target


@pytest.mark.parametrize(
    ("target", "dashboard", "rejected"),
    [
        ("https://localhost/chat", "https://127.0.0.1/", True),
        ("http://localhost/chat", "http://127.0.0.1/", True),
        ("https://owned.example/chat", "https://owned.example/", True),
        ("https://agent.example/chat", "https://dashboard.example/", False),
        ("ws://localhost:8000/chat", "http://127.0.0.1:8765/", False),
        ("mcp+sse://localhost:8000/mcp", "http://127.0.0.1:8765/", False),
        ("mcp+sses://localhost/mcp", "https://127.0.0.1/", True),
        ("mcp+sses://agent.example/mcp", "https://dashboard.example/", False),
        ("http://localhost:invalid/chat", "http://127.0.0.1:8765/", True),
    ],
)
def test_origin_comparison_uses_effective_port(target, dashboard, rejected):
    assert bool(dashboard_target_error(target, dashboard)) is rejected


def test_invalid_json_retains_route_validation(dashboard_client):
    response = dashboard_client.post(
        "/api/scan", content=b"{broken", headers={"Content-Type": "application/json"}
    )
    assert response.status_code == 422
    assert "JSON" in response.json()["field_errors"]["body"]


def test_wrong_body_shape_explains_json_object_without_echo(dashboard_client):
    marker = "synthetic-secret-that-must-not-be-reflected"
    response = dashboard_client.post("/api/scan", json=[marker])
    assert response.status_code == 422
    assert "JSON object" in response.json()["field_errors"]["body"]
    assert marker not in response.text


def test_unknown_dashboard_endpoint_has_readable_error(dashboard_client):
    response = dashboard_client.get("/api/nonexistent-fixture")
    assert response.status_code == 404
    assert response.json()["error"] == "Not Found"


async def test_attack_catalog_cache_retains_setup_failures_and_redacts_tokens(monkeypatch):
    from agentscan.attacks.registry import registry
    from agentscan.ui.routers import reports

    modules = [{"attack_id": "fixture", "modes": ["SCAN"]}]
    monkeypatch.setattr(reports, "_cached_attacks", modules)
    token = "synthetic-authentication-token-12345"
    monkeypatch.setattr(
        registry,
        "load_errors",
        [{"module_id": "fixture.deep", "mode": "deep", "error": f"Authorization: Bearer {token}"}],
    )
    data = json.loads((await reports.api_attacks()).body)
    assert data["count"] == 1
    assert data["attacks"] == modules
    assert data["load_errors_count"] == 1
    assert len(data["load_errors"]) == 1
    assert token not in data["load_errors"][0]["error"]
    assert "REDACTED" in data["load_errors"][0]["error"]


def test_unexpected_error_has_reference_without_secret_details(tmp_path, monkeypatch):
    from loguru import logger

    monkeypatch.delenv("AGENTSCAN_UI_TOKEN", raising=False)
    app = create_app(project_root=tmp_path)
    marker = "synthetic-private-exception-message"

    @app.get("/api/failure-fixture")
    async def failure_fixture():
        raise RuntimeError(marker)

    diagnostics = []
    sink = logger.add(diagnostics.append, format="{message}")
    try:
        with TestClient(app, raise_server_exceptions=False) as client:
            response = client.get("/api/failure-fixture")
        assert response.status_code == 500
        assert len(response.json()["error_id"]) == 12
        assert marker not in response.text
        assert marker not in "".join(diagnostics)
        assert response.json()["error_id"] in "".join(diagnostics)
        assert "RuntimeError" in "".join(diagnostics)
    finally:
        logger.remove(sink)


@pytest.mark.parametrize("site", ["cross-site", "same-site"])
@pytest.mark.parametrize("page", ["/", "/overview", "/findings"])
def test_link_navigation_can_open_dashboard(tmp_path, monkeypatch, site, page):
    monkeypatch.delenv("AGENTSCAN_UI_TOKEN", raising=False)
    with TestClient(create_app(project_root=tmp_path)) as client:
        response = client.get(
            page,
            headers={
                "Sec-Fetch-Site": site,
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Dest": "document",
            },
        )
        assert response.status_code == 200
        assert "HttpOnly" in response.headers["set-cookie"]
        assert response.headers["X-Frame-Options"] == "DENY"
        assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
        assert client.get("/api/features").status_code == 200


@pytest.mark.parametrize("site", ["cross-site", "same-site"])
@pytest.mark.parametrize(
    "method,path,mode,dest",
    [
        ("GET", "/api/features", "navigate", "document"),
        ("GET", "/api/report/download", "navigate", "document"),
        ("GET", "/", "cors", "empty"),
        ("GET", "/", "navigate", "iframe"),
        ("POST", "/api/scan/cancel", "navigate", "document"),
    ],
)
def test_link_exception_does_not_allow_cross_origin_api_or_embedding(
    dashboard_client,
    site,
    method,
    path,
    mode,
    dest,
):
    response = dashboard_client.request(
        method,
        path,
        headers={
            "Sec-Fetch-Site": site,
            "Sec-Fetch-Mode": mode,
            "Sec-Fetch-Dest": dest,
        },
    )
    assert response.status_code == 403


def test_link_navigation_preserves_token_authentication(tmp_path):
    headers = {
        "Sec-Fetch-Site": "cross-site",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Dest": "document",
    }
    with TestClient(create_app(project_root=tmp_path, token="synthetic-link-token")) as client:
        assert client.get("/", headers=headers).status_code == 401
        response = client.get("/?token=synthetic-link-token", headers=headers)
        assert response.status_code == 200
        assert "token=" not in str(response.url)
        assert client.get("/api/features").status_code == 200
