"""Runtime gateway status surface must stay honest and loopback-only."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from agentscan.ui.routers import gateway
from agentscan.ui.routers import gateway as gateway_module


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    monkeypatch.delenv("AGENTSCAN_GATEWAY_URL", raising=False)
    from agentscan.ui.app import create_app
    from agentscan.ui.state import state

    previous_report, previous_path = state.report, state.report_path
    app = create_app(project_root=tmp_path)
    with TestClient(app) as instance:
        yield instance
    state.report, state.report_path = previous_report, previous_path


async def _exploding_probe(base_url: str) -> dict[str, Any]:
    raise AssertionError("probe_gateway must not run without a configured gateway URL")


def test_gateway_status_not_configured_returns_200_without_network(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(gateway_module, "probe_gateway", _exploding_probe)
    response = client.get("/api/gateway/status")
    assert response.status_code == 200
    body = response.json()
    assert body["configured"] is False
    assert body["status"] == "not_configured"
    assert body["reason"] == "gateway_url_unset"
    assert body["url"] is None
    assert body["health"] is None
    assert body["readiness"] is None
    assert isinstance(body["checked_at"], str) and body["checked_at"]
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.parametrize(
    "value",
    [
        "http://example.com:8765",
        "http://127.0.0.1:8765/healthz",
        "http://user:secret@127.0.0.1:8765",
        "http://127.0.0.1:8765?token=synthetic-token-value",
        "ftp://127.0.0.1:8765",
        "http://192.168.1.10:8765",
        "http://127.0.0.1:99999",
    ],
)
def test_gateway_status_rejects_invalid_urls_without_network(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    value: str,
) -> None:
    monkeypatch.setattr(gateway_module, "probe_gateway", _exploding_probe)
    monkeypatch.setenv("AGENTSCAN_GATEWAY_URL", value)
    response = client.get("/api/gateway/status")
    assert response.status_code == 200
    body = response.json()
    assert body["configured"] is True
    assert body["status"] == "misconfigured"
    assert body["reason"] == "gateway_url_invalid"
    assert body["health"] is None
    assert body["readiness"] is None
    assert value not in response.text


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("http://127.0.0.1:8765", True),
        ("http://localhost:8765/", True),
        ("https://localhost", True),
        ("http://[::1]:8765", True),
        ("http://127.0.0.1:8765/healthz", False),
        ("http://example.com:8765", False),
        ("http://user:secret@127.0.0.1:8765", False),
        ("http://127.0.0.1:8765?token=1", False),
        ("http://127.0.0.1:8765#fragment", False),
        ("ftp://127.0.0.1:8765", False),
        ("http://192.168.1.5:8765", False),
        ("http://127.0.0.1:99999", False),
    ],
)
def test_gateway_url_accepts_loopback_http_only(value: str, expected: bool) -> None:
    assert gateway.gateway_url_is_valid(value) is expected


def test_gateway_status_ready_reports_probe_results(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AGENTSCAN_GATEWAY_URL", "http://127.0.0.1:8765")

    async def fake_probe(base_url: str) -> dict[str, Any]:
        return {
            "configured": True,
            "url": base_url,
            "status": "ready",
            "reason": None,
            "health": {"http_status": 200, "status": "ok", "latency_ms": 2.0},
            "readiness": {"http_status": 200, "status": "ready", "latency_ms": 3.0, "reason": None},
            "checked_at": "2026-11-11T12:00:00+00:00",
        }

    monkeypatch.setattr(gateway_module, "probe_gateway", fake_probe)
    response = client.get("/api/gateway/status")
    assert response.status_code == 200
    body = response.json()
    assert body["configured"] is True
    assert body["url"] == "http://127.0.0.1:8765"
    assert body["status"] == "ready"
    assert body["reason"] is None
    assert body["health"]["status"] == "ok"
    assert body["readiness"]["status"] == "ready"


async def test_probe_gateway_ready_via_mock_transport() -> None:
    def ready(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/healthz" or request.url.path == "/readyz"
        if request.url.path == "/healthz":
            return httpx.Response(200, json={"status": "ok"})
        return httpx.Response(200, json={"status": "ready"})

    client = httpx.AsyncClient(
        transport=httpx.MockTransport(ready), timeout=1.5, follow_redirects=False, trust_env=False
    )
    try:
        result = await gateway.probe_gateway("http://127.0.0.1:8765", client=client)
    finally:
        await client.aclose()
    assert result["status"] == "ready"
    assert result["health"]["http_status"] == 200
    assert result["health"]["status"] == "ok"
    assert isinstance(result["health"]["latency_ms"], float)
    assert result["readiness"]["http_status"] == 200
    assert result["readiness"]["status"] == "ready"


async def test_probe_gateway_not_ready_maps_bounded_reason() -> None:
    def not_ready(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/healthz":
            return httpx.Response(200, json={"status": "ok"})
        return httpx.Response(
            503,
            json={
                "status": "not_ready",
                "agentscan_code": "GATEWAY_UNAVAILABLE",
                "reason": "catalog_unavailable",
            },
        )

    client = httpx.AsyncClient(
        transport=httpx.MockTransport(not_ready),
        timeout=1.5,
        follow_redirects=False,
        trust_env=False,
    )
    try:
        result = await gateway.probe_gateway("http://127.0.0.1:8765", client=client)
    finally:
        await client.aclose()
    assert result["status"] == "not_ready"
    assert result["reason"] == "catalog_unavailable"
    assert result["readiness"]["http_status"] == 503
    assert result["readiness"]["reason"] == "catalog_unavailable"
    assert result["health"]["status"] == "ok"


async def test_probe_gateway_timeout_reports_unreachable() -> None:
    def health_timeout(_request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("synthetic timeout failure")

    client = httpx.AsyncClient(
        transport=httpx.MockTransport(health_timeout),
        timeout=1.5,
        follow_redirects=False,
        trust_env=False,
    )
    try:
        result = await gateway.probe_gateway("http://127.0.0.1:8765", client=client)
    finally:
        await client.aclose()
    assert result["status"] == "unreachable"
    assert result["reason"] == "health_timeout"
    assert result["health"]["status"] == "unreachable"


async def test_probe_gateway_unreachable_reports_bounded_reason() -> None:
    def health_unreachable(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("synthetic connect failure")

    client = httpx.AsyncClient(
        transport=httpx.MockTransport(health_unreachable),
        timeout=1.5,
        follow_redirects=False,
        trust_env=False,
    )
    try:
        result = await gateway.probe_gateway("http://127.0.0.1:8765", client=client)
    finally:
        await client.aclose()
    assert result["status"] == "unreachable"
    assert result["reason"] == "health_unreachable"
    assert "synthetic connect failure" not in repr(result)


async def test_probe_gateway_unhealthy_rejects_bad_health_body() -> None:
    def health_error(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"status": "error"})

    client = httpx.AsyncClient(
        transport=httpx.MockTransport(health_error),
        timeout=1.5,
        follow_redirects=False,
        trust_env=False,
    )
    try:
        result = await gateway.probe_gateway("http://127.0.0.1:8765", client=client)
    finally:
        await client.aclose()
    assert result["status"] == "unhealthy"
    assert result["reason"] == "health_invalid"


def test_gateway_status_requires_dashboard_authentication(tmp_path: Path) -> None:
    from agentscan.ui.app import create_app

    app = create_app(token="synthetic-ui-gateway-token", project_root=tmp_path)
    with TestClient(app) as instance:
        assert instance.get("/api/gateway/status").status_code == 401


def test_gateway_status_response_does_not_echo_raw_url_or_token(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    secret_value = "synthetic-raw-token-value"
    monkeypatch.setenv("AGENTSCAN_GATEWAY_URL", f"http://user:{secret_value}@127.0.0.1:8765")
    response = client.get("/api/gateway/status")
    assert response.status_code == 200
    assert secret_value not in response.text
    assert "user:" not in response.text
