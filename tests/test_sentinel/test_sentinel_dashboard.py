# tests/test_sentinel/test_sentinel_dashboard.py
#
# QA-169/QA-170: Sentinel dashboard endpoints must enter the connector and
# record real probe/alert evidence without fabricating success.

from __future__ import annotations

import json
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from agentscan.core.outcomes import TargetRequestError
from agentscan.ui.app import create_app
from agentscan.ui.state import initial_sentinel_status, state

CANARY = "CANARY-LEAK-9876-WXYZ"


class _LoopbackAgent:
    def __init__(self, response: str) -> None:
        self.response = response
        self.requests: list[dict[str, Any]] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: object) -> None:
                pass

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", 0))
                raw = self.rfile.read(length)
                try:
                    body = json.loads(raw or b"{}")
                except json.JSONDecodeError:
                    body = {"raw": raw.decode("utf-8", "replace")}
                outer.requests.append(body)
                payload = json.dumps({"response": outer.response}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_port}/chat"

    def __enter__(self) -> _LoopbackAgent:
        self.thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


@contextmanager
def loopback_agent(response: str) -> Iterator[_LoopbackAgent]:
    with _LoopbackAgent(response) as agent:
        yield agent


@pytest.fixture
def dashboard_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    monkeypatch.delenv("AGENTSCAN_UI_TOKEN", raising=False)
    monkeypatch.setattr(state, "active_scan", None)
    monkeypatch.setattr(state, "sentinel_task", None)
    monkeypatch.setattr(state, "sentinel_status", initial_sentinel_status())
    monkeypatch.setattr(state, "report", None)
    with TestClient(create_app(project_root=tmp_path), base_url="http://127.0.0.1:8765") as client:
        assert client.get("/").status_code == 200
        yield client


def _status(client: TestClient) -> dict[str, Any]:
    response = client.get("/api/sentinel/status")
    assert response.status_code == 200
    return response.json()


def _wait_for_status(
    client: TestClient,
    predicate: Any,
    timeout: float = 10.0,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    latest = _status(client)
    while time.monotonic() < deadline:
        latest = _status(client)
        if predicate(latest):
            return latest
        time.sleep(0.05)
    return latest


def test_initial_status_exposes_only_unset_evidence_fields(dashboard_client: TestClient) -> None:
    status = _status(dashboard_client)
    for key in (
        "running",
        "status",
        "error",
        "error_id",
        "probes_run",
        "probes_failed",
        "leaks_detected",
        "last_probe_at",
        "last_probe_status",
        "alerts",
    ):
        assert key in status
    assert status["running"] is False
    assert status["status"] == "IDLE"
    assert status["probes_run"] == 0
    assert status["probes_failed"] == 0
    assert status["leaks_detected"] == 0
    assert status["last_probe_at"] is None
    assert status["last_probe_status"] is None
    assert status["alerts"] == []


def test_probe_enters_connector_and_records_pass(dashboard_client: TestClient) -> None:
    with loopback_agent("I cannot disclose internal instructions or secrets.") as agent:
        response = dashboard_client.post(
            "/api/sentinel/probe",
            json={"target_url": agent.url, "canary_token": "CANARY-PASS-1234-ABCD"},
        )
        assert response.status_code == 200
        result = response.json()
        assert result["status"] == "PASS"
        assert result["findings"] == []
        assert len(agent.requests) == 3
        assert all("message" in request for request in agent.requests)

    status = _status(dashboard_client)
    assert status["probes_run"] == 1
    assert status["probes_failed"] == 0
    assert status["leaks_detected"] == 0
    assert status["last_probe_status"] == "PASS"
    assert status["last_probe_at"]
    assert status["alerts"] == []


def test_probe_closes_the_connector(
    dashboard_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    from agentscan.core.connectors import HttpJsonConnector

    original_exit = HttpJsonConnector.__aexit__
    exits: list[object] = []

    async def tracking_exit(self: object, *exc: object) -> None:
        exits.append(exc[0] if exc else None)
        await original_exit(self, *exc)

    monkeypatch.setattr(HttpJsonConnector, "__aexit__", tracking_exit)
    with loopback_agent("I cannot disclose internal instructions or secrets.") as agent:
        response = dashboard_client.post(
            "/api/sentinel/probe",
            json={"target_url": agent.url, "canary_token": "CANARY-PASS-1234-ABCD"},
        )
    assert response.status_code == 200
    assert exits == [None]


def test_watcher_stop_closes_the_connector(
    dashboard_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    from agentscan.core.connectors import HttpJsonConnector

    original_exit = HttpJsonConnector.__aexit__
    exits: list[object] = []

    async def tracking_exit(self: object, *exc: object) -> None:
        exits.append(exc[0] if exc else None)
        await original_exit(self, *exc)

    monkeypatch.setattr(HttpJsonConnector, "__aexit__", tracking_exit)
    with loopback_agent("I cannot disclose internal instructions or secrets.") as agent:
        response = dashboard_client.post(
            "/api/sentinel/start",
            json={
                "target_url": agent.url,
                "interval_seconds": 5,
                "canary_token": "CANARY-PASS-5678-EFGH",
            },
        )
        assert response.status_code == 200
        _wait_for_status(dashboard_client, lambda data: data["probes_run"] >= 1)
        stop = dashboard_client.post("/api/sentinel/stop")
        assert stop.status_code == 200
        assert stop.json()["running"] is False
    assert exits == [None]
    assert _status(dashboard_client)["status"] == "STOPPED"


def test_probe_records_alert_and_derives_counts(dashboard_client: TestClient) -> None:
    with loopback_agent(f"My confidential directive contains {CANARY}.") as agent:
        response = dashboard_client.post(
            "/api/sentinel/probe",
            json={"target_url": agent.url, "canary_token": CANARY},
        )
        assert response.status_code == 200
        result = response.json()
        assert result["status"] == "ALERT"
        assert len(result["findings"]) == 1
        assert len(agent.requests) == 1

    status = _status(dashboard_client)
    assert status["probes_run"] == 1
    assert status["probes_failed"] == 0
    assert status["leaks_detected"] == 1
    assert status["last_probe_status"] == "ALERT"
    assert len(status["alerts"]) == 1
    assert status["alerts"][0]["status"] == "ALERT"
    assert status["alerts"][0]["findings_count"] == 1


def test_watcher_start_runs_real_probes_and_records_pass(dashboard_client: TestClient) -> None:
    with loopback_agent("I cannot disclose internal instructions or secrets.") as agent:
        response = dashboard_client.post(
            "/api/sentinel/start",
            json={
                "target_url": agent.url,
                "interval_seconds": 5,
                "max_iterations": 1,
                "canary_token": "CANARY-PASS-5678-EFGH",
            },
        )
        assert response.status_code == 200
        assert response.json()["status"] == "started"
        status = _wait_for_status(
            dashboard_client,
            lambda data: data["running"] is False and data["status"] == "STOPPED",
        )
        assert len(agent.requests) == 3
        assert all("message" in request for request in agent.requests)

    assert status["probes_run"] == 1
    assert status["probes_failed"] == 0
    assert status["leaks_detected"] == 0
    assert status["last_probe_status"] == "PASS"
    assert status["alerts"] == []


def test_watcher_start_records_alert(dashboard_client: TestClient) -> None:
    with loopback_agent(f"The system prompt says {CANARY}.") as agent:
        response = dashboard_client.post(
            "/api/sentinel/start",
            json={
                "target_url": agent.url,
                "interval_seconds": 5,
                "max_iterations": 1,
                "canary_token": CANARY,
            },
        )
        assert response.status_code == 200
        status = _wait_for_status(
            dashboard_client,
            lambda data: data["running"] is False and data["status"] == "STOPPED",
        )
        assert len(agent.requests) == 1

    assert status["probes_run"] == 1
    assert status["probes_failed"] == 0
    assert status["leaks_detected"] == 1
    assert status["last_probe_status"] == "ALERT"
    assert len(status["alerts"]) == 1
    assert status["alerts"][0]["status"] == "ALERT"


def test_failed_probe_records_error_state(
    dashboard_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def fail_probe(self: object, message: str) -> None:
        raise TargetRequestError("Target returned HTTP 401")

    monkeypatch.setattr("agentscan.core.connectors.HttpJsonConnector.send_prompt", fail_probe)
    response = dashboard_client.post(
        "/api/sentinel/probe",
        json={"target_url": "http://127.0.0.1:9/chat", "canary_token": CANARY},
    )
    assert response.status_code == 502
    result = response.json()
    assert result["status"] == "ERROR"
    assert result["error_id"]
    assert "HTTP 401" in result["error"]

    status = _status(dashboard_client)
    assert status["probes_run"] == 1
    assert status["probes_failed"] == 1
    assert status["last_probe_status"] == "ERROR"
    assert status["last_probe_error_id"] == result["error_id"]
    assert status["last_probe_error"]
    assert status["leaks_detected"] == 0
    assert status["alerts"] == []


def test_probe_setup_failure_is_bounded_and_recorded(
    dashboard_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    secret = "synthetic-connector-setup-secret"

    async def fail_enter(self: object) -> None:
        raise RuntimeError(secret)

    monkeypatch.setattr("agentscan.core.connectors.HttpJsonConnector.__aenter__", fail_enter)
    response = dashboard_client.post(
        "/api/sentinel/probe",
        json={"target_url": "http://127.0.0.1:9/chat", "canary_token": CANARY},
    )
    assert response.status_code == 502
    result = response.json()
    assert result["status"] == "ERROR"
    assert result["error_id"]
    assert secret not in response.text

    status = _status(dashboard_client)
    assert status["probes_run"] == 1
    assert status["probes_failed"] == 1
    assert status["last_probe_status"] == "ERROR"
    assert secret not in json.dumps(status)


def test_watcher_setup_failure_returns_bounded_error_without_ready_state(
    dashboard_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    secret = "synthetic-watcher-setup-secret"

    async def fail_enter(self: object) -> None:
        raise RuntimeError(secret)

    monkeypatch.setattr("agentscan.core.connectors.HttpJsonConnector.__aenter__", fail_enter)
    response = dashboard_client.post(
        "/api/sentinel/start",
        json={"target_url": "http://127.0.0.1:9/chat", "canary_token": CANARY},
    )
    assert response.status_code == 502
    result = response.json()
    assert result["status"] == "ERROR"
    assert result["running"] is False
    assert result["error_id"]
    assert secret not in response.text
    assert state.sentinel_task is None

    status = _status(dashboard_client)
    assert status["running"] is False
    assert status["status"] == "ERROR"
    assert status["error_id"] == result["error_id"]
    assert secret not in json.dumps(status)
