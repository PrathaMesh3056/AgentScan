from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock

import httpx
import pytest
from pydantic import ValidationError

from agentscan.api import server
from agentscan.api.auth import get_current_tenant
from agentscan.api.contracts import ScanRequest


@pytest.fixture
async def client(monkeypatch):
    monkeypatch.setattr(server, "read_scan_events", AsyncMock(return_value=[]))
    app = server.create_api_app()
    app.dependency_overrides[get_current_tenant] = lambda: "tenant-a"
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://api.test"
    ) as client:
        yield client


@pytest.mark.parametrize(
    "url",
    [
        "mcp://stdio?command=python",
        "browser://agent.test",
        "file:///tmp/test",
        "https://unapproved.test/chat",
        "ws://agent.test/chat",
        "wss://agent.test/chat",
        "http://user:password@agent.test/chat",
        "http://agent.test/chat#fragment",
    ],
)
def test_remote_request_rejects_unapproved_execution_paths(url):
    with pytest.raises(ValidationError):
        ScanRequest(target_url=url)


@pytest.mark.parametrize("url", ["ws://agent.test/chat", "wss://agent.test/chat"])
async def test_remote_websocket_submission_rejected_before_persistence(client, monkeypatch, url):
    persist, enqueue = AsyncMock(), AsyncMock()
    monkeypatch.setattr(server, "submit_scan", persist)
    monkeypatch.setattr(server, "dispatch_outbox", enqueue)
    response = await client.post("/scans", json={"target_url": url})
    assert response.status_code == 422
    persist.assert_not_awaited()
    enqueue.assert_not_awaited()


async def test_queue_submission_passes_datetime(client, monkeypatch):
    persist, enqueue = AsyncMock(), AsyncMock(return_value="1-0")
    monkeypatch.setattr(server, "submit_scan", persist)
    monkeypatch.setattr(server, "dispatch_outbox", enqueue)
    response = await client.post("/scans", json={"target_url": "http://agent.test/chat"})
    assert response.status_code == 202
    timestamp = persist.await_args.args[1]
    assert isinstance(timestamp, datetime) and timestamp.utcoffset().total_seconds() == 0


async def test_queue_failure_retains_durable_accepted_delivery(client, monkeypatch):
    persist = AsyncMock()
    monkeypatch.setattr(server, "submit_scan", persist)
    monkeypatch.setattr(
        server, "dispatch_outbox", AsyncMock(side_effect=RuntimeError("queue unavailable"))
    )
    response = await client.post("/scans", json={"target_url": "http://agent.test/chat"})
    assert response.status_code == 202
    assert response.json()["scan_id"] == persist.await_args.args[0]["scan_id"]


async def test_tenant_cannot_submit_another_tenants_origin(client, monkeypatch):
    persist = AsyncMock()
    monkeypatch.setattr(server, "submit_scan", persist)
    client._transport.app.dependency_overrides[get_current_tenant] = lambda: "tenant-b"
    response = await client.post("/scans", json={"target_url": "http://agent.test/chat"})
    assert response.status_code == 403
    persist.assert_not_awaited()


async def test_readiness_fails_for_dependency_outage(client, monkeypatch):
    monkeypatch.setattr(server, "check_db", AsyncMock(side_effect=RuntimeError("down")))
    monkeypatch.setattr(server, "check_redis", AsyncMock())
    assert (await client.get("/health/ready")).status_code == 503
    assert (await client.get("/health/live")).status_code == 200


async def test_completed_json_report_and_timestamp_response(client, monkeypatch):
    row = {
        "scan_id": "a",
        "tenant_id": "tenant-a",
        "target_url": "http://agent.test/chat",
        "scan_mode": "SCAN",
        "status": "completed",
        "score": 81,
        "started_at": datetime.now(UTC),
        "completed_at": datetime.now(UTC),
        "report_json": {"findings": [], "score": 81},
    }
    monkeypatch.setattr(server, "get_scan", AsyncMock(return_value=row))
    response = await client.get("/scans/a")
    assert response.status_code == 200
    assert response.json()["report"] == row["report_json"]
    assert response.json()["started_at"].endswith("Z")


async def test_active_record_delete_is_rejected(client, monkeypatch):
    monkeypatch.setattr(server, "get_scan", AsyncMock(return_value={"status": "running"}))
    delete = AsyncMock()
    monkeypatch.setattr(server, "delete_terminal_scan", delete)
    response = await client.delete("/scans/a")
    assert response.status_code == 409
    delete.assert_not_awaited()


async def test_late_terminal_subscription_returns_immediately(client, monkeypatch):
    monkeypatch.setattr(
        server, "get_scan", AsyncMock(return_value={"status": "inconclusive", "score": None})
    )
    response = await client.get("/scans/a/stream")
    assert response.status_code == 200
    assert '"status": "inconclusive"' in response.text


async def test_startup_dependency_failure_closes_pool(monkeypatch):
    close = AsyncMock()
    monkeypatch.setattr(server, "init_db", AsyncMock())
    monkeypatch.setattr(
        server, "ensure_consumer_groups", AsyncMock(side_effect=RuntimeError("Redis unavailable"))
    )
    monkeypatch.setattr(server, "close_db", close)
    with pytest.raises(RuntimeError, match="Redis unavailable"):
        async with server.lifespan(server.create_api_app()):
            pytest.fail("Failed initialization must not yield a serving application.")
    close.assert_awaited_once()


async def test_initial_persistence_failure_returns_service_error(client, monkeypatch):
    monkeypatch.setattr(
        server, "submit_scan", AsyncMock(side_effect=RuntimeError("database unavailable"))
    )
    enqueue = AsyncMock()
    monkeypatch.setattr(server, "dispatch_outbox", enqueue)
    response = await client.post("/scans", json={"target_url": "http://agent.test/chat"})
    assert response.status_code == 503
    enqueue.assert_not_awaited()


async def test_external_analysis_requires_designation_and_tenant_opt_in(client, monkeypatch):
    persist = AsyncMock()
    monkeypatch.setattr(server, "submit_scan", persist)
    missing = await client.post(
        "/scans", json={"target_url": "http://agent.test/chat", "analysis_mode": "external"}
    )
    assert missing.status_code == 422
    denied = await client.post(
        "/scans",
        json={
            "target_url": "http://agent.test/chat",
            "analysis_mode": "external",
            "data_classification": "non_sensitive",
        },
    )
    assert denied.status_code == 403
    persist.assert_not_awaited()


async def test_external_analysis_records_designation_but_never_provider_key(client, monkeypatch):
    import json
    import os

    policies = json.loads(os.environ["AGENTSCAN_TENANT_POLICIES_JSON"])
    policies["tenant-a"]["allow_external_model_analysis"] = True
    monkeypatch.setenv("AGENTSCAN_TENANT_POLICIES_JSON", json.dumps(policies))
    monkeypatch.setenv("AGENTSCAN_EXTERNAL_MODEL", "gemini/synthetic-model")
    monkeypatch.setenv("GEMINI_API_KEY", "synthetic-provider-key")
    persist = AsyncMock()
    monkeypatch.setattr(server, "submit_scan", persist)
    monkeypatch.setattr(server, "dispatch_outbox", AsyncMock())
    response = await client.post(
        "/scans",
        json={
            "target_url": "http://agent.test/chat",
            "analysis_mode": "external",
            "data_classification": "non_sensitive",
        },
    )
    assert response.status_code == 202
    target = persist.await_args.args[0]["target"]
    assert target["data_classification"] == "non_sensitive"
    assert "synthetic-provider-key" not in json.dumps(target)
