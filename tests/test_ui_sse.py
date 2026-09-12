# tests/test_ui_sse.py

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest


def test_event_bus_pub_sub() -> None:
    from agentscan.ui.app import EventBus

    bus = EventBus()
    q = bus.subscribe()
    assert q in bus.subscribers

    async def run_pub() -> None:
        await bus.publish({"type": "finding", "data": {"id": "ATK-001"}})

    asyncio.run(run_pub())
    assert not q.empty()
    item = q.get_nowait()
    assert item["type"] == "finding"
    assert item["data"]["id"] == "ATK-001"

    bus.unsubscribe(q)
    assert q not in bus.subscribers


def test_ui_sse_endpoints(tmp_path: Path) -> None:
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from agentscan.ui.app import create_app

    app = create_app()
    client = TestClient(app)

    # Test POST /api/events
    resp = client.post("/api/events", json={"type": "finding", "data": {"id": "ATK-013"}})
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}

    # Test POST /api/reload
    resp2 = client.post("/api/reload")
    assert resp2.status_code == 200
    assert resp2.json() == {"status": "reloaded"}

    # Test GET /api/events connection streaming with limit=1
    resp3 = client.get("/api/events?limit=1")
    assert resp3.status_code == 200
    assert "text/event-stream" in resp3.headers.get("content-type", "")
    assert "event: ping" in resp3.text
