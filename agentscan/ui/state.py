# agentscan/ui/state.py
#
# Shared in-memory UI state and SSE event bus.

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from agentscan.core.models import ScanReport
from agentscan.swarm.blackboard import SwarmBlackboard

STATIC_DIR = Path(__file__).resolve().parent / "static"


class UiState:
    def __init__(self) -> None:
        self.report_path: Path | None = None
        self.identity_path: Path | None = None
        self.report: ScanReport | None = None
        self.active_scan: asyncio.Task[Any] | None = None
        self.scan_recorder: Any = None
        self.scan_status: dict[str, Any] = {
            "status": "idle",
            "target": None,
            "progress": 0,
            "current_module": None,
            "findings_count": 0,
        }
        self.swarm_blackboard: SwarmBlackboard = SwarmBlackboard()
        self.sentinel_status: dict[str, Any] = {
            "running": False,
            "target": None,
            "interval": 60,
            "canary_token": None,
            "webhook_url": None,
            "alerts": [],
        }
        self.sentinel_task: asyncio.Task[Any] | None = None
        self.audit_report: dict[str, Any] | None = None
        self.webhook_receiver_status: dict[str, Any] = {
            "status": "online",
            "port": 8766,
            "endpoint": "/webhook/alert",
            "recent_alerts": [],
        }

    def load_report(self, path: Path | None) -> ScanReport | None:
        self.report_path = path
        if path is None or not path.exists():
            self.report = None
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            self.report = ScanReport.model_validate(data)
            return self.report
        except (json.JSONDecodeError, ValidationError, UnicodeDecodeError) as err:
            raise RuntimeError(
                f"Failed to parse report from '{path}': expected valid JSON adhering to ScanReport schema. "
                f"Detail: {err}. Note: 'agentscan ui --report' requires a JSON report generated via "
                f"'agentscan scan --output report.json' (HTML reports cannot be loaded as data)."
            ) from err


state = UiState()


class EventBus:
    """In-memory publish/subscribe event bus for real-time dashboard updates."""

    def __init__(self) -> None:
        self.subscribers: list[asyncio.Queue[dict[str, Any]]] = []

    def subscribe(self) -> asyncio.Queue[dict[str, Any]]:
        q: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=256)
        self.subscribers.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue[dict[str, Any]]) -> None:
        if q in self.subscribers:
            self.subscribers.remove(q)

    async def publish(self, event: dict[str, Any]) -> None:
        dead: list[asyncio.Queue[dict[str, Any]]] = []
        for q in list(self.subscribers):
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                dead.append(q)
        for q in dead:
            self.subscribers.remove(q)


event_bus = EventBus()
