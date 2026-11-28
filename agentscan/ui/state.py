# agentscan/ui/state.py
#
# Shared in-memory UI state and SSE event bus.

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from agentscan.core.models import ScanReport
from agentscan.swarm.blackboard import SwarmBlackboard

STATIC_DIR = Path(__file__).resolve().parent / "static"


def initial_sentinel_status() -> dict[str, Any]:
    """Return a Sentinel status record with only factual, unset values."""
    return {
        "running": False,
        "status": "IDLE",
        "error": None,
        "error_id": None,
        "webhook_error": None,
        "target": None,
        "interval": 60,
        "canary_token": None,
        "webhook_url": None,
        "probes_run": 0,
        "probes_failed": 0,
        "leaks_detected": 0,
        "last_probe_at": None,
        "last_probe_status": None,
        "last_probe_error": None,
        "last_probe_error_id": None,
        "alerts": [],
    }


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
        self.sentinel_status: dict[str, Any] = initial_sentinel_status()
        self.sentinel_task: asyncio.Task[Any] | None = None
        self.audit_report: dict[str, Any] | None = None
        self.webhook_receiver_status: dict[str, Any] = {
            "status": "online",
            "port": 8766,
            "endpoint": "/webhook/alert",
            "recent_alerts": [],
        }

    def record_sentinel_probe(
        self,
        status: str,
        *,
        error: str | None = None,
        error_id: str | None = None,
    ) -> dict[str, Any]:
        """Record one completed probe attempt without inventing an outcome."""
        normalized = status if status in {"PASS", "ALERT", "ERROR"} else "ERROR"
        recorded_at = datetime.now(UTC).isoformat()
        self.sentinel_status["probes_run"] = int(self.sentinel_status.get("probes_run") or 0) + 1
        self.sentinel_status["last_probe_at"] = recorded_at
        self.sentinel_status["last_probe_status"] = normalized
        if normalized == "ERROR":
            self.sentinel_status["probes_failed"] = (
                int(self.sentinel_status.get("probes_failed") or 0) + 1
            )
            self.sentinel_status["last_probe_error"] = error
            self.sentinel_status["last_probe_error_id"] = error_id
        else:
            self.sentinel_status["last_probe_error"] = None
            self.sentinel_status["last_probe_error_id"] = None
        return {"status": normalized, "timestamp": recorded_at}

    def record_sentinel_alert(self, record: dict[str, Any]) -> None:
        """Record a leak alert and derive the alert count from recorded evidence."""
        alerts = self.sentinel_status.setdefault("alerts", [])
        alerts.insert(0, record)
        self.sentinel_status["leaks_detected"] = sum(
            1 for alert in alerts if isinstance(alert, dict) and alert.get("status") == "ALERT"
        )

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
