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

SCAN_IDLE = "idle"
SCAN_RUNNING = "running"
SCAN_COMPLETED = "completed"
SCAN_INCONCLUSIVE = "inconclusive"
SCAN_FAILED = "failed"
SCAN_CANCELLED = "cancelled"

# The dashboard scan status is a small state machine: a terminal (or idle) scan may start, a running
# scan may only finish, and every terminal transition is idempotent so duplicate task callbacks are safe.
SCAN_TERMINAL_STATES = frozenset(
    {SCAN_IDLE, SCAN_COMPLETED, SCAN_INCONCLUSIVE, SCAN_FAILED, SCAN_CANCELLED}
)
SCAN_ACTIVE_STATES = frozenset({SCAN_RUNNING})
SCAN_TRANSITIONS: dict[str, frozenset[str]] = {
    SCAN_IDLE: frozenset({SCAN_RUNNING}),
    SCAN_RUNNING: frozenset({SCAN_COMPLETED, SCAN_INCONCLUSIVE, SCAN_FAILED, SCAN_CANCELLED}),
    SCAN_COMPLETED: frozenset({SCAN_RUNNING}),
    SCAN_INCONCLUSIVE: frozenset({SCAN_RUNNING}),
    SCAN_FAILED: frozenset({SCAN_RUNNING}),
    SCAN_CANCELLED: frozenset({SCAN_RUNNING}),
}


class ScanStateError(RuntimeError):
    """Raised when a scan status transition leaves the dashboard state machine."""


def _timestamp() -> str:
    return datetime.now(UTC).isoformat()


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

    def scan_snapshot(self) -> dict[str, Any]:
        """Return a copy of the authoritative scan status for API responses."""
        return dict(self.scan_status)

    def scan_in_progress(self) -> bool:
        """A scan is in progress while its task runs or the status machine is still running."""
        if self.active_scan is not None and not self.active_scan.done():
            return True
        return str(self.scan_status.get("status", SCAN_IDLE)) in SCAN_ACTIVE_STATES

    def _scan_transition(self, status: str, **fields: Any) -> dict[str, Any]:
        current = str(self.scan_status.get("status", SCAN_IDLE))
        allowed = SCAN_TRANSITIONS.get(current)
        if allowed is None or status not in allowed:
            raise ScanStateError(f"Cannot move a {current!r} scan to {status!r}.")
        self.scan_status = {**self.scan_status, **fields, "status": status}
        return dict(self.scan_status)

    def begin_scan(self, scan_id: str, target: str, modes: list[str]) -> dict[str, Any]:
        """Start a new scan from idle or from a previous terminal state."""
        return self._scan_transition(
            SCAN_RUNNING,
            scan_id=scan_id,
            target=target,
            modes=list(modes),
            findings_count=0,
            progress=5,
            current_module="Initializing scan orchestrator...",
            tests_run=0,
            tests_selected=0,
            module_errors=[],
            module_outcomes=[],
            score=None,
            assessment_scope=None,
            error=None,
            error_id=None,
            error_code=None,
            started_at=_timestamp(),
            finished_at=None,
        )

    def finish_scan(self, status: str, **fields: Any) -> dict[str, Any]:
        """Move a running scan to a terminal state; repeated terminal updates are ignored."""
        if status not in SCAN_TERMINAL_STATES or status == SCAN_IDLE:
            raise ScanStateError(f"{status!r} is not a scan terminal status.")
        current = str(self.scan_status.get("status", SCAN_IDLE))
        if current == SCAN_IDLE:
            raise ScanStateError("No scan is running.")
        if current in SCAN_TERMINAL_STATES:
            return dict(self.scan_status)
        progress = self.scan_status.get("progress", 0)
        terminal = {
            SCAN_COMPLETED: ("Done", 100),
            SCAN_INCONCLUSIVE: ("Inconclusive", 100),
            SCAN_FAILED: ("Error", 0),
            SCAN_CANCELLED: ("Cancelled by operator", progress),
        }[status]
        return self._scan_transition(
            status,
            **{
                "progress": terminal[1],
                "current_module": terminal[0],
                "finished_at": _timestamp(),
                **fields,
            },
        )

    def cancel_scan(self) -> tuple[dict[str, Any], bool]:
        """Cancel only a running scan; terminal scans are never overwritten."""
        if str(self.scan_status.get("status", SCAN_IDLE)) != SCAN_RUNNING:
            return dict(self.scan_status), False
        snapshot = self._scan_transition(
            SCAN_CANCELLED,
            progress=self.scan_status.get("progress", 0),
            current_module="Cancelled by operator",
            finished_at=_timestamp(),
        )
        return snapshot, True


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
