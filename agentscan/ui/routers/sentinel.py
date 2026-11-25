# agentscan/ui/routers/sentinel.py
#
# Continuous Sentinel monitoring, canary tokens, and periodic probe endpoints.

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from loguru import logger

from agentscan.core.models import Finding, Target
from agentscan.ui.state import event_bus, state
from agentscan.ui.validation import Fields

router = APIRouter(tags=["sentinel"])


@router.get("/api/sentinel/status")
@router.get("/api/sentinel")
async def api_sentinel_status() -> Any:
    return JSONResponse(state.sentinel_status)


@router.post("/api/sentinel/probe")
async def api_sentinel_probe(payload: dict[str, Any] | None = None) -> Any:
    from agentscan.core.connectors import HttpJsonConnector
    from agentscan.sentinel.watcher import ContinuousWatcher

    if payload is None:
        payload = {}
    fields = Fields(payload)
    target_url = fields.url("target_url", aliases=("target",))
    webhook_url = fields.url("webhook_url", required=False)
    canary_token = fields.text("canary_token", max_length=128)
    if canary_token and (
        len(canary_token) < 16
        or not all(c.isascii() and (c.isalnum() or c in "_-") for c in canary_token)
    ):
        fields.errors["canary_token"] = "Use 16–128 letters, numbers, underscores or hyphens."
    if error_response := fields.response():
        return error_response
    assert target_url is not None
    target = Target(url=target_url)
    watcher = ContinuousWatcher(
        target=target,
        canary_token=canary_token,
        webhook_url=webhook_url,
    )
    connector = HttpJsonConnector(target)
    from agentscan.sentinel.watcher import SentinelProbeError

    try:
        findings = await watcher.run_iteration(connector)
    except SentinelProbeError as error:
        reference = str(uuid.uuid4())
        logger.error("Sentinel probe failed [reference {}]: {}", reference, type(error).__name__)
        diagnostic = {"status": "ERROR", "error": str(error), "error_id": reference}
        await event_bus.publish({"type": "sentinel:error", "data": diagnostic})
        return JSONResponse(diagnostic, status_code=502)

    event = {
        "timestamp": datetime.now(UTC).isoformat(),
        "target": target_url,
        "findings_count": len(findings),
        "status": "ALERT" if findings else "PASS",
        "findings": [f.model_dump(mode="json") for f in findings],
        "webhook_error": watcher.dispatcher.last_error,
    }
    state.sentinel_status["alerts"].insert(0, event)
    await event_bus.publish({"type": "sentinel:probe", "data": event})

    return JSONResponse(
        {
            "status": "ALERT" if findings else "PASS",
            "findings": [f.model_dump(mode="json") for f in findings],
            "canary_token": watcher.canary_sentinel.canary_token,
            "webhook_error": watcher.dispatcher.last_error,
        }
    )


@router.post("/api/sentinel/start")
async def api_sentinel_start(payload: dict[str, Any] | None = None) -> Any:
    from agentscan.core.connectors import HttpJsonConnector
    from agentscan.sentinel.canary import generate_canary_token
    from agentscan.sentinel.watcher import ContinuousWatcher

    if payload is None:
        payload = {}
    fields = Fields(payload)
    target_url = fields.url("target_url", aliases=("target",))
    interval = fields.integer("interval_seconds", 5, 3600, default=60, aliases=("interval",))
    max_iters = fields.integer("max_iterations", 1, 100000)
    webhook_url = fields.url("webhook_url", required=False)
    canary_token = fields.text("canary_token", max_length=128)
    if canary_token and (
        len(canary_token) < 16
        or not all(c.isascii() and (c.isalnum() or c in "_-") for c in canary_token)
    ):
        fields.errors["canary_token"] = "Use 16–128 letters, numbers, underscores or hyphens."
    if error_response := fields.response():
        return error_response
    assert target_url is not None and interval is not None
    canary_token = canary_token or generate_canary_token()
    if state.sentinel_task and not state.sentinel_task.done():
        return JSONResponse(
            {"error": "A Sentinel watcher is already running. Stop it before starting another."},
            status_code=409,
        )

    target = Target(url=target_url)
    watcher = ContinuousWatcher(
        target=target,
        interval_seconds=interval,
        max_iterations=max_iters,
        webhook_url=webhook_url,
        canary_token=canary_token,
    )
    connector = HttpJsonConnector(target)

    state.sentinel_status = {
        "running": True,
        "status": "RUNNING",
        "error": None,
        "error_id": None,
        "webhook_error": None,
        "target": target_url,
        "interval": interval,
        # The status artifact is readable by any dashboard viewer and replayed over
        # SSE: keep only a configured marker, never the raw synthetic canary token.
        # The operator-facing start/probe responses still return the token once so
        # it can be planted on the target.
        "canary_token": "configured" if canary_token else None,
        "canary_token_configured": bool(canary_token),
        "webhook_url": webhook_url,
        "alerts": state.sentinel_status.get("alerts", []),
    }
    await event_bus.publish({"type": "sentinel:start", "data": state.sentinel_status})

    async def _watcher_loop() -> None:
        def _callback(cycle: int, f_list: list[Finding]) -> None:
            state.sentinel_status["webhook_error"] = watcher.dispatcher.last_error
            record = {
                "timestamp": datetime.now(UTC).isoformat(),
                "cycle": cycle,
                "target": target_url,
                "findings_count": len(f_list),
                "status": "ALERT" if f_list else "PASS",
                "findings": [f.model_dump(mode="json") for f in f_list],
            }
            state.sentinel_status["alerts"].insert(0, record)
            asyncio.create_task(event_bus.publish({"type": "sentinel:alert", "data": record}))

        try:
            await watcher.run_loop(connector, callback=_callback)
        except Exception as error:
            import httpx

            from agentscan.core.outcomes import ModuleUnavailableError, TargetRequestError

            reference = str(uuid.uuid4())
            message = "Sentinel monitoring failed. Review the diagnostic reference and restart after correcting the monitoring configuration."
            from agentscan.sentinel.watcher import SentinelProbeError

            if isinstance(error, SentinelProbeError):
                message = str(error)
            elif isinstance(error, TargetRequestError):
                message = "Sentinel could not evaluate a target request. Check the endpoint and target authentication, then restart monitoring."
            elif isinstance(error, ModuleUnavailableError):
                message = "A required monitoring component is unavailable. Check the installed runtime dependencies and restart monitoring."
            elif isinstance(error, httpx.TimeoutException):
                message = "The monitoring request timed out. Check target availability and restart monitoring."
            elif isinstance(error, httpx.ConnectError):
                message = "Sentinel could not connect to the monitoring service. Check its endpoint and availability, then restart monitoring."
            logger.error(
                "Sentinel watcher failed [reference {}]: {}", reference, type(error).__name__[:80]
            )
            state.sentinel_status.update(
                {"status": "ERROR", "error": message, "error_id": reference}
            )
            await event_bus.publish(
                {
                    "type": "sentinel:error",
                    "data": {
                        "running": False,
                        "status": "ERROR",
                        "error": message,
                        "error_id": reference,
                    },
                }
            )
        finally:
            state.sentinel_status["running"] = False
            if state.sentinel_status.get("status") != "ERROR":
                state.sentinel_status["status"] = "STOPPED"
            await event_bus.publish(
                {
                    "type": "sentinel:stop",
                    "data": {
                        key: state.sentinel_status.get(key)
                        for key in ("running", "status", "error", "error_id")
                    },
                }
            )

    state.sentinel_task = asyncio.create_task(_watcher_loop())
    return JSONResponse({"status": "started", "running": True, "canary_token": canary_token})


@router.post("/api/sentinel/stop")
async def api_sentinel_stop() -> Any:
    if state.sentinel_task and not state.sentinel_task.done():
        state.sentinel_task.cancel()
    state.sentinel_status["running"] = False
    state.sentinel_status["status"] = "STOPPED"
    await event_bus.publish({"type": "sentinel:stop", "data": {"running": False}})
    return JSONResponse({"status": "stopped", "running": False})
