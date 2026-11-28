# agentscan/ui/routers/sentinel.py
#
# Continuous Sentinel monitoring, canary tokens, and periodic probe endpoints.

from __future__ import annotations

import asyncio
import uuid
from contextlib import AsyncExitStack
from typing import Any

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from loguru import logger

from agentscan.core.models import Finding, Target
from agentscan.ui.state import event_bus, state
from agentscan.ui.validation import Fields

router = APIRouter(tags=["sentinel"])


def _probe_failure(
    error: Exception,
    reference: str,
    message: str,
) -> dict[str, Any]:
    """Record and return a bounded probe failure without exposing transport detail."""
    state.record_sentinel_probe("ERROR", error=message, error_id=reference)
    logger.error("Sentinel probe failed [reference {}]: {}", reference, type(error).__name__[:80])
    return {
        "status": "ERROR",
        "error": message,
        "error_id": reference,
        "probes_run": state.sentinel_status.get("probes_run", 0),
        "probes_failed": state.sentinel_status.get("probes_failed", 0),
        "last_probe_at": state.sentinel_status.get("last_probe_at"),
        "last_probe_status": state.sentinel_status.get("last_probe_status"),
    }


@router.get("/api/sentinel/status")
@router.get("/api/sentinel")
async def api_sentinel_status() -> Any:
    return JSONResponse(state.sentinel_status)


@router.post("/api/sentinel/probe")
async def api_sentinel_probe(payload: dict[str, Any] | None = None) -> Any:
    from agentscan.core.connectors import HttpJsonConnector
    from agentscan.sentinel.watcher import ContinuousWatcher, SentinelProbeError

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

    try:
        async with connector:
            findings = await watcher.run_iteration(connector)
    except SentinelProbeError as error:
        reference = str(uuid.uuid4())
        diagnostic = _probe_failure(error, reference, str(error))
        await event_bus.publish({"type": "sentinel:error", "data": diagnostic})
        return JSONResponse(diagnostic, status_code=502)
    except Exception as error:
        reference = str(uuid.uuid4())
        message = (
            "Sentinel could not complete the probe. Review the diagnostic reference and retry."
        )
        diagnostic = _probe_failure(error, reference, message)
        await event_bus.publish({"type": "sentinel:error", "data": diagnostic})
        return JSONResponse(diagnostic, status_code=502)

    status = "ALERT" if findings else "PASS"
    recorded = state.record_sentinel_probe(status)
    event = {
        "timestamp": recorded["timestamp"],
        "target": target_url,
        "findings_count": len(findings),
        "status": status,
        "findings": [f.model_dump(mode="json") for f in findings],
        "webhook_error": watcher.dispatcher.last_error,
    }
    if findings:
        state.record_sentinel_alert(event)
    await event_bus.publish({"type": "sentinel:probe", "data": event})

    return JSONResponse(
        {
            "status": status,
            "findings": [f.model_dump(mode="json") for f in findings],
            "canary_token": watcher.canary_sentinel.canary_token,
            "webhook_error": watcher.dispatcher.last_error,
            "probes_run": state.sentinel_status.get("probes_run", 0),
            "probes_failed": state.sentinel_status.get("probes_failed", 0),
            "leaks_detected": state.sentinel_status.get("leaks_detected", 0),
            "last_probe_at": recorded["timestamp"],
            "last_probe_status": status,
        }
    )


@router.post("/api/sentinel/start")
async def api_sentinel_start(payload: dict[str, Any] | None = None) -> Any:
    from agentscan.core.connectors import HttpJsonConnector
    from agentscan.sentinel.canary import generate_canary_token
    from agentscan.sentinel.watcher import ContinuousWatcher, SentinelProbeError

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

    # Startup self-test: enter the connector context, run the watcher's
    # configuration/readiness check, and verify the probe surface before the
    # dashboard reports the watcher as ready. The same context stays open for
    # the watcher loop and is closed on every exit path.
    connector_stack = AsyncExitStack()
    try:
        connector = await connector_stack.enter_async_context(HttpJsonConnector(target))
        self_test = getattr(watcher, "self_test", None)
        if callable(self_test):
            self_test(connector)
        if not callable(getattr(connector, "send_prompt", None)) and not callable(
            getattr(connector, "send_message", None)
        ):
            raise RuntimeError("connector does not expose a prompt method")
        state.sentinel_status.update(
            {
                "running": True,
                "status": "RUNNING",
                "error": None,
                "error_id": None,
                "webhook_error": None,
                "target": target_url,
                "interval": interval,
                "canary_token": canary_token,
                "webhook_url": webhook_url,
            }
        )
        state.sentinel_status.setdefault("alerts", [])
        await event_bus.publish({"type": "sentinel:start", "data": state.sentinel_status})
    except Exception as error:
        await connector_stack.aclose()
        reference = str(uuid.uuid4())
        message = (
            str(error)
            if isinstance(error, SentinelProbeError)
            else (
                "Sentinel could not initialise the monitoring connector. "
                "Check the target configuration and restart monitoring."
            )
        )
        logger.error(
            "Sentinel watcher setup failed [reference {}]: {}",
            reference,
            type(error).__name__[:80],
        )
        state.sentinel_status.update(
            {
                "running": False,
                "status": "ERROR",
                "error": message,
                "error_id": reference,
                "webhook_error": None,
                "target": target_url,
                "interval": interval,
                "canary_token": canary_token,
                "webhook_url": webhook_url,
            }
        )
        diagnostic = {
            "running": False,
            "status": "ERROR",
            "error": message,
            "error_id": reference,
        }
        await event_bus.publish({"type": "sentinel:error", "data": diagnostic})
        return JSONResponse(diagnostic, status_code=502)

    async def _watcher_loop() -> None:
        def _callback(cycle: int, f_list: list[Finding]) -> None:
            state.sentinel_status["webhook_error"] = watcher.dispatcher.last_error
            status = "ALERT" if f_list else "PASS"
            recorded = state.record_sentinel_probe(status)
            record = {
                "timestamp": recorded["timestamp"],
                "cycle": cycle,
                "target": target_url,
                "findings_count": len(f_list),
                "status": status,
                "findings": [f.model_dump(mode="json") for f in f_list],
            }
            if f_list:
                state.record_sentinel_alert(record)
                asyncio.create_task(event_bus.publish({"type": "sentinel:alert", "data": record}))
            else:
                asyncio.create_task(event_bus.publish({"type": "sentinel:probe", "data": record}))

        try:
            await watcher.run_loop(connector, callback=_callback)
        except asyncio.CancelledError:
            raise
        except Exception as error:
            import httpx

            from agentscan.core.outcomes import ModuleUnavailableError, TargetRequestError

            reference = str(uuid.uuid4())
            message = "Sentinel monitoring failed. Review the diagnostic reference and restart after correcting the monitoring configuration."
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
            if isinstance(error, SentinelProbeError):
                state.record_sentinel_probe("ERROR", error=message, error_id=reference)
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
            try:
                await connector_stack.aclose()
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

    try:
        state.sentinel_task = asyncio.create_task(_watcher_loop())
    except Exception as error:
        await connector_stack.aclose()
        reference = str(uuid.uuid4())
        message = (
            "Sentinel could not start the monitoring loop. "
            "Review the diagnostic reference and restart monitoring."
        )
        logger.error(
            "Sentinel watcher task creation failed [reference {}]: {}",
            reference,
            type(error).__name__[:80],
        )
        state.sentinel_status.update(
            {"running": False, "status": "ERROR", "error": message, "error_id": reference}
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
        return JSONResponse(
            {
                "running": False,
                "status": "ERROR",
                "error": message,
                "error_id": reference,
            },
            status_code=502,
        )

    return JSONResponse(
        {
            "status": "started",
            "running": True,
            "canary_token": canary_token,
            "probes_run": state.sentinel_status.get("probes_run", 0),
            "probes_failed": state.sentinel_status.get("probes_failed", 0),
            "leaks_detected": state.sentinel_status.get("leaks_detected", 0),
        }
    )


@router.post("/api/sentinel/stop")
async def api_sentinel_stop() -> Any:
    task = state.sentinel_task
    if task and not task.done():
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
    state.sentinel_task = None
    state.sentinel_status["running"] = False
    state.sentinel_status["status"] = "STOPPED"
    await event_bus.publish({"type": "sentinel:stop", "data": {"running": False}})
    return JSONResponse({"status": "stopped", "running": False})
