# agentscan/ui/routers/events.py
#
# SSE real-time event streaming and event publication endpoints.

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncGenerator
from typing import Any

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse, StreamingResponse
from loguru import logger

from agentscan.ui.state import event_bus, state
from agentscan.ui.validation import Fields

router = APIRouter(tags=["events"])


@router.get("/api/events")
async def api_events(limit: int | None = Query(default=None, ge=1, le=10000)) -> Any:
    """Stream real-time scan findings, traffic, and sentinel alerts via SSE."""
    q = event_bus.subscribe()

    async def event_generator() -> AsyncGenerator[str, None]:
        count = 0
        try:
            # Send initial ping event to confirm connection
            yield "event: ping\ndata: {}\n\n"
            count += 1
            if limit is not None and count >= limit:
                return

            while True:
                try:
                    event = await asyncio.wait_for(q.get(), timeout=15.0)
                    event_type = event.get("type", "message")
                    data_str = json.dumps(event.get("data", {}))
                    yield f"event: {event_type}\ndata: {data_str}\n\n"
                    count += 1
                    if limit is not None and count >= limit:
                        return
                except TimeoutError:
                    yield ": keep-alive\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            event_bus.unsubscribe(q)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.post("/api/events")
@router.post("/api/telemetry/events")
async def api_publish_event(payload: dict[str, Any]) -> Any:
    fields = Fields(payload)
    event_type = fields.text("type", required=True, max_length=128, aliases=("event",))
    data = fields.object("data")
    if event_type and not all(c.isascii() and (c.isalnum() or c in "_:.-") for c in event_type):
        fields.errors["type"] = (
            "Use an event name containing letters, numbers, underscores, colons, dots or hyphens."
        )
    if error_response := fields.response():
        return error_response
    payload = {"type": event_type, "data": data}
    logger.debug("Internal event published via POST /api/events")
    await event_bus.publish(payload)
    return JSONResponse({"status": "ok"})


@router.post("/api/reload")
async def api_reload() -> Any:
    if state.report_path:
        state.load_report(state.report_path)
        await event_bus.publish({"type": "reload", "data": {"status": "reloaded"}})
    return JSONResponse({"status": "reloaded"})
