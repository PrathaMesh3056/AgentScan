# agentscan/api/pubsub.py
#
# Redis pub/sub channel for real-time scan progress events.
# The worker publishes progress events; the API SSE endpoint subscribes.

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import Any

from agentscan.api.queue import REDIS_URL

CHANNEL_PREFIX = "agentscan:progress:"


def _channel(scan_id: str) -> str:
    return f"{CHANNEL_PREFIX}{scan_id}"


async def publish_progress(scan_id: str, event: dict[str, Any]) -> None:
    """Publish a progress event dict to the scan's Redis channel."""
    import redis.asyncio as aioredis  # type: ignore[import-untyped]

    r = aioredis.from_url(
        REDIS_URL, decode_responses=True, socket_connect_timeout=2, socket_timeout=2
    )
    try:
        await r.publish(_channel(scan_id), json.dumps(event))
    finally:
        await r.aclose()


async def subscribe_progress(scan_id: str) -> AsyncIterator[dict[str, Any]]:
    """
    Async generator that yields progress event dicts for a scan.
    Yields until a 'completed' or 'failed' event is received.
    """
    import redis.asyncio as aioredis  # type: ignore[import-untyped]

    r = aioredis.from_url(REDIS_URL, decode_responses=True, socket_connect_timeout=2)
    pubsub = r.pubsub()
    try:
        await pubsub.subscribe(_channel(scan_id))
        while True:
            message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=2)
            if message is None:
                yield {"event": "heartbeat"}
                continue
            event = json.loads(message["data"])
            yield event
            if event.get("status") in ("completed", "inconclusive", "failed", "cancelled"):
                break
    finally:
        try:
            await pubsub.aclose()
        finally:
            await r.aclose()
