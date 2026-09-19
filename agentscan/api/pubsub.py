# agentscan/api/pubsub.py
#
# Redis pub/sub channel for real-time scan progress events.
# The worker publishes progress events; the API SSE endpoint subscribes.

from __future__ import annotations

import json
from typing import Any

from agentscan.api.queue import REDIS_URL

CHANNEL_PREFIX = "agentscan:progress:"


def _channel(scan_id: str) -> str:
    return f"{CHANNEL_PREFIX}{scan_id}"


async def publish_progress(scan_id: str, event: dict[str, Any]) -> None:
    """Publish a progress event dict to the scan's Redis channel."""
    import redis.asyncio as aioredis  # type: ignore[import-untyped]

    r = await aioredis.from_url(REDIS_URL, decode_responses=True)
    await r.publish(_channel(scan_id), json.dumps(event))
    await r.close()


async def subscribe_progress(scan_id: str):
    """
    Async generator that yields progress event dicts for a scan.
    Yields until a 'completed' or 'failed' event is received.
    """
    import redis.asyncio as aioredis  # type: ignore[import-untyped]

    r = await aioredis.from_url(REDIS_URL, decode_responses=True)
    pubsub = r.pubsub()
    await pubsub.subscribe(_channel(scan_id))
    try:
        async for message in pubsub.listen():
            if message["type"] != "message":
                continue
            event = json.loads(message["data"])
            yield event
            if event.get("status") in ("completed", "failed"):
                break
    finally:
        await pubsub.unsubscribe(_channel(scan_id))
        await pubsub.close()
        await r.close()
