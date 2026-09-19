# agentscan/api/queue.py
#
# Redis Streams task queue for AgentScan scan jobs.
#
# Three streams (priority queues):
#   agentscan:scan:high   — EXPLOIT/DEEP priority scans
#   agentscan:scan:normal — standard SCAN mode
#   agentscan:scan:deep   — DEEP mode (routed to GPU workers)
#
# Consumer group name: agentscan-workers
# Each worker calls claim_job() in a loop, calls run_scan(), writes result to DB.

from __future__ import annotations

import contextlib
import json
import os
from typing import Any

REDIS_URL = os.environ.get("AGENTSCAN_REDIS_URL", "redis://localhost:6379/0")

STREAM_HIGH = "agentscan:scan:high"
STREAM_NORMAL = "agentscan:scan:normal"
STREAM_DEEP = "agentscan:scan:deep"
CONSUMER_GROUP = "agentscan-workers"


def _stream_for_mode(scan_mode: str) -> str:
    if scan_mode.upper() == "DEEP":
        return STREAM_DEEP
    if scan_mode.upper() in ("EXPLOIT",):
        return STREAM_HIGH
    return STREAM_NORMAL


async def get_redis():
    """Return an async Redis client. Import here to keep it optional."""
    import redis.asyncio as aioredis  # type: ignore[import-untyped]

    return await aioredis.from_url(REDIS_URL, decode_responses=True)


async def enqueue_scan(job: dict[str, Any], scan_mode: str = "SCAN") -> str:
    """
    Push a scan job onto the appropriate Redis Stream.

    job must contain at least:
        scan_id    str
        tenant_id  str
        target     dict  (serialised Target)

    Returns the Redis stream entry ID.
    """
    r = await get_redis()
    stream = _stream_for_mode(scan_mode)
    entry_id = await r.xadd(stream, {"payload": json.dumps(job)})
    await r.aclose()
    return entry_id


async def ensure_consumer_groups() -> None:
    """Create consumer groups on all three streams if they don't exist."""
    r = await get_redis()
    for stream in (STREAM_HIGH, STREAM_NORMAL, STREAM_DEEP):
        with contextlib.suppress(Exception):
            await r.xgroup_create(stream, CONSUMER_GROUP, id="0", mkstream=True)
    await r.aclose()


async def claim_job(
    consumer_name: str,
    streams: list[str] | None = None,
    block_ms: int = 5000,
) -> tuple[str, str, dict[str, Any]] | None:
    """
    Block-read one job from the streams in priority order.

    Returns (stream_name, entry_id, job_dict) or None on timeout.
    """
    if streams is None:
        streams = [STREAM_HIGH, STREAM_NORMAL, STREAM_DEEP]

    r = await get_redis()
    try:
        stream_ids = {s: ">" for s in streams}
        result = await r.xreadgroup(
            groupname=CONSUMER_GROUP,
            consumername=consumer_name,
            streams=stream_ids,
            count=1,
            block=block_ms,
        )
        if not result:
            return None
        stream_name, entries = result[0]
        entry_id, fields = entries[0]
        job = json.loads(fields["payload"])
        return stream_name, entry_id, job
    finally:
        await r.aclose()


async def ack_job(stream_name: str, entry_id: str) -> None:
    """Acknowledge a completed job so Redis removes it from the PEL."""
    r = await get_redis()
    await r.xack(stream_name, CONSUMER_GROUP, entry_id)
    await r.aclose()
