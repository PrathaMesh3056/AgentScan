"""Redis Streams delivery: one returned job per read, reclaim, and explicit cleanup."""

from __future__ import annotations

import asyncio
import json
import os
from typing import Any, cast

from redis.asyncio import Redis
from redis.exceptions import ResponseError

REDIS_URL = os.environ.get("AGENTSCAN_REDIS_URL", "redis://localhost:6379/0")
STREAM_HIGH = "agentscan:scan:high"
STREAM_NORMAL = "agentscan:scan:normal"
STREAM_DEEP = "agentscan:scan:deep"
STREAM_DEAD = "agentscan:scan:dead"
CONSUMER_GROUP = "agentscan-workers"
_reclaim_cursors: dict[tuple[str, str], str] = {}


def _stream_for_mode(scan_mode: str) -> str:
    return (
        STREAM_DEEP
        if scan_mode == "DEEP"
        else STREAM_HIGH
        if scan_mode == "EXPLOIT"
        else STREAM_NORMAL
    )


async def get_redis() -> Redis:
    return Redis.from_url(
        REDIS_URL, decode_responses=True, socket_timeout=10.0, socket_connect_timeout=2.0
    )


async def check_redis() -> None:
    r = await get_redis()
    try:
        await r.ping()
    finally:
        await r.aclose()


async def enqueue_scan(job: dict[str, Any], scan_mode: str = "SCAN") -> str:
    r = await get_redis()
    try:
        return cast(str, await r.xadd(_stream_for_mode(scan_mode), {"payload": json.dumps(job)}))
    finally:
        await r.aclose()


async def ensure_consumer_groups() -> None:
    r = await get_redis()
    try:
        for stream in (STREAM_HIGH, STREAM_NORMAL, STREAM_DEEP):
            try:
                await r.xgroup_create(stream, CONSUMER_GROUP, id="0", mkstream=True)
            except ResponseError as exc:
                if not str(exc).startswith("BUSYGROUP"):
                    raise
    finally:
        await r.aclose()


def _decode_job(fields: dict[str, str]) -> dict[str, Any]:
    try:
        decoded = json.loads(fields.get("payload", ""))
        if isinstance(decoded, dict):
            return decoded
    except (ValueError, TypeError):
        pass
    return {"_invalid_payload": fields.get("payload", "")[:4096]}


async def claim_job(
    consumer_name: str,
    streams: list[str] | None = None,
    block_ms: int = 5000,
    lease_ms: int = 60000,
) -> tuple[str, str, dict[str, Any]] | None:
    """Read each stream separately; COUNT applies per stream in Redis.

    Reclaim idle deliveries before fresh ones. The caller rotates stream order for
    fairness. Returned entries remain pending until durable completion and ACK.
    Redis 6.2+ is required for XAUTOCLAIM.
    """
    streams = streams or [STREAM_HIGH, STREAM_NORMAL, STREAM_DEEP]
    deadline = asyncio.get_running_loop().time() + block_ms / 1000
    r = await get_redis()
    try:
        while True:
            for stream in streams:
                cursor_key = (consumer_name, stream)
                reclaimed = await r.xautoclaim(
                    stream,
                    CONSUMER_GROUP,
                    consumer_name,
                    min_idle_time=lease_ms,
                    start_id=_reclaim_cursors.get(cursor_key, "0-0"),
                    count=1,
                )
                _reclaim_cursors[cursor_key] = reclaimed[0]
                if reclaimed[1]:
                    entry_id, fields = reclaimed[1][0]
                    return stream, entry_id, _decode_job(fields)
                # decode_responses=True gives the RESP stream list with string IDs
                # and fields. Redis stubs also describe the incompatible RESP3 map.
                result = cast(
                    list[tuple[str, list[tuple[str, dict[str, str]]]]],
                    await r.xreadgroup(CONSUMER_GROUP, consumer_name, {stream: ">"}, count=1),
                )
                if result:
                    entry_id, fields = result[0][1][0]
                    return stream, entry_id, _decode_job(fields)
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                return None
            await asyncio.sleep(min(0.1, remaining))
    finally:
        await r.aclose()


async def heartbeat_job(stream_name: str, entry_id: str, consumer_name: str) -> bool:
    r = await get_redis()
    try:
        return bool(
            await r.xclaim(
                stream_name,
                CONSUMER_GROUP,
                consumer_name,
                min_idle_time=0,
                message_ids=[entry_id],
                justid=True,
            )
        )
    finally:
        await r.aclose()


async def ack_job(stream_name: str, entry_id: str) -> None:
    """ACK and remove the completed entry. This service uses a single consumer group."""
    r = await get_redis()
    try:
        async with r.pipeline(transaction=True) as pipe:
            pipe.xack(stream_name, CONSUMER_GROUP, entry_id)
            pipe.xdel(stream_name, entry_id)
            await pipe.execute()
    finally:
        await r.aclose()


async def quarantine_job(stream_name: str, entry_id: str, reason: str) -> None:
    """Persist a bounded malformed-delivery receipt before ACK, retaining its source ID."""
    r = await get_redis()
    try:
        async with r.pipeline(transaction=True) as pipe:
            pipe.xadd(
                STREAM_DEAD,
                {"stream": stream_name, "entry_id": entry_id, "reason": reason[:1000]},
                maxlen=1000,
                approximate=True,
            )
            pipe.xack(stream_name, CONSUMER_GROUP, entry_id)
            pipe.xdel(stream_name, entry_id)
            await pipe.execute()
    finally:
        await r.aclose()
