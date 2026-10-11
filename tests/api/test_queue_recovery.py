from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock

import fakeredis.aioredis
import pytest
from redis.exceptions import ResponseError

from agentscan.api import queue


@pytest.fixture
async def redis_fixture(monkeypatch):
    server = fakeredis.FakeServer()
    clients = []

    async def connect():
        client = fakeredis.aioredis.FakeRedis(server=server, decode_responses=True)
        clients.append(client)
        return client

    monkeypatch.setattr(queue, "get_redis", connect)
    queue._reclaim_cursors.clear()
    await queue.ensure_consumer_groups()
    inspect = await connect()
    yield inspect
    for client in clients:
        await client.aclose()


async def test_every_nonempty_stream_job_is_returned(redis_fixture):
    streams = [queue.STREAM_HIGH, queue.STREAM_NORMAL, queue.STREAM_DEEP]
    for mode in ("EXPLOIT", "SCAN", "DEEP"):
        await queue.enqueue_scan({"scan_id": mode}, mode)
    first = await queue.claim_job("worker", streams=streams, block_ms=0)
    assert first[2]["scan_id"] == "EXPLOIT"
    pending = [await redis_fixture.xpending(stream, queue.CONSUMER_GROUP) for stream in streams]
    assert [item["pending"] for item in pending] == [1, 0, 0]
    rest = [await queue.claim_job("worker", streams=streams, block_ms=0) for _ in range(2)]
    assert {item[2]["scan_id"] for item in [first, *rest]} == {"EXPLOIT", "SCAN", "DEEP"}
    for item in [first, *rest]:
        await queue.ack_job(item[0], item[1])
    assert [await redis_fixture.xlen(stream) for stream in streams] == [0, 0, 0]


async def test_crashed_consumer_delivery_reclaimed(redis_fixture):
    await queue.enqueue_scan({"scan_id": "recover-me"})
    first = await queue.claim_job("crashed", streams=[queue.STREAM_NORMAL], block_ms=0, lease_ms=1)
    await asyncio.sleep(0.03)
    recovered = await queue.claim_job(
        "replacement", streams=[queue.STREAM_NORMAL], block_ms=0, lease_ms=1
    )
    assert recovered == first
    pending = await redis_fixture.xpending_range(
        queue.STREAM_NORMAL, queue.CONSUMER_GROUP, "-", "+", 10
    )
    assert pending[0]["consumer"] == "replacement"


async def test_heartbeat_prevents_immediate_reclaim(redis_fixture):
    await queue.enqueue_scan({"scan_id": "active"})
    first = await queue.claim_job("active", streams=[queue.STREAM_NORMAL], block_ms=0)
    assert await queue.heartbeat_job(first[0], first[1], "active")
    assert (
        await queue.claim_job("other", streams=[queue.STREAM_NORMAL], block_ms=0, lease_ms=10000)
        is None
    )


async def test_group_permission_failure_is_not_suppressed(monkeypatch):
    redis = AsyncMock()
    redis.xgroup_create.side_effect = ResponseError("NOPERM group create denied")
    monkeypatch.setattr(queue, "get_redis", AsyncMock(return_value=redis))
    with pytest.raises(ResponseError, match="NOPERM"):
        await queue.ensure_consumer_groups()
    redis.aclose.assert_awaited_once()


async def test_quarantine_receipt_precedes_cleanup(redis_fixture):
    entry = await redis_fixture.xadd(queue.STREAM_NORMAL, {"payload": "not-json"})
    claimed = await queue.claim_job("worker", streams=[queue.STREAM_NORMAL], block_ms=0)
    assert "_invalid_payload" in claimed[2]
    await queue.quarantine_job(queue.STREAM_NORMAL, entry, "Malformed envelope")
    assert await redis_fixture.xlen(queue.STREAM_DEAD) == 1
    assert (await redis_fixture.xpending(queue.STREAM_NORMAL, queue.CONSUMER_GROUP))["pending"] == 0
