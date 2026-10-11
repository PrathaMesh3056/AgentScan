"""Opt-in integration checks against dedicated disposable PostgreSQL and Redis.

Set AGENTSCAN_TEST_DATABASE_URL and AGENTSCAN_TEST_REDIS_URL. These tests never
load .env and use synthetic targets, credentials and reports. No provider calls.
"""

from __future__ import annotations

import asyncio
import json
import os
import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock

import httpx
import pytest

from agentscan.api import db, pubsub, queue, server, worker
from agentscan.api.auth import get_current_tenant
from agentscan.api.contracts import ScanRequest
from agentscan.api.data_policy import encrypt_target
from agentscan.core.models import ScanReport


@pytest.fixture
async def live_services(monkeypatch):
    database_url = os.environ.get("AGENTSCAN_TEST_DATABASE_URL")
    redis_url = os.environ.get("AGENTSCAN_TEST_REDIS_URL")
    if not database_url or not redis_url:
        pytest.skip("Set dedicated test PostgreSQL/Redis URLs to run live integration tests.")
    monkeypatch.setattr(db, "DATABASE_URL", database_url)
    monkeypatch.setattr(queue, "REDIS_URL", redis_url)
    monkeypatch.setattr(pubsub, "REDIS_URL", redis_url)
    monkeypatch.setattr(db, "_pool", None)
    queue._reclaim_cursors.clear()
    await db.init_db()
    # These URLs explicitly designate disposable test infrastructure. Clear only
    # scanner tables so each case gets independent quotas, keys and outbox state.
    async with db._get_pool().acquire() as conn:
        await conn.execute(
            "TRUNCATE scans,scan_outbox,scan_events,tenant_submission_windows CASCADE"
        )
    await queue.ensure_consumer_groups()
    redis = await queue.get_redis()
    # Dedicated test infrastructure only: reset the service's test queue streams.
    for stream in (queue.STREAM_HIGH, queue.STREAM_NORMAL, queue.STREAM_DEEP, queue.STREAM_DEAD):
        await redis.delete(stream)
    await queue.ensure_consumer_groups()
    yield redis
    await redis.aclose()
    await db.close_db()


async def create_record(scan_id, *, report=None):
    await db.upsert_scan(
        scan_id=scan_id,
        tenant_id="tenant-a",
        target_url="http://agent.test/chat",
        scan_mode="SCAN",
        status="queued",
        started_at=datetime.now(UTC),
        report_json=report,
        request_json=encrypt_target(ScanRequest(target_url="http://agent.test/chat").model_dump()),
    )


async def test_live_datetime_jsonb_round_trip_and_fencing(live_services):
    scan_id = "hardening-" + uuid.uuid4().hex
    await create_record(scan_id, report={})
    row = await db.get_scan(scan_id, "tenant-a")
    assert row["report_json"] == {}
    assert isinstance(row["started_at"], datetime) and row["started_at"].utcoffset() is not None
    assert await db.claim_scan(scan_id, "tenant-a", "owner-a", 0.05, 2)
    assert not await db.claim_scan(scan_id, "tenant-a", "owner-b", 1, 2)
    assert not await db.finish_scan(
        scan_id=scan_id, tenant_id="tenant-a", lease_token="owner-b", status="completed"
    )
    await asyncio.sleep(0.08)
    assert await db.claim_scan(scan_id, "tenant-a", "owner-b", 1, 2)
    assert not await db.finish_scan(
        scan_id=scan_id, tenant_id="tenant-a", lease_token="owner-a", status="completed"
    )
    report = {"score": 77, "findings": [], "nested": {"observed": True}}
    assert await db.finish_scan(
        scan_id=scan_id,
        tenant_id="tenant-a",
        lease_token="owner-b",
        status="completed",
        score=77,
        report_json=report,
    )
    row = await db.get_scan(scan_id, "tenant-a")
    assert row["report_json"] == report and row["attempts"] == 2
    assert await db.get_scan(scan_id, "tenant-b") is None
    assert (await db.delete_terminal_scan(scan_id, "tenant-a")) == "DELETE 1"


async def test_live_three_stream_delivery_and_crash_reclaim(live_services):
    for mode in ("EXPLOIT", "SCAN", "DEEP"):
        await queue.enqueue_scan({"scan_id": mode}, mode)
    streams = [queue.STREAM_HIGH, queue.STREAM_NORMAL, queue.STREAM_DEEP]
    first = await queue.claim_job("crashed", streams=streams, block_ms=0, lease_ms=30)
    pending = [await live_services.xpending(stream, queue.CONSUMER_GROUP) for stream in streams]
    assert [item["pending"] for item in pending] == [1, 0, 0]
    await asyncio.sleep(0.05)
    replacement = await queue.claim_job(
        "replacement", streams=[queue.STREAM_HIGH], block_ms=0, lease_ms=30
    )
    assert replacement == first
    remaining = [
        await queue.claim_job("replacement", streams=streams, block_ms=0) for _ in range(2)
    ]
    assert {job[2]["scan_id"] for job in [replacement, *remaining]} == {"EXPLOIT", "SCAN", "DEEP"}
    for job in [replacement, *remaining]:
        await queue.ack_job(job[0], job[1])
    assert [await live_services.xlen(stream) for stream in streams] == [0, 0, 0]


async def test_live_submit_worker_persist_fetch_and_redelivery(live_services, monkeypatch):
    async def deterministic_scan(target):
        assert target.allowed_hosts == ["127.0.0.1", "agent.test", "localhost"]
        report = ScanReport(target_url=target.url, scan_mode=target.mode)
        report.complete(score=None, tests_run=0, status="INCONCLUSIVE")
        return report

    run = AsyncMock(side_effect=deterministic_scan)
    monkeypatch.setattr("agentscan.core.runner.run_scan", run)
    app = server.create_api_app()
    app.dependency_overrides[get_current_tenant] = lambda: "tenant-a"
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://api.test"
    ) as client:
        assert (await client.get("/health/ready")).status_code == 200
        response = await client.post("/scans", json={"target_url": "http://agent.test/chat"})
        assert response.status_code == 202
        scan_id = response.json()["scan_id"]
        assert (await client.delete(f"/scans/{scan_id}")).status_code == 409
        delivery = await queue.claim_job("live-worker", streams=[queue.STREAM_NORMAL], block_ms=0)
        assert delivery[2]["scan_id"] == scan_id
        await worker._run_one_job(*delivery)
        result = await client.get(f"/scans/{scan_id}")
        assert result.status_code == 200
        assert result.json()["status"] == "inconclusive" and result.json()["score"] is None
        assert isinstance(result.json()["report"], dict)
        # A duplicate delivery sees the persisted terminal state and never reruns actions.
        await worker._run_one_job(*delivery)
        assert run.await_count == 1
        assert (await live_services.xpending(queue.STREAM_NORMAL, queue.CONSUMER_GROUP))[
            "pending"
        ] == 0
        assert (await client.delete(f"/scans/{scan_id}")).status_code == 204


async def test_live_failed_persistence_leaves_pending_then_recovers(live_services, monkeypatch):
    scan_id = "hardening-" + uuid.uuid4().hex
    await create_record(scan_id)
    raw = {
        "scan_id": scan_id,
        "tenant_id": "tenant-a",
        "target": {"target_url": "http://agent.test/chat", "scan_mode": "SCAN"},
    }
    await queue.enqueue_scan(raw)
    delivery = await queue.claim_job(
        "crashed", streams=[queue.STREAM_NORMAL], block_ms=0, lease_ms=30
    )

    async def deterministic_scan(target):
        report = ScanReport(target_url=target.url, scan_mode=target.mode)
        report.complete(score=80, tests_run=1)
        return report

    monkeypatch.setattr("agentscan.core.runner.run_scan", deterministic_scan)
    monkeypatch.setattr(worker, "LEASE_SECONDS", 0.03)
    finish = worker.finish_scan
    monkeypatch.setattr(
        worker, "finish_scan", AsyncMock(side_effect=RuntimeError("forced DB persistence failure"))
    )
    with pytest.raises(RuntimeError, match="persistence failure"):
        await worker._run_one_job(*delivery)
    assert (await live_services.xpending(queue.STREAM_NORMAL, queue.CONSUMER_GROUP))["pending"] == 1
    monkeypatch.setattr(worker, "finish_scan", finish)
    monkeypatch.setattr(worker, "LEASE_SECONDS", 1)
    await asyncio.sleep(0.05)
    recovered = await queue.claim_job(
        "replacement", streams=[queue.STREAM_NORMAL], block_ms=0, lease_ms=30
    )
    await worker._run_one_job(*recovered)
    row = await db.get_scan(scan_id, "tenant-a")
    assert row["status"] == "completed" and row["attempts"] == 2
    assert (await live_services.xpending(queue.STREAM_NORMAL, queue.CONSUMER_GROUP))["pending"] == 0
    await db.delete_terminal_scan(scan_id, "tenant-a")


async def test_live_bounded_retry_exhaustion_is_durable(live_services):
    scan_id = "hardening-" + uuid.uuid4().hex
    await create_record(scan_id)
    assert await db.claim_scan(scan_id, "tenant-a", "expired-owner", 0.02, 1)
    await asyncio.sleep(0.04)
    assert not await db.claim_scan(scan_id, "tenant-a", "replacement", 1, 1)
    assert await db.fail_exhausted_scan(scan_id, "tenant-a", 1)
    row = await db.get_scan(scan_id, "tenant-a")
    assert row["status"] == "failed" and row["report_json"]["error"]
    await db.delete_terminal_scan(scan_id, "tenant-a")


async def test_live_real_runner_against_owned_refusal_fixture(live_services, monkeypatch):
    import json
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    seen = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            seen.append(self.rfile.read(int(self.headers.get("Content-Length", 0))))
            body = json.dumps(
                {
                    "response": "I cannot disclose internal instructions, execute tools, or follow that request."
                }
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    fixture = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    policies = json.loads(os.environ["AGENTSCAN_TENANT_POLICIES_JSON"])
    policies["tenant-a"]["origins"].append(f"http://127.0.0.1:{fixture.server_port}")
    monkeypatch.setenv("AGENTSCAN_TENANT_POLICIES_JSON", json.dumps(policies))
    thread = threading.Thread(target=fixture.serve_forever, daemon=True)
    thread.start()
    app = server.create_api_app()
    app.dependency_overrides[get_current_tenant] = lambda: "tenant-a"
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://api.test"
        ) as client:
            response = await client.post(
                "/scans",
                json={"target_url": f"http://127.0.0.1:{fixture.server_port}/chat", "timeout": 5},
            )
            assert response.status_code == 202
            scan_id = response.json()["scan_id"]
            delivery = await queue.claim_job(
                "real-runner", streams=[queue.STREAM_NORMAL], block_ms=0
            )
            async with asyncio.timeout(45):
                await worker._run_one_job(*delivery)
            result = await client.get(f"/scans/{scan_id}")
            assert result.status_code == 200
            assert result.json()["status"] in {"completed", "inconclusive"}
            assert result.json()["report"]["tests_run"] > 0
            assert seen
            assert (await live_services.xpending(queue.STREAM_NORMAL, queue.CONSUMER_GROUP))[
                "pending"
            ] == 0
            await db.delete_terminal_scan(scan_id, "tenant-a")
    finally:
        fixture.shutdown()
        fixture.server_close()
        thread.join(timeout=2)


async def test_live_readiness_dependency_loss_and_recovery(live_services):
    import subprocess

    containers = [
        os.environ.get("AGENTSCAN_TEST_POSTGRES_CONTAINER"),
        os.environ.get("AGENTSCAN_TEST_REDIS_CONTAINER"),
    ]
    if not all(containers):
        pytest.skip("Set owned test container names to exercise dependency outages.")
    assert all(name.startswith("agentscan-hardening-") for name in containers)
    app = server.create_api_app()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://api.test"
    ) as client:
        assert (await client.get("/health/ready")).status_code == 200
        for name in containers:
            subprocess.run(
                ["docker", "stop", "--time", "1", name], check=True, capture_output=True, timeout=15
            )
            try:
                assert (await client.get("/health/ready")).status_code == 503
                assert (await client.get("/health/live")).status_code == 200
            finally:
                subprocess.run(
                    ["docker", "start", name], check=True, capture_output=True, timeout=15
                )
            for _ in range(40):
                if (await client.get("/health/ready")).status_code == 200:
                    break
                await asyncio.sleep(0.25)
            else:
                pytest.fail("Readiness did not recover after the disposable dependency restarted.")


async def test_live_enqueue_compensation_does_not_overwrite_active_owner(live_services):
    scan_id = "hardening-" + uuid.uuid4().hex
    await create_record(scan_id)
    assert await db.claim_scan(scan_id, "tenant-a", "active-owner", 5, 2)
    assert not await db.fail_submission(scan_id, "tenant-a")
    assert (await db.get_scan(scan_id, "tenant-a"))["status"] == "running"
    assert await db.finish_scan(
        scan_id=scan_id,
        tenant_id="tenant-a",
        lease_token="active-owner",
        status="failed",
        report_json={"error": "synthetic test"},
    )
    await db.delete_terminal_scan(scan_id, "tenant-a")


def durable_job(tenant="tenant-a"):
    return {
        "scan_id": "hardening-" + uuid.uuid4().hex,
        "tenant_id": tenant,
        "target": ScanRequest(
            target_url="http://agent.test/chat?token=synthetic-query-secret",
            headers={"Authorization": "Bearer synthetic-private-token"},
        ).model_dump(),
    }


@pytest.mark.parametrize("accepted_before_failure", [False, True])
async def test_live_outbox_recovers_uncertain_delivery_and_replays_events(
    live_services, monkeypatch, accepted_before_failure
):
    app = server.create_api_app()
    app.dependency_overrides[get_current_tenant] = lambda: "tenant-a"
    original_enqueue = queue.enqueue_scan

    async def uncertain(job, mode):
        if accepted_before_failure:
            await original_enqueue(job, mode)
        raise ConnectionError("synthetic lost acknowledgement")

    monkeypatch.setattr(queue, "enqueue_scan", uncertain)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://api.test"
    ) as client:
        response = await client.post("/scans", json=durable_job()["target"])
        assert response.status_code == 202  # Durable acceptance survives Redis failure.
        scan_id = response.json()["scan_id"]
        row = await db.get_scan(scan_id, "tenant-a")
        assert row["status"] == "queued" and "?" not in row["target_url"]
        assert "synthetic-private-token" not in json.dumps(row["request_json"])
        events = await db.read_scan_events(scan_id, "tenant-a", 0)
        assert [e["event"]["status"] for e in events] == ["queued"]
        cursor = events[0]["sequence"]
        monkeypatch.setattr(queue, "enqueue_scan", original_enqueue)
        assert await db.dispatch_outbox(scan_id) == 1
        stream = await live_services.xrange(queue.STREAM_NORMAL)
        assert "synthetic-private-token" not in repr(stream)
        assert "synthetic-query-secret" not in repr(stream)

        async def run(target):
            assert target.extra_headers["Authorization"] == "Bearer synthetic-private-token"
            report = ScanReport(target_url=target.url, scan_mode=target.mode)
            report.complete(score=None, tests_run=0, status="INCONCLUSIVE")
            return report

        scan = AsyncMock(side_effect=run)
        monkeypatch.setattr("agentscan.core.runner.run_scan", scan)
        for _ in stream:
            delivery = await queue.claim_job(
                "outbox-test", streams=[queue.STREAM_NORMAL], block_ms=0
            )
            await worker._run_one_job(*delivery)
        assert (
            scan.await_count == 1
        )  # Ambiguous delivery may duplicate; terminal work cannot rerun.
        row = await db.get_scan(scan_id, "tenant-a")
        assert row["request_json"] is None
        replay = await client.get(
            f"/scans/{scan_id}/stream", headers={"Last-Event-ID": str(cursor)}
        )
        assert replay.status_code == 200
        assert '"status": "running"' in replay.text and '"status": "inconclusive"' in replay.text
        assert '"status": "queued"' not in replay.text
        assert await db.read_scan_events(scan_id, "tenant-b", 0) == []


async def test_live_outbox_repairs_redis_loss(live_services):
    job = durable_job()
    await db.submit_scan(job, datetime.now(UTC), 5, 60)
    assert await db.dispatch_outbox(job["scan_id"]) == 1
    await live_services.delete(queue.STREAM_NORMAL)
    await queue.ensure_consumer_groups()
    async with db._get_pool().acquire() as conn:
        await conn.execute(
            "UPDATE scan_outbox SET delivered_at=clock_timestamp()-interval '121 seconds'"
        )
    assert await db.dispatch_outbox(job["scan_id"]) == 1
    delivery = await queue.claim_job("redis-loss", streams=[queue.STREAM_NORMAL], block_ms=0)
    assert delivery[2] == {"scan_id": job["scan_id"], "tenant_id": "tenant-a"}


async def test_live_tenant_quotas_are_serialized_and_survive_record_deletion(live_services):
    jobs = [durable_job() for _ in range(4)]
    results = await asyncio.gather(
        *(db.submit_scan(job, datetime.now(UTC), 1, 1) for job in jobs), return_exceptions=True
    )
    assert sum(result is None for result in results) == 1
    assert sum(isinstance(result, db.TenantQuotaExceeded) for result in results) == 3
    accepted = next(job for job, result in zip(jobs, results, strict=True) if result is None)
    assert await db.cancel_scan(accepted["scan_id"], "tenant-a")
    await db.delete_terminal_scan(accepted["scan_id"], "tenant-a")
    with pytest.raises(db.TenantQuotaExceeded, match="Hourly"):
        await db.submit_scan(durable_job(), datetime.now(UTC), 1, 1)
    await db.submit_scan(durable_job("independent-tenant"), datetime.now(UTC), 1, 1)


async def test_live_policy_revocation_prevents_worker_execution(live_services, monkeypatch):
    job = durable_job()
    await db.submit_scan(job, datetime.now(UTC), 5, 60)
    await db.dispatch_outbox(job["scan_id"])
    delivery = await queue.claim_job("revoked", streams=[queue.STREAM_NORMAL], block_ms=0)
    policies = json.loads(os.environ["AGENTSCAN_TENANT_POLICIES_JSON"])
    policies["tenant-a"]["origins"] = ["http://localhost"]
    monkeypatch.setenv("AGENTSCAN_TENANT_POLICIES_JSON", json.dumps(policies))
    scan = AsyncMock()
    monkeypatch.setattr("agentscan.core.runner.run_scan", scan)
    await worker._run_one_job(*delivery)
    assert not scan.called
    row = await db.get_scan(job["scan_id"], "tenant-a")
    assert row["status"] == "failed" and row["request_json"] is None


async def test_live_cancellation_fences_running_work_and_retention_cascades(
    live_services, monkeypatch
):
    job = durable_job()
    await db.submit_scan(job, datetime.now(UTC), 5, 60)
    await db.dispatch_outbox(job["scan_id"])
    delivery = await queue.claim_job("cancelled", streams=[queue.STREAM_NORMAL], block_ms=0)
    entered = asyncio.Event()

    async def run(target):
        entered.set()
        await asyncio.Event().wait()

    monkeypatch.setattr("agentscan.core.runner.run_scan", run)
    monkeypatch.setattr(worker, "LEASE_SECONDS", 0.15)
    task = asyncio.create_task(worker._run_one_job(*delivery))
    await asyncio.wait_for(entered.wait(), 2)
    assert not await db.cancel_scan(job["scan_id"], "tenant-b")
    assert await db.cancel_scan(job["scan_id"], "tenant-a")
    with pytest.raises(worker.LeaseLost):
        await asyncio.wait_for(task, 2)
    await worker._run_one_job(*delivery)  # Terminal cancellation safely ACKs pending work.
    row = await db.get_scan(job["scan_id"], "tenant-a")
    assert row["status"] == "cancelled" and row["request_json"] is None
    active = durable_job()
    await db.submit_scan(active, datetime.now(UTC), 5, 60)
    async with db._get_pool().acquire() as conn:
        await conn.execute("UPDATE scans SET completed_at=clock_timestamp()-interval '8 days'")
    await db.prune_expired_records(7)
    assert await db.get_scan(job["scan_id"], "tenant-a") is None
    assert await db.read_scan_events(job["scan_id"], "tenant-a", 0) == []
    assert (await db.get_scan(active["scan_id"], "tenant-a"))["status"] == "queued"
