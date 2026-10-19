from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from agentscan.api import worker
from agentscan.api.contracts import ScanRequest
from agentscan.api.data_policy import encrypt_target


@pytest.fixture
async def job_fixture(monkeypatch):
    job = {
        "scan_id": "scan-a",
        "tenant_id": "tenant-a",
        "target": {"target_url": "http://agent.test/chat", "scan_mode": "SCAN"},
    }
    row = {
        "scan_id": "scan-a",
        "tenant_id": "tenant-a",
        "target_url": "http://agent.test/chat",
        "scan_mode": "SCAN",
        "status": "queued",
        "request_json": encrypt_target(ScanRequest.model_validate(job["target"]).model_dump()),
    }
    monkeypatch.setattr(worker, "get_scan", AsyncMock(return_value=row))
    monkeypatch.setattr(worker, "claim_scan", AsyncMock(return_value=True))
    monkeypatch.setattr(worker, "finish_scan", AsyncMock(return_value=True))
    monkeypatch.setattr(worker, "renew_scan_lease", AsyncMock(return_value=True))
    monkeypatch.setattr(worker, "heartbeat_job", AsyncMock(return_value=True))
    monkeypatch.setattr(worker, "ack_job", AsyncMock())
    monkeypatch.setattr(worker, "publish_progress", AsyncMock())
    monkeypatch.setattr(worker, "fail_exhausted_scan", AsyncMock(return_value=False))
    report = SimpleNamespace(
        status="COMPLETE", score=91, model_dump=lambda **_: {"score": 91, "status": "COMPLETE"}
    )
    runner = AsyncMock(return_value=report)
    monkeypatch.setattr("agentscan.core.runner.run_scan", runner)
    return job, row, runner


async def test_result_persistence_failure_retains_delivery(job_fixture):
    job, _, runner = job_fixture
    worker.finish_scan.side_effect = RuntimeError("database unavailable")
    with pytest.raises(RuntimeError, match="database unavailable"):
        await worker._run_one_job("stream", "1-0", job)
    runner.assert_awaited_once()
    worker.ack_job.assert_not_awaited()


async def test_running_persistence_failure_retains_delivery(job_fixture):
    job, _, runner = job_fixture
    worker.claim_scan.side_effect = RuntimeError("database unavailable")
    with pytest.raises(RuntimeError):
        await worker._run_one_job("stream", "1-0", job)
    runner.assert_not_awaited()
    worker.ack_job.assert_not_awaited()


async def test_pubsub_failure_does_not_lose_durable_result(job_fixture):
    job, _, runner = job_fixture
    worker.publish_progress.side_effect = RuntimeError("redis pubsub unavailable")
    await worker._run_one_job("stream", "1-0", job)
    runner.assert_awaited_once()
    worker.finish_scan.assert_awaited_once()
    worker.ack_job.assert_awaited_once()


async def test_unavailable_probe_persists_inconclusive_without_score(job_fixture):
    job, _, runner = job_fixture
    runner.return_value = SimpleNamespace(
        status="INCONCLUSIVE",
        score=None,
        model_dump=lambda **_: {"status": "INCONCLUSIVE", "score": None},
    )
    await worker._run_one_job("stream", "1-0", job)
    assert worker.finish_scan.await_args.kwargs["status"] == "inconclusive"
    assert worker.finish_scan.await_args.kwargs["score"] is None


async def test_terminal_redelivery_does_not_execute_again(job_fixture):
    job, row, runner = job_fixture
    row["status"] = "completed"
    await worker._run_one_job("stream", "1-0", job)
    runner.assert_not_awaited()
    worker.claim_scan.assert_not_awaited()
    worker.ack_job.assert_awaited_once()


@pytest.mark.parametrize(
    "url",
    [
        "mcp://stdio?command=python",
        "file:///tmp/test",
        "https://not-enrolled.test/chat",
        "ws://agent.test/chat",
        "wss://agent.test/chat",
    ],
)
async def test_worker_rejects_queue_injected_target(job_fixture, url):
    job, row, runner = job_fixture
    job["target"]["target_url"] = url
    row["target_url"] = url
    await worker._run_one_job("stream", "1-0", job)
    runner.assert_not_awaited()
    assert worker.finish_scan.await_args.kwargs["status"] == "failed"
    worker.ack_job.assert_awaited_once()


async def test_stale_owner_cannot_ack(job_fixture):
    job, _, _ = job_fixture
    worker.finish_scan.return_value = False
    with pytest.raises(worker.LeaseLost):
        await worker._run_one_job("stream", "1-0", job)
    worker.ack_job.assert_not_awaited()


async def test_lease_loss_cancels_inflight_scan(job_fixture, monkeypatch):
    job, _, runner = job_fixture
    cancelled = asyncio.Event()

    async def stalled(target):
        try:
            await asyncio.sleep(10)
        finally:
            cancelled.set()

    runner.side_effect = stalled
    monkeypatch.setattr(worker, "LEASE_SECONDS", 0.03)
    worker.renew_scan_lease.return_value = False
    with pytest.raises(worker.LeaseLost):
        await worker._run_one_job("stream", "1-0", job)
    assert cancelled.is_set()
    worker.finish_scan.assert_not_awaited()
    worker.ack_job.assert_not_awaited()


async def test_retry_limit_must_be_persisted_before_ack(job_fixture):
    job, _, runner = job_fixture
    worker.claim_scan.return_value = False
    worker.fail_exhausted_scan.side_effect = RuntimeError("db unavailable")
    with pytest.raises(RuntimeError):
        await worker._run_one_job("stream", "1-0", job)
    worker.ack_job.assert_not_awaited()
    runner.assert_not_awaited()


async def test_worker_startup_failure_closes_pool(monkeypatch):
    close = AsyncMock()
    monkeypatch.setattr(
        worker, "init_db", AsyncMock(side_effect=RuntimeError("startup database unavailable"))
    )
    monkeypatch.setattr(worker, "close_db", close)
    with pytest.raises(RuntimeError, match="startup database unavailable"):
        await worker.worker_loop()
    close.assert_awaited_once()


async def test_worker_shutdown_closes_pool_without_ack(monkeypatch):
    entered = asyncio.Event()

    async def wait_for_job(*args, **kwargs):
        entered.set()
        await asyncio.sleep(20)

    close, ack = AsyncMock(), AsyncMock()
    monkeypatch.setattr(worker, "init_db", AsyncMock())
    monkeypatch.setattr(worker, "ensure_consumer_groups", AsyncMock())
    monkeypatch.setattr(worker, "dispatch_outbox", AsyncMock())
    monkeypatch.setattr(worker, "claim_job", wait_for_job)
    monkeypatch.setattr(worker, "close_db", close)
    monkeypatch.setattr(worker, "ack_job", ack)
    task = asyncio.create_task(worker.worker_loop())
    await entered.wait()
    task.cancel()
    await task
    close.assert_awaited_once()
    ack.assert_not_awaited()


async def test_worker_rechecks_external_opt_in_before_model_execution(job_fixture, monkeypatch):
    job, row, runner = job_fixture
    job["target"].update({"analysis_mode": "external", "data_classification": "non_sensitive"})
    row["request_json"] = encrypt_target(ScanRequest.model_validate(job["target"]).model_dump())
    await worker._run_one_job("stream", "1-0", job)
    runner.assert_not_awaited()
    assert worker.finish_scan.await_args.kwargs["status"] == "failed"


async def test_worker_forwards_encrypted_approved_answer_profile(job_fixture):
    job, row, execute = job_fixture
    baseline = {
        "schema_version": "agentscan.factuality.v1",
        "target_url": "http://agent.test/chat",
        "cases": [
            {
                "id": "policy",
                "question": "SYNTHETIC-CLIENT-QUESTION",
                "expected_answer": "APPROVED-ANSWER",
                "false_answer": "FALSE-ANSWER",
            }
        ],
    }
    job["target"]["factuality_baseline"] = baseline
    row["request_json"] = encrypt_target(ScanRequest.model_validate(job["target"]).model_dump())
    await worker._run_one_job("stream", "1-0", job)
    execute.assert_awaited_once()
    target = execute.await_args.args[0]
    assert target.factuality_baseline.model_dump() == baseline
    assert target.analysis_mode == "deterministic"
