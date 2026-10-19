"""Request retries are deduplicated without retaining keys or credential hashes.

Live cases use only AGENTSCAN_TEST_DATABASE_URL, a dedicated disposable DB.
They reset scanner tables, never load .env and never contact model providers.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock

import httpx
import pytest

from agentscan.api import db, server
from agentscan.api.auth import get_current_tenant
from agentscan.api.contracts import ScanRequest
from agentscan.api.data_policy import decrypt_target


def job(*, tenant="tenant-a", **changes):
    request = {"target_url": "http://localhost/chat", **changes}
    return {
        "scan_id": str(uuid.uuid4()),
        "tenant_id": tenant,
        "target": ScanRequest(**request).model_dump(),
    }


@pytest.fixture
async def client(monkeypatch):
    app = server.create_api_app()
    app.dependency_overrides[get_current_tenant] = lambda: "tenant-a"
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://api.test"
    ) as client:
        yield client


@pytest.mark.parametrize("key", ["", " ", "two words", "x" * 129, "é", "a,b", "a/b", "a:b"])
async def test_invalid_key_returns_400_without_persistence(client, monkeypatch, key):
    persist, relay = AsyncMock(), AsyncMock()
    monkeypatch.setattr(server, "submit_scan", persist)
    monkeypatch.setattr(server, "dispatch_outbox", relay)
    response = await client.post(
        "/scans",
        json={"target_url": "http://localhost/chat"},
        headers={"Idempotency-Key": key.encode("utf-8")},
    )
    assert response.status_code == 400
    persist.assert_not_awaited()
    relay.assert_not_awaited()
    if len(key) > 1:
        assert key not in response.text


async def test_duplicate_key_headers_return_400(client, monkeypatch):
    persist = AsyncMock()
    monkeypatch.setattr(server, "submit_scan", persist)
    response = await client.post(
        "/scans",
        json={"target_url": "http://localhost/chat"},
        headers=[("Idempotency-Key", "first"), ("Idempotency-Key", "second")],
    )
    assert response.status_code == 400
    persist.assert_not_awaited()


@pytest.mark.parametrize(
    "scan_status", ["queued", "running", "completed", "inconclusive", "failed", "cancelled"]
)
async def test_replay_returns_durable_identity_status_without_delivery(
    client, monkeypatch, scan_status
):
    persist = AsyncMock(return_value=db.ScanSubmission("original-id", scan_status, True))
    relay = AsyncMock()
    monkeypatch.setattr(server, "submit_scan", persist)
    monkeypatch.setattr(server, "dispatch_outbox", relay)
    response = await client.post(
        "/scans",
        json={"target_url": "http://localhost/chat"},
        headers={"Idempotency-Key": "client-request-1"},
    )
    assert response.status_code == 202
    assert response.json() == {
        "scan_id": "original-id",
        "status": scan_status,
        "stream_url": "/scans/original-id/stream",
    }
    assert persist.await_args.kwargs["idempotency_key"] == "client-request-1"
    assert persist.await_args.args[0]["tenant_id"] == "tenant-a"
    relay.assert_not_awaited()


async def test_new_key_returns_committed_identity_and_relays_once(client, monkeypatch):
    persist = AsyncMock(return_value=db.ScanSubmission("committed-id", "queued", False))
    relay = AsyncMock()
    monkeypatch.setattr(server, "submit_scan", persist)
    monkeypatch.setattr(server, "dispatch_outbox", relay)
    response = await client.post(
        "/scans",
        json={"target_url": "http://localhost/chat"},
        headers={"Idempotency-Key": "request-1"},
    )
    assert response.status_code == 202
    assert response.json()["scan_id"] == "committed-id"
    relay.assert_awaited_once_with("committed-id")


@pytest.mark.parametrize("adapter", [None, "document_v1"])
async def test_optional_document_adapter_preserves_legacy_admission_payload(
    client, monkeypatch, adapter
):
    persist = AsyncMock(return_value=db.ScanSubmission("committed-id", "queued", False))
    monkeypatch.setattr(server, "submit_scan", persist)
    monkeypatch.setattr(server, "dispatch_outbox", AsyncMock())
    body = {"target_url": "http://localhost/chat"}
    if adapter is not None:
        body["indirect_adapter"] = adapter
    response = await client.post(
        "/scans", json=body, headers={"Idempotency-Key": "adapter-contract-1"}
    )
    assert response.status_code == 202
    stored = persist.await_args.args[0]["target"]
    legacy = ScanRequest(target_url=body["target_url"]).model_dump()
    legacy.pop("indirect_adapter")
    legacy.pop("factuality_baseline")
    if adapter is None:
        assert stored == legacy
    else:
        assert stored == {**legacy, "indirect_adapter": "document_v1"}


async def test_key_conflict_returns_safe_409_without_delivery(client, monkeypatch):
    monkeypatch.setattr(
        server,
        "submit_scan",
        AsyncMock(
            side_effect=db.IdempotencyConflict(
                "Idempotency-Key is already bound to a different scan request."
            )
        ),
    )
    relay = AsyncMock()
    monkeypatch.setattr(server, "dispatch_outbox", relay)
    response = await client.post(
        "/scans",
        json={"target_url": "http://localhost/chat", "system_prompt": "private instruction"},
        headers={"Idempotency-Key": "secret-low-entropy-key"},
    )
    assert response.status_code == 409
    assert "private instruction" not in response.text
    assert "secret-low-entropy-key" not in response.text
    relay.assert_not_awaited()


async def test_keyed_replay_still_requires_current_tenant_authorization(client, monkeypatch):
    persist = AsyncMock()
    monkeypatch.setattr(server, "submit_scan", persist)
    response = await client.post(
        "/scans",
        json={"target_url": "https://agent.test/chat"},
        headers={"Idempotency-Key": "request-1"},
    )
    assert response.status_code == 403
    persist.assert_not_awaited()


def test_fingerprints_are_canonical_tenant_scoped_and_keyed():
    request = job(headers={"X-API-Key": "1234"}, system_prompt="private")["target"]
    reversed_request = dict(reversed(list(request.items())))
    original = db._idempotency_fingerprints("tenant-a", "1", request)
    assert original == db._idempotency_fingerprints("tenant-a", "1", reversed_request)
    assert original != db._idempotency_fingerprints("tenant-b", "1", request)
    assert original[0] != db._idempotency_fingerprints("tenant-a", "2", request)[0]
    assert (
        original[1]
        != db._idempotency_fingerprints(
            "tenant-a", "1", {**request, "headers": {"X-API-Key": "4321"}}
        )[1]
    )
    assert all(len(item) == 64 for item in original)
    assert original[0] != hashlib.sha256(b"1").hexdigest()
    canonical = json.dumps(
        request, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    assert original[1] != hashlib.sha256(canonical).hexdigest()


@pytest.mark.parametrize(
    "changes",
    [
        {"target_url": "http://localhost/other"},
        {"scan_mode": "EXPLOIT"},
        {"system_prompt": "other"},
        {"framework": "custom"},
        {"timeout": 45},
        {"concurrency": 3},
        {"headers": {"Authorization": "Bearer synthetic"}},
        {"analysis_mode": "local"},
        {"data_classification": "non_sensitive"},
    ],
)
def test_fingerprint_detects_every_request_option(changes):
    baseline = db._idempotency_fingerprints("tenant-a", "same-key", job()["target"])
    changed = db._idempotency_fingerprints("tenant-a", "same-key", job(**changes)["target"])
    assert baseline[0] == changed[0]
    assert baseline[1] != changed[1]


@pytest.fixture
async def live_idempotency_db(monkeypatch):
    database_url = os.environ.get("AGENTSCAN_TEST_DATABASE_URL")
    if not database_url:
        pytest.skip(
            "Set a dedicated disposable AGENTSCAN_TEST_DATABASE_URL for live PostgreSQL checks."
        )
    monkeypatch.setattr(db, "DATABASE_URL", database_url)
    monkeypatch.setattr(db, "_pool", None)
    await db.init_db()
    try:
        async with db._get_pool().acquire() as conn:
            await conn.execute(
                "TRUNCATE scans,scan_outbox,scan_events,tenant_submission_windows CASCADE"
            )
        yield
    finally:
        await db.close_db()


async def test_live_concurrent_retries_accept_once_before_quota(live_idempotency_db):
    jobs = [job() for _ in range(24)]
    results = await asyncio.gather(
        *(
            db.submit_scan(item, datetime.now(UTC), 1, 1, idempotency_key="concurrent-key")
            for item in jobs
        )
    )
    assert len({result.scan_id for result in results}) == 1
    assert sum(not result.replayed for result in results) == 1
    assert all(result.status == "queued" for result in results)
    async with db._get_pool().acquire() as conn:
        for table in ("scans", "scan_outbox", "scan_events", "scan_idempotency"):
            assert await conn.fetchval(f"SELECT count(*) FROM {table}") == 1
        assert await conn.fetchval("SELECT sum(submissions) FROM tenant_submission_windows") == 1


async def test_live_concurrent_changed_requests_conflict_atomically(live_idempotency_db):
    jobs = [job(timeout=30 if index % 2 else 45) for index in range(20)]
    results = await asyncio.gather(
        *(
            db.submit_scan(item, datetime.now(UTC), 1, 1, idempotency_key="contended-key")
            for item in jobs
        ),
        return_exceptions=True,
    )
    accepted = [result for result in results if isinstance(result, db.ScanSubmission)]
    assert len(accepted) == 10
    assert len({result.scan_id for result in accepted}) == 1
    assert sum(not result.replayed for result in accepted) == 1
    assert sum(isinstance(result, db.IdempotencyConflict) for result in results) == 10
    async with db._get_pool().acquire() as conn:
        assert await conn.fetchval("SELECT sum(submissions) FROM tenant_submission_windows") == 1


async def test_live_same_key_is_independent_across_tenants(live_idempotency_db):
    results = await asyncio.gather(
        *(
            db.submit_scan(
                job(tenant=tenant), datetime.now(UTC), 1, 1, idempotency_key="shared-key"
            )
            for tenant in ("tenant-a", "tenant-b")
        )
    )
    assert results[0].scan_id != results[1].scan_id
    assert all(not result.replayed for result in results)
    assert await db.get_scan(results[0].scan_id, "tenant-b") is None
    async with db._get_pool().acquire() as conn:
        assert await conn.fetchval("SELECT count(DISTINCT key_digest) FROM scan_idempotency") == 2


async def test_live_binding_and_queue_never_retain_raw_key_or_request_credentials(
    live_idempotency_db,
):
    item = job(
        headers={"X-API-Key": "synthetic-private-1234"}, system_prompt="synthetic-private-prompt"
    )
    result = await db.submit_scan(
        item, datetime.now(UTC), 5, 60, idempotency_key="synthetic-secret-key"
    )
    async with db._get_pool().acquire() as conn:
        binding = dict(await conn.fetchrow("SELECT * FROM scan_idempotency"))
        outbox = dict(await conn.fetchrow("SELECT * FROM scan_outbox"))
    encoded = json.dumps({"binding": binding, "outbox": outbox}, default=str)
    for secret in ("synthetic-private-1234", "synthetic-private-prompt", "synthetic-secret-key"):
        assert secret not in encoded
    record = await db.get_scan(result.scan_id, "tenant-a")
    assert decrypt_target(record["request_json"]) == item["target"]
    assert "synthetic-private-1234" not in json.dumps(record["request_json"])


async def test_live_quota_rejection_does_not_reserve_key(live_idempotency_db):
    active = await db.submit_scan(job(), datetime.now(UTC), 1, 60, idempotency_key="first")
    retry = job()
    with pytest.raises(db.TenantQuotaExceeded):
        await db.submit_scan(retry, datetime.now(UTC), 1, 60, idempotency_key="not-reserved")
    assert await db.cancel_scan(active.scan_id, "tenant-a")
    result = await db.submit_scan(retry, datetime.now(UTC), 1, 60, idempotency_key="not-reserved")
    assert not result.replayed
    async with db._get_pool().acquire() as conn:
        assert await conn.fetchval("SELECT sum(submissions) FROM tenant_submission_windows") == 2


async def test_live_binding_survives_pool_recreation_and_terminal_request_erasure(
    live_idempotency_db,
):
    original = await db.submit_scan(job(), datetime.now(UTC), 1, 60, idempotency_key="persistent")
    assert await db.cancel_scan(original.scan_id, "tenant-a")
    assert (await db.get_scan(original.scan_id, "tenant-a"))["request_json"] is None
    await db.close_db()
    await db.init_db()
    replay = await db.submit_scan(job(), datetime.now(UTC), 1, 60, idempotency_key="persistent")
    assert replay == db.ScanSubmission(original.scan_id, "cancelled", True)


@pytest.mark.parametrize("cleanup", ["delete", "retention"])
async def test_live_binding_expires_with_scan_and_key_can_be_reused(live_idempotency_db, cleanup):
    original = await db.submit_scan(job(), datetime.now(UTC), 1, 60, idempotency_key="reusable")
    assert await db.cancel_scan(original.scan_id, "tenant-a")
    if cleanup == "delete":
        assert await db.delete_terminal_scan(original.scan_id, "tenant-a") == "DELETE 1"
    else:
        async with db._get_pool().acquire() as conn:
            await conn.execute("UPDATE scans SET completed_at=clock_timestamp()-interval '8 days'")
        await db.prune_expired_records(7)
    assert await db.get_scan(original.scan_id, "tenant-a") is None
    result = await db.submit_scan(
        job(timeout=45), datetime.now(UTC), 1, 60, idempotency_key="reusable"
    )
    assert result.scan_id != original.scan_id and not result.replayed
    async with db._get_pool().acquire() as conn:
        assert await conn.fetchval("SELECT count(*) FROM scan_idempotency") == 1
        assert await conn.fetchval("SELECT sum(submissions) FROM tenant_submission_windows") == 2


async def test_live_endpoint_canonical_defaults_replay_and_changed_credentials_conflict(
    live_idempotency_db, client, monkeypatch
):
    relay = AsyncMock(side_effect=RuntimeError("synthetic relay outage"))
    monkeypatch.setattr(server, "dispatch_outbox", relay)
    minimal = {"target_url": "http://localhost/chat", "headers": {"X-API-Key": "1234"}}
    key = {"Idempotency-Key": "canonical-defaults"}
    original = await client.post("/scans", json=minimal, headers=key)
    assert original.status_code == 202
    explicit = ScanRequest(**minimal).model_dump()
    replay = await client.post("/scans", json=dict(reversed(list(explicit.items()))), headers=key)
    assert replay.json() == original.json()
    conflict = await client.post(
        "/scans", json={**minimal, "headers": {"X-API-Key": "4321"}}, headers=key
    )
    assert conflict.status_code == 409
    assert await db.cancel_scan(original.json()["scan_id"], "tenant-a")
    terminal = await client.post("/scans", json=minimal, headers=key)
    assert terminal.json()["scan_id"] == original.json()["scan_id"]
    assert terminal.json()["status"] == "cancelled"
    assert relay.await_count == 1


async def test_live_completed_external_retry_needs_no_provider_key_but_new_scan_does(
    live_idempotency_db, client, monkeypatch
):
    policies = json.loads(os.environ["AGENTSCAN_TENANT_POLICIES_JSON"])
    policies["tenant-a"]["allow_external_model_analysis"] = True
    monkeypatch.setenv("AGENTSCAN_TENANT_POLICIES_JSON", json.dumps(policies))
    monkeypatch.setenv("AGENTSCAN_EXTERNAL_MODEL", "gemini/synthetic-model")
    monkeypatch.setenv("GEMINI_API_KEY", "synthetic-provider-key")
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    relay = AsyncMock()
    monkeypatch.setattr(server, "dispatch_outbox", relay)
    request = {
        "target_url": "http://localhost/chat",
        "analysis_mode": "external",
        "data_classification": "non_sensitive",
    }
    headers = {"Idempotency-Key": "external-original"}
    response = await client.post("/scans", json=request, headers=headers)
    assert response.status_code == 202
    scan_id = response.json()["scan_id"]
    assert await db.claim_scan(scan_id, "tenant-a", "synthetic-owner", 60, 3)
    assert await db.finish_scan(
        scan_id=scan_id,
        tenant_id="tenant-a",
        lease_token="synthetic-owner",
        status="completed",
        score=100,
        report_json={"findings": []},
    )
    monkeypatch.delenv("GEMINI_API_KEY")
    replay = await client.post("/scans", json=request, headers=headers)
    assert replay.status_code == 202
    assert replay.json()["scan_id"] == scan_id and replay.json()["status"] == "completed"
    conflict = await client.post("/scans", json={**request, "timeout": 45}, headers=headers)
    assert conflict.status_code == 409
    new = await client.post("/scans", json=request, headers={"Idempotency-Key": "external-new"})
    assert new.status_code == 503
    assert new.json()["detail"] == "External analysis configuration unavailable."
    async with db._get_pool().acquire() as conn:
        assert await conn.fetchval("SELECT count(*) FROM scan_idempotency") == 1
        assert await conn.fetchval("SELECT sum(submissions) FROM tenant_submission_windows") == 1
    policies["tenant-a"]["allow_external_model_analysis"] = False
    monkeypatch.setenv("AGENTSCAN_TENANT_POLICIES_JSON", json.dumps(policies))
    revoked = await client.post("/scans", json=request, headers=headers)
    assert revoked.status_code == 403
    relay.assert_awaited_once_with(scan_id)
