"""PostgreSQL scan repository with UTC timestamps and fenced worker leases."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, TypedDict, cast

import asyncpg

from agentscan.api.contracts import ScanState


class TenantQuotaExceeded(RuntimeError):
    pass


class IdempotencyConflict(RuntimeError):
    """An accepted tenant key is bound to a different canonical request."""


@dataclass(frozen=True)
class ScanSubmission:
    scan_id: str
    status: ScanState
    replayed: bool


def validate_idempotency_key(key: str) -> str:
    """Bound keys without reflecting client input in errors or logs."""
    if not re.fullmatch(r"[A-Za-z0-9._~-]{1,128}", key):
        raise ValueError(
            "Idempotency-Key must contain 1–128 ASCII letters, digits, '.', '_', '~' or '-'."
        )
    return key


def _idempotency_fingerprints(tenant_id: str, key: str, target: dict[str, Any]) -> tuple[str, str]:
    """Domain-separated HMACs keep low-entropy keys and credentials out of DB hashes.

    The shared persistent data key must remain stable while these bindings exist.
    Only the validated request is fingerprinted: generated job IDs are excluded.
    """
    from cryptography.fernet import Fernet

    validate_idempotency_key(key)
    try:
        encoded = Path(os.environ["AGENTSCAN_DATA_KEY_FILE"]).read_bytes().strip()
        Fernet(encoded)
        secret = base64.urlsafe_b64decode(encoded)
    except (KeyError, OSError, ValueError) as exc:
        raise RuntimeError("The configured service data key is unavailable or invalid.") from exc

    def digest(domain: bytes, value: dict[str, Any]) -> str:
        canonical = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode("utf-8")
        return hmac.new(secret, domain + canonical, hashlib.sha256).hexdigest()

    return (
        digest(b"agentscan/idempotency-key/v1\0", {"tenant_id": tenant_id, "key": key}),
        digest(b"agentscan/idempotency-request/v1\0", {"tenant_id": tenant_id, "target": target}),
    )


DATABASE_URL = os.environ.get(
    "AGENTSCAN_DATABASE_URL", "postgresql://agentscan:agentscan@localhost:5432/agentscan"
)
_pool: asyncpg.Pool | None = None


class ScanRecord(TypedDict):
    scan_id: str
    tenant_id: str
    target_url: str
    scan_mode: str
    status: ScanState
    score: int | None
    started_at: datetime | None
    completed_at: datetime | None
    report_json: dict[str, Any] | None
    lease_token: str | None
    lease_expires_at: datetime | None
    attempts: int
    request_json: dict[str, Any] | None


async def _configure_connection(conn: asyncpg.Connection) -> None:
    for typename in ("json", "jsonb"):
        await conn.set_type_codec(
            typename, schema="pg_catalog", encoder=json.dumps, decoder=json.loads, format="text"
        )


async def init_db() -> None:
    global _pool
    if _pool is not None:
        return
    pool = await asyncpg.create_pool(
        DATABASE_URL,
        min_size=2,
        max_size=20,
        timeout=10,
        command_timeout=10,
        init=_configure_connection,
    )
    try:
        async with pool.acquire() as conn:
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL,
                    target_url TEXT, scan_mode TEXT, status TEXT NOT NULL DEFAULT 'queued',
                    score INT, started_at TIMESTAMPTZ, completed_at TIMESTAMPTZ, report_json JSONB,
                    lease_token TEXT, lease_expires_at TIMESTAMPTZ, attempts INT NOT NULL DEFAULT 0
                );
                ALTER TABLE scans ADD COLUMN IF NOT EXISTS lease_token TEXT;
                ALTER TABLE scans ADD COLUMN IF NOT EXISTS lease_expires_at TIMESTAMPTZ;
                ALTER TABLE scans ADD COLUMN IF NOT EXISTS attempts INT NOT NULL DEFAULT 0;
                ALTER TABLE scans ADD COLUMN IF NOT EXISTS request_json JSONB;
                CREATE INDEX IF NOT EXISTS idx_scans_tenant ON scans (tenant_id, started_at DESC);
                CREATE INDEX IF NOT EXISTS idx_scans_status ON scans (status);
                CREATE TABLE IF NOT EXISTS scan_outbox (
                    scan_id TEXT PRIMARY KEY REFERENCES scans(scan_id) ON DELETE CASCADE,
                    tenant_id TEXT NOT NULL, scan_mode TEXT NOT NULL,
                    delivered_at TIMESTAMPTZ
                );
                CREATE TABLE IF NOT EXISTS scan_events (
                    sequence BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                    scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
                    tenant_id TEXT NOT NULL, event JSONB NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
                );
                CREATE INDEX IF NOT EXISTS idx_scan_events ON scan_events(scan_id,sequence);
                CREATE TABLE IF NOT EXISTS tenant_submission_windows (
                    tenant_id TEXT NOT NULL, window_start TIMESTAMPTZ NOT NULL,
                    submissions INT NOT NULL, PRIMARY KEY(tenant_id,window_start)
                );
                CREATE TABLE IF NOT EXISTS scan_idempotency (
                    tenant_id TEXT NOT NULL,
                    key_digest TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    scan_id TEXT NOT NULL UNIQUE REFERENCES scans(scan_id) ON DELETE CASCADE,
                    PRIMARY KEY(tenant_id,key_digest)
                );
            """)
    except BaseException:
        await pool.close()
        raise
    _pool = pool


async def close_db() -> None:
    global _pool
    pool, _pool = _pool, None
    if pool is not None:
        await pool.close()


def _get_pool() -> asyncpg.Pool:
    if _pool is None:
        raise RuntimeError("Database pool not initialised. Call init_db() first.")
    return _pool


async def check_db() -> None:
    async with _get_pool().acquire(timeout=2) as conn:
        await conn.fetchval("SELECT 1")


def _aware(value: datetime | None) -> None:
    if value is not None and (
        not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None
    ):
        raise ValueError("Persistence timestamps must be timezone-aware datetime values.")


async def upsert_scan(
    *,
    scan_id: str,
    tenant_id: str,
    target_url: str,
    scan_mode: str,
    status: ScanState,
    score: int | None = None,
    started_at: datetime | None = None,
    completed_at: datetime | None = None,
    report_json: dict[str, Any] | None = None,
    request_json: dict[str, Any] | None = None,
) -> None:
    """Persist submission metadata; worker transitions use fenced update methods below."""
    _aware(started_at)
    _aware(completed_at)
    async with _get_pool().acquire() as conn:
        result = await conn.execute(
            """
            INSERT INTO scans (scan_id,tenant_id,target_url,scan_mode,status,score,started_at,completed_at,report_json,request_json)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
            ON CONFLICT (scan_id) DO UPDATE SET status=EXCLUDED.status,score=EXCLUDED.score,
                completed_at=EXCLUDED.completed_at,report_json=EXCLUDED.report_json
            WHERE scans.tenant_id=EXCLUDED.tenant_id
        """,
            scan_id,
            tenant_id,
            target_url,
            scan_mode,
            status,
            score,
            started_at,
            completed_at,
            report_json,
            request_json,
        )
    if result == "INSERT 0 0":
        raise ValueError("Scan identity belongs to a different tenant.")


async def get_scan(scan_id: str, tenant_id: str) -> ScanRecord | None:
    async with _get_pool().acquire() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM scans WHERE scan_id=$1 AND tenant_id=$2", scan_id, tenant_id
        )
    return cast(ScanRecord, dict(row)) if row is not None else None


async def submit_scan(
    job: dict[str, Any],
    started_at: datetime,
    max_active: int,
    hourly_limit: int,
    *,
    idempotency_key: str | None = None,
    admission_check: Callable[[], None] | None = None,
) -> ScanSubmission | None:
    """Commit a scan, its initial event and delivery intent in one transaction.

    A per-tenant transaction lock serializes quota checks across API replicas.
    Request credentials are encrypted; Redis only receives the scan identity.
    Optional tenant-key bindings are checked before quotas under the same lock.
    Bindings live until their scan is deleted, including terminal retention.
    Without a key the historical return value remains None.
    """
    from urllib.parse import urlsplit

    from agentscan.api.data_policy import encrypt_target

    _aware(started_at)
    scan_id, tenant_id, target = job["scan_id"], job["tenant_id"], job["target"]
    encrypted = encrypt_target(target)
    fingerprints = (
        _idempotency_fingerprints(tenant_id, idempotency_key, target)
        if idempotency_key is not None
        else None
    )
    display_url = urlsplit(target["target_url"])._replace(query="").geturl()
    async with _get_pool().acquire() as conn, conn.transaction():
        await conn.execute("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", tenant_id)
        if fingerprints is not None:
            existing = await conn.fetchrow(
                """SELECT binding.request_digest,scans.scan_id,scans.status
                FROM scan_idempotency AS binding
                JOIN scans ON scans.scan_id=binding.scan_id AND scans.tenant_id=binding.tenant_id
                WHERE binding.tenant_id=$1 AND binding.key_digest=$2""",
                tenant_id,
                fingerprints[0],
            )
            if existing is not None:
                if not hmac.compare_digest(existing["request_digest"], fingerprints[1]):
                    raise IdempotencyConflict(
                        "Idempotency-Key is already bound to a different scan request."
                    )
                return ScanSubmission(existing["scan_id"], existing["status"], replayed=True)
        if admission_check is not None:
            # Only environment configuration is inspected by the API callback;
            # no provider or other network IO belongs in this transaction.
            admission_check()
        active = await conn.fetchval(
            "SELECT count(*) FROM scans WHERE tenant_id=$1 AND status IN ('queued','running')",
            tenant_id,
        )
        if active >= max_active:
            raise TenantQuotaExceeded("Active scan quota reached.")
        accepted = await conn.fetchval(
            """
            INSERT INTO tenant_submission_windows VALUES ($1,date_trunc('hour',clock_timestamp()),1)
            ON CONFLICT (tenant_id,window_start) DO UPDATE SET submissions=tenant_submission_windows.submissions+1
            WHERE tenant_submission_windows.submissions<$2 RETURNING submissions
        """,
            tenant_id,
            hourly_limit,
        )
        if accepted is None:
            raise TenantQuotaExceeded("Hourly submission quota reached.")
        await conn.execute(
            """
            INSERT INTO scans(scan_id,tenant_id,target_url,scan_mode,status,started_at,request_json)
            VALUES($1,$2,$3,$4,'queued',$5,$6)
        """,
            scan_id,
            tenant_id,
            display_url,
            target["scan_mode"],
            started_at,
            encrypted,
        )
        await conn.execute(
            "INSERT INTO scan_outbox(scan_id,tenant_id,scan_mode) VALUES($1,$2,$3)",
            scan_id,
            tenant_id,
            target["scan_mode"],
        )
        await conn.execute(
            "INSERT INTO scan_events(scan_id,tenant_id,event) VALUES($1,$2,$3)",
            scan_id,
            tenant_id,
            {"status": "queued", "progress": 0},
        )
        if fingerprints is not None:
            await conn.execute(
                """INSERT INTO scan_idempotency(tenant_id,key_digest,request_digest,scan_id)
                VALUES($1,$2,$3,$4)""",
                tenant_id,
                fingerprints[0],
                fingerprints[1],
                scan_id,
            )
    return ScanSubmission(scan_id, "queued", replayed=False) if fingerprints is not None else None


async def dispatch_outbox(scan_id: str | None = None, limit: int = 20) -> int:
    """At-least-once relay with row locks; re-enqueue stranded queued jobs.

    A crash after Redis accepted a delivery may duplicate it. Fenced DB leases
    prevent simultaneous execution. Periodic redelivery also repairs Redis loss.
    """
    from agentscan.api.queue import enqueue_scan

    delivered = 0
    async with _get_pool().acquire() as conn, conn.transaction():
        rows = await conn.fetch(
            """
            SELECT o.* FROM scan_outbox o JOIN scans s USING(scan_id)
            WHERE ($1::text IS NULL OR o.scan_id=$1) AND
                (o.delivered_at IS NULL OR (s.status='queued' AND o.delivered_at<clock_timestamp()-interval '120 seconds')
                 OR (s.status='running' AND s.lease_expires_at<clock_timestamp() AND o.delivered_at<clock_timestamp()-interval '120 seconds'))
            ORDER BY o.delivered_at NULLS FIRST LIMIT $2 FOR UPDATE OF o SKIP LOCKED
        """,
            scan_id,
            limit,
        )
        for row in rows:
            await enqueue_scan(
                {"scan_id": row["scan_id"], "tenant_id": row["tenant_id"]}, row["scan_mode"]
            )
            await conn.execute(
                "UPDATE scan_outbox SET delivered_at=clock_timestamp() WHERE scan_id=$1",
                row["scan_id"],
            )
            delivered += 1
    return delivered


async def read_scan_events(
    scan_id: str, tenant_id: str, after: int, limit: int = 100
) -> list[dict[str, Any]]:
    async with _get_pool().acquire() as conn:
        rows = await conn.fetch(
            """SELECT sequence,event FROM scan_events
            WHERE scan_id=$1 AND tenant_id=$2 AND sequence>$3 ORDER BY sequence LIMIT $4""",
            scan_id,
            tenant_id,
            after,
            limit,
        )
    return [dict(row) for row in rows]


async def fail_submission(scan_id: str, tenant_id: str) -> bool:
    """Terminate an explicitly abandoned queued job without overwriting its worker."""
    async with _get_pool().acquire() as conn, conn.transaction():
        result = await conn.execute(
            """UPDATE scans SET status='failed',completed_at=clock_timestamp(),report_json=$3,
            request_json=NULL WHERE scan_id=$1 AND tenant_id=$2 AND status='queued'""",
            scan_id,
            tenant_id,
            {"error": "Submission was explicitly abandoned before execution."},
        )
        if result == "UPDATE 1":
            await conn.execute("DELETE FROM scan_outbox WHERE scan_id=$1", scan_id)
            await conn.execute(
                "INSERT INTO scan_events(scan_id,tenant_id,event) VALUES($1,$2,$3)",
                scan_id,
                tenant_id,
                {"status": "failed"},
            )
    return result == "UPDATE 1"


async def list_scans(tenant_id: str, limit: int = 20, offset: int = 0) -> list[dict[str, Any]]:
    async with _get_pool().acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT scan_id,target_url,scan_mode,status,score,started_at,completed_at FROM scans
            WHERE tenant_id=$1 ORDER BY started_at DESC NULLS LAST LIMIT $2 OFFSET $3
        """,
            tenant_id,
            limit,
            offset,
        )
    return [dict(row) for row in rows]


async def claim_scan(
    scan_id: str, tenant_id: str, lease_token: str, lease_seconds: float, max_attempts: int
) -> bool:
    async with _get_pool().acquire() as conn, conn.transaction():
        result = await conn.execute(
            """
            UPDATE scans SET status='running',lease_token=$3,
                lease_expires_at=clock_timestamp()+($4 * interval '1 second'),attempts=attempts+1
            WHERE scan_id=$1 AND tenant_id=$2 AND attempts<$5
                AND (status='queued' OR (status='running' AND (lease_expires_at IS NULL OR lease_expires_at<clock_timestamp())))
        """,
            scan_id,
            tenant_id,
            lease_token,
            lease_seconds,
            max_attempts,
        )
        if result == "UPDATE 1":
            await conn.execute(
                "INSERT INTO scan_events(scan_id,tenant_id,event) VALUES($1,$2,$3)",
                scan_id,
                tenant_id,
                {"status": "running", "progress": 0},
            )
    return result == "UPDATE 1"


async def renew_scan_lease(
    scan_id: str, tenant_id: str, lease_token: str, lease_seconds: float
) -> bool:
    async with _get_pool().acquire() as conn, conn.transaction():
        result = await conn.execute(
            """
            UPDATE scans SET lease_expires_at=clock_timestamp()+($4 * interval '1 second')
            WHERE scan_id=$1 AND tenant_id=$2 AND status='running' AND lease_token=$3
                AND lease_expires_at>clock_timestamp()
        """,
            scan_id,
            tenant_id,
            lease_token,
            lease_seconds,
        )
    return result == "UPDATE 1"


async def finish_scan(
    *,
    scan_id: str,
    tenant_id: str,
    lease_token: str,
    status: ScanState,
    score: int | None = None,
    report_json: dict[str, Any] | None = None,
) -> bool:
    if status not in {"completed", "inconclusive", "failed"}:
        raise ValueError("A worker can only persist a terminal scan outcome.")
    async with _get_pool().acquire() as conn, conn.transaction():
        result = await conn.execute(
            """
            UPDATE scans SET status=$4,score=$5,report_json=$6,completed_at=clock_timestamp(),
                lease_token=NULL,lease_expires_at=NULL,request_json=NULL
            WHERE scan_id=$1 AND tenant_id=$2 AND status='running' AND lease_token=$3
                AND lease_expires_at>clock_timestamp()
        """,
            scan_id,
            tenant_id,
            lease_token,
            status,
            score,
            report_json,
        )
        if result == "UPDATE 1":
            await conn.execute("DELETE FROM scan_outbox WHERE scan_id=$1", scan_id)
            await conn.execute(
                "INSERT INTO scan_events(scan_id,tenant_id,event) VALUES($1,$2,$3)",
                scan_id,
                tenant_id,
                {"status": status, "progress": 100, "score": score},
            )
    return result == "UPDATE 1"


async def fail_exhausted_scan(scan_id: str, tenant_id: str, max_attempts: int) -> bool:
    async with _get_pool().acquire() as conn, conn.transaction():
        result = await conn.execute(
            """
            UPDATE scans SET status='failed',completed_at=clock_timestamp(),lease_token=NULL,
                lease_expires_at=NULL,report_json=$4,request_json=NULL
            WHERE scan_id=$1 AND tenant_id=$2 AND attempts>=$3
                AND (status='queued' OR (status='running' AND (lease_expires_at IS NULL OR lease_expires_at<clock_timestamp())))
        """,
            scan_id,
            tenant_id,
            max_attempts,
            {"error": "Worker retry limit exhausted; outcome unavailable."},
        )
        if result == "UPDATE 1":
            await conn.execute("DELETE FROM scan_outbox WHERE scan_id=$1", scan_id)
            await conn.execute(
                "INSERT INTO scan_events(scan_id,tenant_id,event) VALUES($1,$2,$3)",
                scan_id,
                tenant_id,
                {"status": "failed", "error": "Worker retry limit exhausted."},
            )
    return result == "UPDATE 1"


async def delete_terminal_scan(scan_id: str, tenant_id: str) -> str:
    """Active records remain present so queued/running work cannot recreate deleted data."""
    async with _get_pool().acquire() as conn:
        return await conn.execute(
            """
            DELETE FROM scans WHERE scan_id=$1 AND tenant_id=$2
            AND status IN ('completed','inconclusive','failed','cancelled')
        """,
            scan_id,
            tenant_id,
        )


async def cancel_scan(scan_id: str, tenant_id: str) -> bool:
    async with _get_pool().acquire() as conn, conn.transaction():
        result = await conn.execute(
            """UPDATE scans SET status='cancelled',score=NULL,
            completed_at=clock_timestamp(),lease_token=NULL,lease_expires_at=NULL,request_json=NULL
            WHERE scan_id=$1 AND tenant_id=$2 AND status IN ('queued','running')""",
            scan_id,
            tenant_id,
        )
        if result == "UPDATE 1":
            await conn.execute("DELETE FROM scan_outbox WHERE scan_id=$1", scan_id)
            await conn.execute(
                "INSERT INTO scan_events(scan_id,tenant_id,event) VALUES($1,$2,$3)",
                scan_id,
                tenant_id,
                {"status": "cancelled"},
            )
    return result == "UPDATE 1"


async def prune_expired_records(retention_days: int = 7) -> None:
    if not 1 <= retention_days <= 365:
        raise ValueError("Service retention must be between 1 and 365 days.")
    async with _get_pool().acquire() as conn, conn.transaction():
        await conn.execute(
            """DELETE FROM scans WHERE scan_id IN (
            SELECT scan_id FROM scans WHERE status IN ('completed','inconclusive','failed','cancelled')
            AND completed_at<clock_timestamp()-($1 * interval '1 day') LIMIT 1000)""",
            retention_days,
        )
        await conn.execute(
            "DELETE FROM tenant_submission_windows WHERE window_start<clock_timestamp()-interval '2 hours'"
        )
