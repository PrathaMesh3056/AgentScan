# agentscan/api/db.py
#
# PostgreSQL persistence for scan results via asyncpg.
# Connection pool is initialised once at API server startup.

from __future__ import annotations

import json
import os
from typing import Any

import asyncpg

DATABASE_URL = os.environ.get(
    "AGENTSCAN_DATABASE_URL",
    "postgresql://agentscan:agentscan@localhost:5432/agentscan",
)

_pool: asyncpg.Pool | None = None


async def init_db() -> None:
    """Open the connection pool and create tables if they don't exist."""
    global _pool
    _pool = await asyncpg.create_pool(DATABASE_URL, min_size=2, max_size=20)
    async with _pool.acquire() as conn:
        await conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                scan_id      TEXT PRIMARY KEY,
                tenant_id    TEXT NOT NULL DEFAULT 'local',
                target_url   TEXT,
                scan_mode    TEXT,
                status       TEXT NOT NULL DEFAULT 'queued',
                score        INT,
                started_at   TIMESTAMPTZ,
                completed_at TIMESTAMPTZ,
                report_json  JSONB
            );
            CREATE INDEX IF NOT EXISTS idx_scans_tenant
                ON scans (tenant_id, started_at DESC);
            CREATE INDEX IF NOT EXISTS idx_scans_status
                ON scans (status);
            """
        )


async def close_db() -> None:
    """Close the connection pool gracefully on server shutdown."""
    global _pool
    if _pool:
        await _pool.close()
        _pool = None


def _get_pool() -> asyncpg.Pool:
    if _pool is None:
        raise RuntimeError("Database pool not initialised. Call init_db() first.")
    return _pool


async def upsert_scan(
    *,
    scan_id: str,
    tenant_id: str,
    target_url: str,
    scan_mode: str,
    status: str,
    score: int | None = None,
    started_at: str | None = None,
    completed_at: str | None = None,
    report_json: dict[str, Any] | None = None,
) -> None:
    """Insert or update a scan row."""
    pool = _get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO scans
                (scan_id, tenant_id, target_url, scan_mode, status,
                 score, started_at, completed_at, report_json)
            VALUES ($1, $2, $3, $4, $5, $6,
                    $7::timestamptz, $8::timestamptz, $9::jsonb)
            ON CONFLICT (scan_id) DO UPDATE SET
                status       = EXCLUDED.status,
                score        = EXCLUDED.score,
                completed_at = EXCLUDED.completed_at,
                report_json  = EXCLUDED.report_json
            """,
            scan_id,
            tenant_id,
            target_url,
            scan_mode,
            status,
            score,
            started_at,
            completed_at,
            json.dumps(report_json) if report_json else None,
        )


async def get_scan(scan_id: str, tenant_id: str) -> dict[str, Any] | None:
    """Fetch one scan row by scan_id, scoped to tenant."""
    pool = _get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM scans WHERE scan_id = $1 AND tenant_id = $2",
            scan_id,
            tenant_id,
        )
    if row is None:
        return None
    return dict(row)


async def list_scans(tenant_id: str, limit: int = 20, offset: int = 0) -> list[dict[str, Any]]:
    """List recent scans for a tenant, newest first."""
    pool = _get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT scan_id, target_url, scan_mode, status, score,
                   started_at, completed_at
            FROM scans
            WHERE tenant_id = $1
            ORDER BY started_at DESC NULLS LAST
            LIMIT $2 OFFSET $3
            """,
            tenant_id,
            limit,
            offset,
        )
    return [dict(r) for r in rows]
