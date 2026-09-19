# agentscan/api/worker.py
#
# AgentScan background scan worker.
#
# Run one or more instances of this to process scan jobs from Redis Streams.
# Each instance is stateless: it reads one job, runs run_scan(), writes the
# result to PostgreSQL, publishes progress events, then loops.
#
# Usage:
#   python -m agentscan.api.worker
#   (or launched by the Kubernetes Deployment / Celery equivalent)

from __future__ import annotations

import asyncio
import os
import socket
from datetime import UTC, datetime

from loguru import logger

from agentscan.api.db import close_db, init_db, upsert_scan
from agentscan.api.pubsub import publish_progress
from agentscan.api.queue import (
    STREAM_DEEP,
    STREAM_HIGH,
    STREAM_NORMAL,
    ack_job,
    claim_job,
    ensure_consumer_groups,
)
from agentscan.core.models import ScanMode, Target

WORKER_ID = os.environ.get("WORKER_ID", socket.gethostname())
DEEP_WORKER = os.environ.get("AGENTSCAN_DEEP_WORKER", "false").lower() == "true"


async def _run_one_job(stream_name: str, entry_id: str, job: dict) -> None:
    scan_id = job["scan_id"]
    tenant_id = job["tenant_id"]
    t = job["target"]

    # Mark as running
    now = datetime.now(UTC).isoformat()
    await upsert_scan(
        scan_id=scan_id,
        tenant_id=tenant_id,
        target_url=t.get("target_url", ""),
        scan_mode=t.get("scan_mode", "SCAN"),
        status="running",
        started_at=now,
    )
    await publish_progress(scan_id, {"status": "running", "progress": 0})

    try:
        target = Target(
            url=t["target_url"],
            mode=ScanMode(t.get("scan_mode", "SCAN")),
            framework=t.get("framework", "auto"),
            timeout=t.get("timeout", 30),
            concurrency=t.get("concurrency") or 10,
            extra_headers=t.get("headers", {}),
            system_prompt=t.get("system_prompt"),
        )

        from agentscan.core.runner import run_scan

        report = await run_scan(target)

        completed_at = datetime.now(UTC).isoformat()
        await upsert_scan(
            scan_id=scan_id,
            tenant_id=tenant_id,
            target_url=target.url,
            scan_mode=target.mode.value,
            status="completed",
            score=report.score,
            started_at=now,
            completed_at=completed_at,
            report_json=report.model_dump(mode="json"),
        )
        await publish_progress(
            scan_id,
            {
                "status": "completed",
                "progress": 100,
                "score": report.score,
                "findings": len(report.findings),
            },
        )
        logger.info(f"[{WORKER_ID}] Scan {scan_id} completed. Score={report.score}")

    except Exception as exc:  # noqa: BLE001
        logger.error(f"[{WORKER_ID}] Scan {scan_id} failed: {exc}")
        await upsert_scan(
            scan_id=scan_id,
            tenant_id=tenant_id,
            target_url=t.get("target_url", ""),
            scan_mode=t.get("scan_mode", "SCAN"),
            status="failed",
        )
        await publish_progress(scan_id, {"status": "failed", "error": str(exc)})

    finally:
        await ack_job(stream_name, entry_id)


async def worker_loop() -> None:
    await init_db()
    await ensure_consumer_groups()

    streams = [STREAM_DEEP] if DEEP_WORKER else [STREAM_HIGH, STREAM_NORMAL]
    logger.info(f"[{WORKER_ID}] Worker started. Listening on streams: {streams}")

    while True:
        try:
            result = await claim_job(WORKER_ID, streams=streams)
            if result is None:
                continue  # timeout — loop
            stream_name, entry_id, job = result
            await _run_one_job(stream_name, entry_id, job)
        except KeyboardInterrupt:
            break
        except Exception as exc:  # noqa: BLE001
            logger.error(f"[{WORKER_ID}] Worker loop error: {exc}")
            await asyncio.sleep(2)

    await close_db()
    logger.info(f"[{WORKER_ID}] Worker stopped.")


if __name__ == "__main__":
    asyncio.run(worker_loop())
