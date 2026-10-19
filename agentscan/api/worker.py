"""At-least-once scan worker with fenced DB leases and durable terminal ACKs."""

from __future__ import annotations

import asyncio
import contextlib
import os
import signal
import socket
import uuid
from typing import Any

from loguru import logger
from pydantic import ValidationError

from agentscan.api.contracts import (
    TERMINAL_STATES,
    ScanJob,
    ScanRequest,
    ScanState,
    allowed_target_hosts,
)
from agentscan.api.data_policy import data_cipher, decrypt_target, sanitize_report
from agentscan.api.db import (
    claim_scan,
    close_db,
    dispatch_outbox,
    fail_exhausted_scan,
    finish_scan,
    get_scan,
    init_db,
    renew_scan_lease,
)
from agentscan.api.policy import authorize_target, tenant_policies
from agentscan.api.pubsub import publish_progress
from agentscan.api.queue import (
    STREAM_DEEP,
    STREAM_HIGH,
    STREAM_NORMAL,
    ack_job,
    claim_job,
    ensure_consumer_groups,
    heartbeat_job,
    quarantine_job,
)
from agentscan.core.models import Framework, ScanMode, Target

WORKER_ID = os.environ.get("WORKER_ID", socket.gethostname())
DEEP_WORKER = os.environ.get("AGENTSCAN_DEEP_WORKER", "false").lower() == "true"
LEASE_SECONDS = float(os.environ.get("AGENTSCAN_WORKER_LEASE_SECONDS", "60"))
MAX_ATTEMPTS = int(os.environ.get("AGENTSCAN_WORKER_MAX_ATTEMPTS", "3"))


class LeaseLost(RuntimeError):
    pass


async def _publish(scan_id: str, event: dict[str, Any]) -> None:
    try:
        await publish_progress(scan_id, event)
    except Exception:
        logger.warning(
            "Progress delivery unavailable for scan {}; durable state remains authoritative.",
            scan_id,
        )


async def _heartbeat(
    scan_id: str,
    tenant_id: str,
    token: str,
    stream: str,
    entry: str,
    owner: asyncio.Task[Any],
    lost: asyncio.Event,
) -> None:
    try:
        while True:
            await asyncio.sleep(LEASE_SECONDS / 3)
            if not await renew_scan_lease(scan_id, tenant_id, token, LEASE_SECONDS):
                raise LeaseLost("Database lease expired or ownership changed.")
            if not await heartbeat_job(stream, entry, WORKER_ID):
                raise LeaseLost("Redis delivery is no longer pending.")
    except asyncio.CancelledError:
        raise
    except Exception:
        lost.set()
        owner.cancel()


async def _run_one_job(stream_name: str, entry_id: str, raw_job: dict[str, Any]) -> None:
    scan_id, tenant_id = raw_job.get("scan_id"), raw_job.get("tenant_id")
    if not isinstance(scan_id, str) or not isinstance(tenant_id, str):
        await quarantine_job(stream_name, entry_id, "Invalid scan identity in job envelope.")
        return
    row = await get_scan(scan_id, tenant_id)
    if row is None:
        await quarantine_job(
            stream_name, entry_id, "No corresponding persisted tenant scan record."
        )
        return
    if row["status"] in TERMINAL_STATES:
        await ack_job(stream_name, entry_id)
        return
    token = str(uuid.uuid4())
    if not await claim_scan(scan_id, tenant_id, token, LEASE_SECONDS, MAX_ATTEMPTS):
        if await fail_exhausted_scan(scan_id, tenant_id, MAX_ATTEMPTS):
            await _publish(scan_id, {"status": "failed", "error": "Worker retry limit exhausted."})
            await ack_job(stream_name, entry_id)
        return
    owner = asyncio.current_task()
    assert owner is not None
    lost = asyncio.Event()
    heartbeat = asyncio.create_task(
        _heartbeat(scan_id, tenant_id, token, stream_name, entry_id, owner, lost)
    )
    try:
        outcome: ScanState = "failed"
        score: int | None = None
        payload: dict[str, Any]
        try:
            job = ScanJob.model_validate(raw_job)
            t = ScanRequest.model_validate(decrypt_target(row.get("request_json")))
            if job.target is not None and job.target != t:
                raise ValueError("Queue request does not match the encrypted persisted submission.")
            policy = authorize_target(tenant_id, t.target_url)
            if t.analysis_mode == "local" and not policy.allow_local_model_analysis:
                raise PermissionError("Local model analysis is not enabled for this tenant.")
            if t.analysis_mode == "external" and not policy.allow_external_model_analysis:
                raise PermissionError("External analysis is not enabled for this tenant.")
            target = Target(
                url=t.target_url,
                mode=ScanMode(t.scan_mode),
                framework=Framework(t.framework),
                timeout=t.timeout,
                concurrency=t.concurrency or 10,
                extra_headers=t.headers,
                system_prompt=t.system_prompt,
                indirect_adapter=t.indirect_adapter,
                factuality_baseline=t.factuality_baseline,
                allowed_hosts=sorted(allowed_target_hosts()),
                allowed_origins=policy.origins,
                allowed_networks=policy.networks,
                request_budget=policy.max_target_requests,
                analysis_mode=t.analysis_mode,
                local_model=os.environ.get("AGENTSCAN_LOCAL_MODEL", "ollama/llama3.2"),
                external_model=os.environ.get("AGENTSCAN_EXTERNAL_MODEL", ""),
                data_classification=t.data_classification,
                external_keys_from_dotenv=False,
            )
            await _publish(scan_id, {"status": "running", "progress": 0})
            from agentscan.core.runner import run_scan

            async with asyncio.timeout(policy.max_scan_seconds):
                report = await run_scan(target)
            report.scan_id = scan_id
            report.tenant_id = tenant_id
            report_status = getattr(report, "status", "COMPLETE")
            report_status = getattr(report_status, "value", report_status)
            states: dict[str, ScanState] = {
                "COMPLETE": "completed",
                "INCONCLUSIVE": "inconclusive",
                "ERROR": "failed",
            }
            outcome = states.get(report_status, "inconclusive")
            score = report.score
            payload = sanitize_report(report.model_dump(mode="json"), tuple(t.headers.values()))
        except (ValidationError, ValueError, PermissionError):
            payload = {"error": "Job rejected by service target policy or request schema."}
        except Exception as exc:
            logger.error(
                "[{}] Scan {} execution failed: {}", WORKER_ID, scan_id, type(exc).__name__
            )
            payload = {"error": "Scan execution failed.", "error_type": type(exc).__name__}
        if not await finish_scan(
            scan_id=scan_id,
            tenant_id=tenant_id,
            lease_token=token,
            status=outcome,
            score=score,
            report_json=payload,
        ):
            raise LeaseLost("Terminal result rejected because the lease is no longer owned.")
        await _publish(scan_id, {"status": outcome, "progress": 100, "score": score})
        await ack_job(stream_name, entry_id)
        logger.info("[{}] Scan {} persisted as {}.", WORKER_ID, scan_id, outcome)
    except asyncio.CancelledError:
        if lost.is_set():
            owner.uncancel()
            raise LeaseLost("Dependency failure or lease loss interrupted execution.") from None
        raise
    finally:
        heartbeat.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await heartbeat


async def worker_loop() -> None:
    if not 3 <= LEASE_SECONDS <= 600 or not 1 <= MAX_ATTEMPTS <= 10:
        raise RuntimeError("Worker lease must be 3–600 seconds and max attempts must be 1–10.")
    allowed_target_hosts()
    tenant_policies()
    data_cipher()
    loop = asyncio.get_running_loop()
    owner = asyncio.current_task()
    installed: list[signal.Signals] = []
    if owner is not None:
        for sig in (signal.SIGTERM, signal.SIGINT):
            with contextlib.suppress(NotImplementedError):
                loop.add_signal_handler(sig, owner.cancel)
                installed.append(sig)
    try:
        await init_db()
        await ensure_consumer_groups()
        streams = [STREAM_DEEP] if DEEP_WORKER else [STREAM_HIGH, STREAM_NORMAL]
        logger.info("[{}] Worker started. Streams: {}", WORKER_ID, streams)
        while True:
            try:
                await dispatch_outbox()
                result = await claim_job(
                    WORKER_ID, streams=streams, lease_ms=int(LEASE_SECONDS * 1000)
                )
                streams = streams[1:] + streams[:1]
                if result is not None:
                    await _run_one_job(*result)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error(
                    "[{}] Worker delivery retained for recovery: {}", WORKER_ID, type(exc).__name__
                )
                await asyncio.sleep(2)
    finally:
        for sig in installed:
            loop.remove_signal_handler(sig)
        await close_db()
        logger.info("[{}] Worker stopped.", WORKER_ID)


if __name__ == "__main__":
    asyncio.run(worker_loop())
