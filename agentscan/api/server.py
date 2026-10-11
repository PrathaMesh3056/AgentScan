# agentscan/api/server.py
#
# AgentScan multi-tenant REST API.
#
# Endpoints:
#   POST   /token                       — tenant-bound enrollment (optional)
#   POST   /scans                       — enqueue a new scan
#   GET    /scans                       — list scans for the current tenant
#   GET    /scans/{scan_id}             — get scan status + report
#   GET    /scans/{scan_id}/stream      — SSE live progress stream
#   DELETE /scans/{scan_id}             — delete a terminal scan record
#
# Authentication: Bearer JWT (see agentscan/api/auth.py).
# Persistence:    PostgreSQL via agentscan/api/db.py.
# Task queue:     Redis Streams via agentscan/api/queue.py.

from __future__ import annotations

import asyncio
import contextlib
import os
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, StreamingResponse
from loguru import logger
from pydantic import BaseModel, ConfigDict, Field

from agentscan.api.auth import configure_auth, get_current_tenant, issue_enrollment_token
from agentscan.api.contracts import TERMINAL_STATES, ScanRequest, allowed_target_hosts
from agentscan.api.data_policy import data_cipher
from agentscan.api.db import (
    IdempotencyConflict,
    TenantQuotaExceeded,
    cancel_scan,
    check_db,
    close_db,
    delete_terminal_scan,
    dispatch_outbox,
    get_scan,
    init_db,
    list_scans,
    prune_expired_records,
    read_scan_events,
    submit_scan,
    validate_idempotency_key,
)
from agentscan.api.limits import RequestBodyLimit
from agentscan.api.policy import authorize_target, tenant_policies
from agentscan.api.queue import check_redis, ensure_consumer_groups
from agentscan.core.canary import canary_manager
from agentscan.telemetry.otel import get_metrics_response

# ── Pydantic request/response schemas ─────────────────────────────────────────


class TokenRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenant_id: str = Field(..., min_length=1, max_length=128, description="Tenant identifier")
    secret: str = Field(
        ..., max_length=4096, description="Enrollment credential bound to this tenant"
    )


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    tenant_id: str


class ScanEnqueuedResponse(BaseModel):
    scan_id: str
    status: str = "queued"
    stream_url: str


class ScanStatusResponse(BaseModel):
    scan_id: str
    tenant_id: str
    target_url: str
    scan_mode: str
    status: str
    score: int | None
    started_at: datetime | None
    completed_at: datetime | None
    report: dict[str, Any] | None  # full ScanReport JSON, or None if pending


# ── App factory ───────────────────────────────────────────────────────────────


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    configure_auth()
    allowed_target_hosts()
    tenant_policies()
    data_cipher()
    retention_days = int(os.environ.get("AGENTSCAN_RETENTION_DAYS", "7"))
    if not 1 <= retention_days <= 365:
        raise ValueError("AGENTSCAN_RETENTION_DAYS must be between 1 and 365.")
    relay = None
    try:
        await init_db()
        await ensure_consumer_groups()

        async def recover_delivery() -> None:
            cycle = 0
            while True:
                try:
                    await dispatch_outbox()
                    if cycle % 60 == 0:
                        await prune_expired_records(retention_days)
                except Exception as exc:
                    logger.warning(
                        "Delivery/retention reconciliation deferred: {}", type(exc).__name__
                    )
                cycle += 1
                await asyncio.sleep(1)

        relay = asyncio.create_task(recover_delivery())
        yield
    finally:
        if relay is not None:
            relay.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await relay
        try:
            await close_db()
        except Exception as exc:
            logger.warning(f"Error closing database connection pool on shutdown: {exc}")


def create_api_app() -> FastAPI:
    app = FastAPI(
        title="AgentScan API",
        version="0.2.0",
        description="Multi-tenant REST API for AgentScan security scans",
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            origin.strip()
            for origin in os.environ.get("AGENTSCAN_CORS_ORIGINS", "").split(",")
            if origin.strip()
        ],
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.add_middleware(RequestBodyLimit)

    @app.get("/", include_in_schema=False)
    async def root() -> RedirectResponse:
        """Redirect root path to interactive Swagger UI documentation."""
        return RedirectResponse(url="/docs")

    # ── Auth ──────────────────────────────────────────────────────────────────

    @app.post("/token", response_model=TokenResponse, tags=["auth"])
    async def issue_token(req: TokenRequest) -> TokenResponse:
        """Issue a token only for the identity bound to an enrollment credential."""
        token = issue_enrollment_token(req.tenant_id, req.secret)
        return TokenResponse(access_token=token, tenant_id=req.tenant_id)

    # ── Scans ─────────────────────────────────────────────────────────────────

    @app.post(
        "/scans",
        response_model=ScanEnqueuedResponse,
        status_code=status.HTTP_202_ACCEPTED,
        tags=["scans"],
    )
    async def enqueue_scan_endpoint(
        req: ScanRequest,
        idempotency_key: Annotated[list[str] | None, Header()] = None,
        tenant_id: str = Depends(get_current_tenant),
    ) -> ScanEnqueuedResponse:
        """Submit a new scan job. Returns immediately with a scan_id."""
        scan_id = str(uuid.uuid4())
        now = datetime.now(UTC)
        key = None
        if idempotency_key is not None:
            if len(idempotency_key) != 1:
                raise HTTPException(
                    status_code=400, detail="Provide exactly one Idempotency-Key header."
                )
            try:
                key = validate_idempotency_key(idempotency_key[0])
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
        try:
            policy = authorize_target(tenant_id, req.target_url)
            if req.analysis_mode == "local" and not policy.allow_local_model_analysis:
                raise PermissionError("Local model analysis is not enabled for this tenant.")
            if req.analysis_mode == "external" and not policy.allow_external_model_analysis:
                raise PermissionError("External analysis is not enabled for this tenant.")
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc

        def check_analysis_configuration() -> None:
            if req.analysis_mode == "external":
                from agentscan.core.external_analysis import external_model_name, provider_key

                try:
                    provider, _ = external_model_name(
                        os.environ.get("AGENTSCAN_EXTERNAL_MODEL", "")
                    )
                    provider_key(provider, allow_dotenv=False)
                except RuntimeError as exc:
                    raise HTTPException(
                        status_code=503, detail="External analysis configuration unavailable."
                    ) from exc

        target_payload = req.model_dump()
        if req.indirect_adapter is None:
            # Preserve prior admission fingerprints for clients without this capability.
            target_payload.pop("indirect_adapter")
        job = {"scan_id": scan_id, "tenant_id": tenant_id, "target": target_payload}
        scan_status = "queued"
        replayed = False
        try:
            if key is None:
                check_analysis_configuration()
                await submit_scan(job, now, policy.max_active_scans, policy.submissions_per_hour)
            else:
                submission = await submit_scan(
                    job,
                    now,
                    policy.max_active_scans,
                    policy.submissions_per_hour,
                    idempotency_key=key,
                    admission_check=check_analysis_configuration,
                )
                if submission is None:
                    raise RuntimeError("Missing idempotent submission result.")
                scan_id, scan_status, replayed = (
                    submission.scan_id,
                    submission.status,
                    submission.replayed,
                )
        except HTTPException:
            raise
        except IdempotencyConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except TenantQuotaExceeded as exc:
            raise HTTPException(
                status_code=429, detail=str(exc), headers={"Retry-After": "60"}
            ) from exc
        except Exception as exc:
            raise HTTPException(status_code=503, detail="Scan persistence unavailable.") from exc
        if not replayed:
            try:
                await dispatch_outbox(scan_id)
            except Exception:
                logger.warning("Scan {} committed; background relay will retry delivery.", scan_id)

        return ScanEnqueuedResponse(
            scan_id=scan_id,
            status=scan_status,
            stream_url=f"/scans/{scan_id}/stream",
        )

    @app.get("/scans", tags=["scans"])
    async def list_scans_endpoint(
        limit: int = Query(default=20, ge=1, le=100),
        offset: int = Query(default=0, ge=0),
        tenant_id: str = Depends(get_current_tenant),
    ) -> list[dict[str, Any]]:
        """List recent scans for the authenticated tenant."""
        return await list_scans(tenant_id, limit=limit, offset=offset)

    @app.get(
        "/scans/{scan_id}",
        response_model=ScanStatusResponse,
        tags=["scans"],
    )
    async def get_scan_endpoint(
        scan_id: str,
        tenant_id: str = Depends(get_current_tenant),
    ) -> ScanStatusResponse:
        """Get the status and (if completed) the full report for a scan."""
        row = await get_scan(scan_id, tenant_id)
        if row is None:
            raise HTTPException(status_code=404, detail="Scan not found.")
        return ScanStatusResponse(
            scan_id=row["scan_id"],
            tenant_id=row["tenant_id"],
            target_url=row["target_url"] or "",
            scan_mode=row["scan_mode"] or "SCAN",
            status=row["status"],
            score=row["score"],
            started_at=row["started_at"],
            completed_at=row["completed_at"],
            report=row["report_json"],
        )

    @app.get("/scans/{scan_id}/stream", tags=["scans"])
    async def stream_scan_progress(
        scan_id: str,
        request: Request,
        last_event_id: str | None = Header(default=None, max_length=20),
        tenant_id: str = Depends(get_current_tenant),
    ) -> StreamingResponse:
        """
        Server-Sent Events stream for live scan progress.
        Emits JSON progress events until the scan completes or fails.
        """
        row = await get_scan(scan_id, tenant_id)
        if row is None:
            raise HTTPException(status_code=404, detail="Scan not found.")

        import json as _json

        if last_event_id is not None and (
            not last_event_id.isascii()
            or not last_event_id.isdigit()
            or int(last_event_id) > 2**63 - 1
        ):
            raise HTTPException(status_code=400, detail="Invalid Last-Event-ID.")
        cursor = int(last_event_id or "0")

        async def _event_generator():
            nonlocal cursor
            while not await request.is_disconnected():
                events = await read_scan_events(scan_id, tenant_id, cursor)
                for item in events:
                    cursor = item["sequence"]
                    yield f"id: {cursor}\ndata: {_json.dumps(item['event'])}\n\n"
                current = await get_scan(scan_id, tenant_id)
                if current is None:
                    return
                if current["status"] in TERMINAL_STATES and len(events) < 100:
                    # Legacy rows or cursors beyond this scan still get its authoritative state.
                    if not events:
                        yield f"data: {_json.dumps({'status': current['status'], 'score': current['score']})}\n\n"
                    return
                if len(events) < 100:
                    yield ": keepalive\n\n"
                    await asyncio.sleep(1)

        return StreamingResponse(
            _event_generator(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
            },
        )

    @app.post("/scans/{scan_id}/cancel", tags=["scans"])
    async def cancel_scan_endpoint(
        scan_id: str, tenant_id: str = Depends(get_current_tenant)
    ) -> dict[str, str]:
        if await get_scan(scan_id, tenant_id) is None:
            raise HTTPException(status_code=404, detail="Scan not found.")
        if not await cancel_scan(scan_id, tenant_id):
            raise HTTPException(status_code=409, detail="Scan is already terminal.")
        return {"status": "cancelled"}

    @app.delete("/scans/{scan_id}", status_code=204, tags=["scans"])
    async def delete_scan_endpoint(
        scan_id: str,
        tenant_id: str = Depends(get_current_tenant),
    ) -> None:
        """Delete only terminal records; queued/running work requires explicit cancellation."""
        row = await get_scan(scan_id, tenant_id)
        if row is None:
            raise HTTPException(status_code=404, detail="Scan not found.")
        if row["status"] not in TERMINAL_STATES:
            raise HTTPException(
                status_code=409, detail="Queued or running scans cannot be deleted."
            )
        result = await delete_terminal_scan(scan_id, tenant_id)
        if result == "DELETE 0":
            raise HTTPException(status_code=404, detail="Scan not found.")

    # ── Observability & Canary ────────────────────────────────────────────────

    @app.get("/health/live", include_in_schema=False)
    async def live() -> dict[str, str]:
        return {"status": "alive"}

    @app.get("/health/ready", include_in_schema=False)
    async def ready() -> dict[str, str]:
        try:
            async with asyncio.timeout(3), asyncio.TaskGroup() as checks:
                checks.create_task(check_db())
                checks.create_task(check_redis())
        except Exception as exc:
            raise HTTPException(status_code=503, detail="Required dependency unavailable.") from exc
        return {"status": "ready"}

    @app.get("/metrics", include_in_schema=False)
    async def metrics() -> Response:
        """Prometheus metrics endpoint for scraping."""
        content, media_type = get_metrics_response()
        return Response(content=content, media_type=media_type)

    @app.get("/canary/callback/{token_id}", tags=["Canary"])
    @app.post("/canary/callback/{token_id}", tags=["Canary"])
    async def canary_callback(token_id: str, request: Request) -> dict[str, str]:
        """
        Webhook receiver for out-of-band canary tokens.
        Triggered when an exploited agent makes an external network request with leaked data.
        """
        headers = dict(request.headers)
        query = dict(request.query_params)
        body = (await request.body()).decode("utf-8", errors="replace")

        canary_manager.record_hit(
            token_id=token_id,
            metadata={
                "client_host": request.client.host if request.client else "unknown",
                "headers": headers,
                "query": query,
                "body": body[:1000],
            },
        )
        return {"status": "ok", "recorded": "true"}

    return app


app = create_api_app()
