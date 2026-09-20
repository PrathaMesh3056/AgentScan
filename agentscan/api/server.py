# agentscan/api/server.py
#
# AgentScan multi-tenant REST API.
#
# Endpoints:
#   POST   /token                       — get a JWT for a tenant (dev convenience)
#   POST   /scans                       — enqueue a new scan
#   GET    /scans                       — list scans for the current tenant
#   GET    /scans/{scan_id}             — get scan status + report
#   GET    /scans/{scan_id}/stream      — SSE live progress stream
#   DELETE /scans/{scan_id}             — cancel / delete a scan record
#
# Authentication: Bearer JWT (see agentscan/api/auth.py).
# Persistence:    PostgreSQL via agentscan/api/db.py.
# Task queue:     Redis Streams via agentscan/api/queue.py.

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, StreamingResponse
from loguru import logger
from pydantic import BaseModel, Field

from agentscan.api.auth import create_token, get_current_tenant
from agentscan.api.db import close_db, get_scan, init_db, list_scans, upsert_scan
from agentscan.api.pubsub import subscribe_progress
from agentscan.api.queue import enqueue_scan, ensure_consumer_groups
from agentscan.core.canary import canary_manager
from agentscan.telemetry.otel import get_metrics_response

# ── Pydantic request/response schemas ─────────────────────────────────────────


class TokenRequest(BaseModel):
    tenant_id: str = Field(..., description="Tenant identifier")
    secret: str = Field(..., description="Shared pre-shared key for dev token issue")


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    tenant_id: str


class ScanRequest(BaseModel):
    target_url: str = Field(..., description="Target agent endpoint URL")
    scan_mode: str = Field(default="SCAN", description="SCAN | EXPLOIT | DEEP")
    system_prompt: str | None = Field(default=None)
    framework: str = Field(default="auto")
    timeout: int = Field(default=30, ge=5, le=300)
    concurrency: int | None = Field(default=None, ge=1, le=50)
    headers: dict[str, str] = Field(default_factory=dict)


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
    started_at: str | None
    completed_at: str | None
    report: dict[str, Any] | None  # full ScanReport JSON, or None if pending


# ── App factory ───────────────────────────────────────────────────────────────

TOKEN_PSK = __import__("os").environ.get("AGENTSCAN_TOKEN_PSK", "dev-psk")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    try:
        await init_db()
        await ensure_consumer_groups()
    except Exception as exc:
        logger.warning(f"Failed to initialize database or consumer groups on startup: {exc}")
    try:
        yield
    finally:
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
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/", include_in_schema=False)
    async def root() -> RedirectResponse:
        """Redirect root path to interactive Swagger UI documentation."""
        return RedirectResponse(url="/docs")

    # ── Auth ──────────────────────────────────────────────────────────────────

    @app.post("/token", response_model=TokenResponse, tags=["auth"])
    async def issue_token(req: TokenRequest) -> TokenResponse:
        """Issue a JWT for a tenant. Requires AGENTSCAN_TOKEN_PSK match."""
        if req.secret != TOKEN_PSK:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid PSK.")
        token = create_token(req.tenant_id)
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
        tenant_id: str = Depends(get_current_tenant),
    ) -> ScanEnqueuedResponse:
        """Submit a new scan job. Returns immediately with a scan_id."""
        scan_id = str(uuid.uuid4())
        now = datetime.now(UTC).isoformat()

        # Persist initial queued row
        await upsert_scan(
            scan_id=scan_id,
            tenant_id=tenant_id,
            target_url=req.target_url,
            scan_mode=req.scan_mode,
            status="queued",
            started_at=now,
        )

        # Enqueue the job for a worker to pick up
        job = {
            "scan_id": scan_id,
            "tenant_id": tenant_id,
            "target": req.model_dump(),
        }
        await enqueue_scan(job, scan_mode=req.scan_mode)

        return ScanEnqueuedResponse(
            scan_id=scan_id,
            status="queued",
            stream_url=f"/scans/{scan_id}/stream",
        )

    @app.get("/scans", tags=["scans"])
    async def list_scans_endpoint(
        limit: int = 20,
        offset: int = 0,
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
            started_at=str(row["started_at"]) if row["started_at"] else None,
            completed_at=str(row["completed_at"]) if row["completed_at"] else None,
            report=row["report_json"],
        )

    @app.get("/scans/{scan_id}/stream", tags=["scans"])
    async def stream_scan_progress(
        scan_id: str,
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

        async def _event_generator():
            async for event in subscribe_progress(scan_id):
                data = _json.dumps(event)
                yield f"data: {data}\n\n"
                if event.get("status") in ("completed", "failed"):
                    break

        return StreamingResponse(
            _event_generator(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
            },
        )

    @app.delete("/scans/{scan_id}", status_code=204, tags=["scans"])
    async def delete_scan_endpoint(
        scan_id: str,
        tenant_id: str = Depends(get_current_tenant),
    ) -> None:
        """Delete a scan record. Does not cancel an actively running worker job."""
        from agentscan.api.db import _get_pool

        pool = _get_pool()
        async with pool.acquire() as conn:
            result = await conn.execute(
                "DELETE FROM scans WHERE scan_id = $1 AND tenant_id = $2",
                scan_id,
                tenant_id,
            )
        if result == "DELETE 0":
            raise HTTPException(status_code=404, detail="Scan not found.")

    # ── Observability & Canary ────────────────────────────────────────────────

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
