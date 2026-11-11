# agentscan/ui/routers/gateway.py
#
# Read-only runtime gateway health and readiness status for the dashboard.
# The panel reports probe state only; it never evaluates policy, receipts or
# tool decisions and never exposes gateway metrics.

from __future__ import annotations

import os
import re
import time
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

import httpx
from fastapi import APIRouter
from fastapi.responses import JSONResponse

router = APIRouter(tags=["gateway"])

LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
REASON_PATTERN = re.compile(r"^[a-z0-9_]{1,64}$")
HEALTHY_STATUS = "ok"
READY_STATUS = "ready"
PROBE_TIMEOUT_SECONDS = 1.5
NOT_CONFIGURED_REASON = "gateway_url_unset"
MISCONFIGURED_REASON = "gateway_url_invalid"
UNKNOWN_REASON = "unknown_reason"


def gateway_base_url() -> str | None:
    """Return the configured runtime gateway base URL, or None when unset."""
    value = os.environ.get("AGENTSCAN_GATEWAY_URL", "").strip()
    return value or None


def _is_loopback_host(hostname: str | None) -> bool:
    normalized = (hostname or "").strip().strip("[]").lower()
    return normalized in LOOPBACK_HOSTS


def gateway_url_is_valid(value: str) -> bool:
    """Accept loopback HTTP(S) base URLs only; reject credentials, paths, queries."""
    try:
        parsed = urlsplit(value)
        _ = parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme in {"http", "https"}
        and _is_loopback_host(parsed.hostname)
        and parsed.username is None
        and parsed.password is None
        and not parsed.query
        and not parsed.fragment
        and parsed.path in {"", "/"}
    )


async def _probe_health(client: httpx.AsyncClient, base_url: str) -> dict[str, Any]:
    started = time.monotonic()
    try:
        response = await client.get(f"{base_url}/healthz")
        latency_ms = round((time.monotonic() - started) * 1000, 3)
        if response.status_code != 200:
            return {
                "http_status": response.status_code,
                "status": "unhealthy",
                "latency_ms": latency_ms,
                "reason": f"health_status_{response.status_code}",
            }
        try:
            payload = response.json()
        except Exception:
            payload = None
        if isinstance(payload, dict) and payload.get("status") == HEALTHY_STATUS:
            return {"http_status": 200, "status": HEALTHY_STATUS, "latency_ms": latency_ms}
        return {
            "http_status": response.status_code,
            "status": "unhealthy",
            "latency_ms": latency_ms,
            "reason": "health_invalid",
        }
    except httpx.TimeoutException:
        return {
            "http_status": None,
            "status": "unreachable",
            "latency_ms": round((time.monotonic() - started) * 1000, 3),
            "reason": "health_timeout",
        }
    except Exception:
        return {
            "http_status": None,
            "status": "unreachable",
            "latency_ms": round((time.monotonic() - started) * 1000, 3),
            "reason": "health_unreachable",
        }


async def _probe_readiness(client: httpx.AsyncClient, base_url: str) -> dict[str, Any]:
    started = time.monotonic()
    try:
        response = await client.get(f"{base_url}/readyz")
        latency_ms = round((time.monotonic() - started) * 1000, 3)
        if response.status_code == 200:
            try:
                payload = response.json()
            except Exception:
                payload = None
            if isinstance(payload, dict) and payload.get("status") == READY_STATUS:
                return {
                    "http_status": 200,
                    "status": READY_STATUS,
                    "latency_ms": latency_ms,
                    "reason": None,
                }
        if response.status_code == 503:
            try:
                payload = response.json()
            except Exception:
                payload = None
            reason = payload.get("reason") if isinstance(payload, dict) else None
            bounded = (
                reason
                if isinstance(reason, str) and REASON_PATTERN.fullmatch(reason)
                else UNKNOWN_REASON
            )
            return {
                "http_status": 503,
                "status": "not_ready",
                "latency_ms": latency_ms,
                "reason": bounded,
            }
        return {
            "http_status": response.status_code,
            "status": "not_ready",
            "latency_ms": latency_ms,
            "reason": f"ready_status_{response.status_code}",
        }
    except httpx.TimeoutException:
        return {
            "http_status": None,
            "status": "not_ready",
            "latency_ms": round((time.monotonic() - started) * 1000, 3),
            "reason": "ready_timeout",
        }
    except Exception:
        return {
            "http_status": None,
            "status": "not_ready",
            "latency_ms": round((time.monotonic() - started) * 1000, 3),
            "reason": "ready_unreachable",
        }


async def probe_gateway(
    base_url: str, *, client: httpx.AsyncClient | None = None
) -> dict[str, Any]:
    """Probe the runtime gateway health and readiness endpoints with bounded results."""
    owned_client = client is None
    active_client = (
        client
        if client is not None
        else httpx.AsyncClient(
            timeout=PROBE_TIMEOUT_SECONDS, follow_redirects=False, trust_env=False
        )
    )
    try:
        health = await _probe_health(active_client, base_url)
        readiness = await _probe_readiness(active_client, base_url)
    finally:
        if owned_client:
            await active_client.aclose()
    if health.get("status") != HEALTHY_STATUS:
        status = str(health.get("status"))
        reason = str(health.get("reason"))
    elif readiness.get("status") == READY_STATUS:
        status = READY_STATUS
        reason = None
    else:
        status = "not_ready"
        reason = str(readiness.get("reason"))
    return {
        "configured": True,
        "url": base_url,
        "status": status,
        "reason": reason,
        "health": health,
        "readiness": readiness,
        "checked_at": datetime.now(UTC).isoformat(),
    }


@router.get("/api/gateway/status")
async def api_gateway_status() -> Any:
    base_url = gateway_base_url()
    if base_url is None:
        return JSONResponse(
            {
                "configured": False,
                "status": "not_configured",
                "reason": NOT_CONFIGURED_REASON,
                "url": None,
                "health": None,
                "readiness": None,
                "checked_at": datetime.now(UTC).isoformat(),
            },
            headers={"Cache-Control": "no-store"},
        )
    if not gateway_url_is_valid(base_url):
        return JSONResponse(
            {
                "configured": True,
                "status": "misconfigured",
                "reason": MISCONFIGURED_REASON,
                "url": None,
                "health": None,
                "readiness": None,
                "checked_at": datetime.now(UTC).isoformat(),
            },
            headers={"Cache-Control": "no-store"},
        )
    return JSONResponse(
        await probe_gateway(base_url.rstrip("/")), headers={"Cache-Control": "no-store"}
    )
