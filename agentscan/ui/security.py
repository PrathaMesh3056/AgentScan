"""Dashboard response hardening and server-owned filesystem scopes."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from fastapi import HTTPException, Request

from agentscan.guard.path import PathSecurityError
from agentscan.remediation.paths import contained_path

# Baseline policy for the dashboard. Inline script and style stay allowed because
# the existing markup relies on inline handlers, attributes and the theme
# bootstrap; every other fetch type is pinned to this origin.
DASHBOARD_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "frame-src 'none'; "
    "base-uri 'none'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)

STANDARD_SECURITY_HEADERS: dict[str, str] = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "X-Permitted-Cross-Domain-Policies": "none",
}

REDACTED_PATH = "[redacted path]"

# Filesystem paths that reach an error body. Order matters: drive letters and UNC
# shares are matched before POSIX-style paths.
_WINDOWS_PATH = re.compile(r"(?<![A-Za-z0-9])[A-Za-z]:[\\/][^\s'\"<>|;,)]*")
_UNC_PATH = re.compile(r"(?<![A-Za-z0-9])\\\\[^\s'\"<>|;,)]+")
_POSIX_PATH = re.compile(r"(?<![\w:/])/(?:[A-Za-z0-9_.~@%+-]+/)*[A-Za-z0-9_.~@%+-]+")


def redact_absolute_paths(message: str) -> str:
    """Replace filesystem paths in display text with a stable placeholder.

    Dashboard error bodies must stay actionable without disclosing where the
    project, its containment root or a healing target lives on disk.
    """
    redacted = _WINDOWS_PATH.sub(REDACTED_PATH, message)
    redacted = _UNC_PATH.sub(REDACTED_PATH, redacted)
    return _POSIX_PATH.sub(REDACTED_PATH, redacted)


def public_error_detail(detail: str, limit: int = 512) -> str:
    """Return an exception detail that is safe to place in a 4xx response body."""
    return redact_absolute_paths(detail[:limit])


def security_headers(*, secure: bool = False) -> dict[str, str]:
    """Return the standard header set for a dashboard response."""
    headers = dict(STANDARD_SECURITY_HEADERS)
    if secure:
        headers["Strict-Transport-Security"] = "max-age=31536000"
    return headers


def apply_security_headers(response: Any, *, secure: bool = False) -> Any:
    """Attach the standard headers, preserving a policy set by the route."""
    for name, value in security_headers(secure=secure).items():
        if name == "Cache-Control":
            response.headers[name] = value
        else:
            response.headers.setdefault(name, value)
    policy = response.headers.get("Content-Security-Policy") or DASHBOARD_CSP
    if "frame-ancestors" not in policy:
        policy = f"{policy}; frame-ancestors 'none'"
    response.headers["Content-Security-Policy"] = policy
    return response


def dashboard_target_error(target_url: str, dashboard_url: str) -> str | None:
    """Reject using this dashboard's origin as an agent target, without probing it."""
    if "://" not in target_url:
        target_url = "http://" + target_url
    try:
        target = urlsplit(target_url)
        dashboard = urlsplit(dashboard_url)
        target_host = (target.hostname or "").lower().rstrip(".")
        dashboard_host = (dashboard.hostname or "").lower().rstrip(".")
        target_port = target.port or (443 if target.scheme in ("https", "wss", "mcp+sses") else 80)
        dashboard_port = dashboard.port or (443 if dashboard.scheme == "https" else 80)
    except ValueError:
        return "The target endpoint has an invalid hostname or port."
    loopback_hosts = {"127.0.0.1", "localhost", "::1"}
    same_host = target_host == dashboard_host or (
        target_host in loopback_hosts and dashboard_host in loopback_hosts
    )
    if same_host and target_port == dashboard_port:
        return (
            "This address points to the AgentScan dashboard, not an agent endpoint. "
            "Enter the URL of the agent you want to assess, using its own port or host."
        )
    return None


def project_root(request: Request, requested: str | None = None) -> Path:
    root: Path = request.app.state.project_root
    if requested is not None and not isinstance(requested, str):
        raise HTTPException(status_code=400, detail="Project root must be a string")
    if requested is not None and requested != ".":
        candidate = Path(requested)
        if not candidate.is_absolute():
            candidate = root / candidate
        if candidate.resolve() != root:
            raise HTTPException(
                status_code=403, detail="Dashboard project root is server configured"
            )
    return root


def project_path(request: Request, requested: str) -> Path:
    if not isinstance(requested, str) or not requested:
        raise HTTPException(status_code=400, detail="Project path must be a nonempty string")
    try:
        return contained_path(project_root(request), requested)
    except PathSecurityError as error:
        raise HTTPException(
            status_code=403,
            detail="Choose a path inside the dashboard's configured project directory.",
        ) from error
