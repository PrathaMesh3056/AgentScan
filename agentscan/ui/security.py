"""Server-owned filesystem scopes for dashboard operations."""

from pathlib import Path
from urllib.parse import urlsplit

from fastapi import HTTPException, Request

from agentscan.guard.path import PathSecurityError
from agentscan.remediation.paths import contained_path


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
        raise HTTPException(status_code=403, detail=str(error)) from error
