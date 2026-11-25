# agentscan/ui/app.py
#
# Local FastAPI dashboard entry point for reports, RBAC graphs, trajectory/SSP, and traffic.

from __future__ import annotations

import json
import os
import secrets
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from loguru import logger

from agentscan.ui.routers import register_all_routers
from agentscan.ui.security import (
    apply_security_headers,
    dashboard_target_error,
    public_error_detail,
)
from agentscan.ui.state import (  # noqa: F401
    STATIC_DIR,
    EventBus,
    UiState,
    event_bus,
    state,
)

# Single source of truth for dashboard page routes.
PAGE_ROUTES: tuple[str, ...] = (
    "/",
    "/report",
    "/overview",
    "/pipelines",
    "/findings",
    "/trajectory",
    "/rbac",
    "/identity",
    "/traffic",
    "/guardrails",
    "/gateway",
    "/compliance",
    "/heal",
    "/healing",
    "/team",
    "/mcp",
    "/sentinel",
    "/audit",
    "/benchmark",
)


def create_app(
    report_path: Path | None = None,
    identity_path: Path | None = None,
    token: str | None = None,
    project_root: Path | None = None,
    allowed_hosts: list[str] | None = None,
) -> Any:
    try:
        from fastapi import FastAPI
        from fastapi.exceptions import RequestValidationError
        from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
        from fastapi.staticfiles import StaticFiles
        from starlette.exceptions import HTTPException
    except ImportError as e:
        raise RuntimeError(
            "The UI extra is not installed. Run: pip install 'agentscan[ui]' "
            "(or uv sync --extra ui)."
        ) from e

    app = FastAPI(
        title="AgentScan API",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )

    @app.exception_handler(RequestValidationError)
    async def _request_validation_error(request: Any, error: Any) -> Any:
        from agentscan.ui.validation import validation_error_response

        fields: dict[str, str] = {}
        for item in error.errors():
            location = item.get("loc", ())
            field = str(location[-1]) if location and location[0] == "query" else "body"
            kind = item.get("type", "")
            fields[field] = (
                "Enter valid JSON; check commas and quotation marks."
                if kind == "json_invalid"
                else "This field is required."
                if kind == "missing"
                else "Enter a whole number for this field."
                if kind in {"int_parsing", "int_type"}
                else "Submit a JSON object containing the requested fields."
                if kind == "dict_type"
                else "Choose a valid value for this field."
            )
        return validation_error_response(fields or {"body": "Enter a valid request."}, status=422)

    @app.exception_handler(HTTPException)
    async def _http_error(request: Any, error: Any) -> Any:
        detail = error.detail
        message = (
            public_error_detail(detail)
            if isinstance(detail, str)
            else "The dashboard request could not be accepted."
        )
        return JSONResponse(
            {"error": message, "field_errors": {"request": message}},
            status_code=error.status_code,
            headers=error.headers,
        )

    def unexpected_error_response(request: Any, error: Exception) -> Any:
        error_id = uuid.uuid4().hex[:12]
        route = request.scope.get("route")
        operation = getattr(route, "name", "dashboard request")
        logger.error(
            "Dashboard operation {} failed [reference {}]: {}",
            operation,
            error_id,
            type(error).__name__,
        )
        return JSONResponse(
            {
                "error": "An unexpected dashboard error occurred. Review the terminal diagnostic reference.",
                "error_id": error_id,
            },
            status_code=500,
        )

    @app.exception_handler(Exception)
    async def _unexpected_error(request: Any, error: Exception) -> Any:
        return unexpected_error_response(request, error)

    active_token = token or os.environ.get("AGENTSCAN_UI_TOKEN")
    session_token = secrets.token_urlsafe(32)
    trusted_hosts = {host.lower() for host in (allowed_hosts or ["127.0.0.1", "localhost", "::1"])}
    root = (project_root or (report_path.parent if report_path else Path.cwd())).resolve(
        strict=True
    )
    if not root.is_dir():
        raise ValueError("UI project_root must be an existing directory")
    app.state.project_root = root
    app.state.profile_root = root / ".agentscan" / "profiles"

    @app.middleware("http")
    async def _auth_and_host_guard(request: Any, call_next: Any) -> Any:
        from fastapi.responses import JSONResponse as _JR

        secure_transport = request.url.scheme == "https"

        def secured(response: Any) -> Any:
            return apply_security_headers(response, secure=secure_transport)

        def deny(payload: dict[str, Any], status_code: int) -> Any:
            # Denials leave the middleware early, so they carry the same headers
            # as a routed response.
            return secured(_JR(payload, status_code=status_code))

        client_host = request.client.host if request.client else ""
        host_header = request.headers.get("host", "")
        try:
            authority = urlsplit("//" + host_header)
            hostname = authority.hostname or ""
            _ = authority.port  # Validate port syntax before relying on this authority.
        except ValueError:
            return deny({"error": "Invalid dashboard Host"}, 403)
        test_host = client_host == "testclient" and hostname == "testserver"
        if (
            authority.username
            or authority.password
            or authority.path
            or authority.query
            or authority.fragment
            or (hostname not in trusted_hosts and not test_host)
        ):
            return deny({"error": "Untrusted dashboard Host"}, 403)
        if client_host not in ("127.0.0.1", "::1", "localhost", "testclient") and not active_token:
            return deny({"error": "AgentScan dashboard is localhost-only"}, 403)
        # CORS alone cannot stop simple cross-site POST requests from changing state.
        origin = request.headers.get("origin")
        expected_origin = f"{request.url.scheme}://{host_header}"
        if origin is not None and origin != expected_origin:
            return deny({"error": "Cross-origin dashboard requests are denied"}, 403)
        # Following a link opens a top-level document with cross-/same-site
        # metadata. That navigation is legitimate; fetches, frames and writes
        # still cannot cross the dashboard's origin boundary.
        page_navigation = (
            request.method == "GET"
            and request.url.path in PAGE_ROUTES
            and request.headers.get("sec-fetch-mode") == "navigate"
            and request.headers.get("sec-fetch-dest") == "document"
        )
        if (
            request.headers.get("sec-fetch-site") in ("cross-site", "same-site")
            and not page_navigation
        ):
            return deny({"error": "Cross-site dashboard requests are denied"}, 403)
        auth_header = request.headers.get("authorization", "")
        bearer = auth_header[7:] if auth_header.startswith("Bearer ") else ""
        bearer_ok = bool(active_token and secrets.compare_digest(bearer, active_token))
        session = request.cookies.get("agentscan_ui_session", "")
        session_ok = secrets.compare_digest(session, session_token)
        # Exchange a page bootstrap token for an HttpOnly session; fetch and EventSource
        # then authenticate without placing credentials in every API/SSE URL.
        bootstrap = request.query_params.get("token", "")
        bootstrap_ok = bool(active_token and secrets.compare_digest(bootstrap, active_token))
        is_page = not request.url.path.startswith(("/api/", "/static/"))
        if bootstrap_ok and request.method == "GET" and is_page:
            response = RedirectResponse(
                str(request.url.remove_query_params("token")), status_code=303
            )
        else:
            if active_token and not (bearer_ok or session_ok):
                return deny({"error": "Unauthorized: invalid or missing token"}, 401)
            if request.method not in ("GET", "HEAD", "OPTIONS") and not (bearer_ok or session_ok):
                return deny({"error": "Open the dashboard to establish a local session"}, 401)
            if request.method == "POST" and request.url.path in {
                "/api/scan",
                "/api/discovery",
                "/api/swarms/run",
                "/api/sentinel/probe",
                "/api/sentinel/start",
                "/api/mcp/invoke",
            }:
                try:
                    payload = await request.json()
                except (json.JSONDecodeError, UnicodeDecodeError):
                    payload = None  # Preserve the route's normal invalid-body response.
                if isinstance(payload, dict):
                    if request.url.path == "/api/mcp/invoke":
                        payload = payload.get("arguments")
                    if isinstance(payload, dict):
                        target = (
                            payload.get("target_url") or payload.get("target") or payload.get("url")
                        )
                        if isinstance(target, str):
                            error = dashboard_target_error(target.strip(), str(request.base_url))
                            if error:
                                field = (
                                    "url" if request.url.path == "/api/discovery" else "target_url"
                                )
                                if request.url.path == "/api/mcp/invoke":
                                    field = "arguments.target_url"
                                return deny(
                                    {"error": error, "field_errors": {field: error}},
                                    400,
                                )
            try:
                response = await call_next(request)
            except Exception as error:
                # Handle before the server's outer exception middleware prints an
                # exception's arbitrary message, which may contain target data.
                response = secured(unexpected_error_response(request, error))
        if bootstrap_ok or (not active_token and request.method == "GET"):
            response.set_cookie(
                "agentscan_ui_session",
                session_token,
                httponly=True,
                # Allow the clean-URL redirect after opening a bootstrap link.
                # Origin/Fetch-Metadata checks independently reject cross-site
                # API requests and mutations, and page embedding is denied.
                samesite="lax",
                secure=request.url.scheme == "https",
            )
        return secured(response)

    state.identity_path = identity_path
    state.load_report(report_path)

    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    # Static UI page routes (PAGE_ROUTES is the single source of truth)
    async def index() -> Any:
        return FileResponse(
            STATIC_DIR / "index.html",
            headers={"Cache-Control": "no-store"},
        )

    for _page_route in PAGE_ROUTES:
        app.get(_page_route, include_in_schema=False)(index)

    @app.get("/api/docs", include_in_schema=False)
    async def api_docs_redirect() -> Any:
        return RedirectResponse(url="/docs")

    # Register all modular sub-routers
    register_all_routers(app)

    return app


def build_uvicorn_config(app: Any, host: str = "127.0.0.1", port: int = 8765) -> Any:
    """In-process uvicorn config for the local dashboard (single worker, no reload)."""
    try:
        import uvicorn
    except ImportError as e:
        raise RuntimeError(
            "The UI extra is not installed. Run: pip install 'agentscan[ui]' "
            "(or uv sync --extra ui)."
        ) from e

    return uvicorn.Config(
        app,
        host=host,
        port=port,
        log_level="warning",
        reload=False,
        workers=1,
        access_log=False,
        lifespan="on",
    )


def serve_app(app: Any, host: str = "127.0.0.1", port: int = 8765) -> None:
    """Serve the dashboard with uvicorn in-process (single worker, no reload)."""
    config = build_uvicorn_config(app, host=host, port=port)
    import uvicorn

    uvicorn.Server(config).run()
