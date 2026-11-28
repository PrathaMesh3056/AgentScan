"""Phase 4 MCP transport and narrow Phase 5 tool-runtime seam."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any, Protocol, cast

from mcp.server.lowlevel import Server
from mcp.server.lowlevel.server import request_ctx
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.server.transport_security import TransportSecuritySettings
from mcp.shared.exceptions import McpError
from mcp.types import (
    CallToolRequest,
    CallToolResult,
    ErrorData,
    ListToolsRequest,
    ListToolsResult,
    ServerResult,
    Tool,
)
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Route

from agentscan.gateway.config import GatewaySettings
from agentscan.gateway.errors import GatewayError
from agentscan.gateway.identity import IdentityVerifier, UnverifiedIdentity, VerifiedIdentity
from agentscan.gateway.metrics import MetricsRegistry
from agentscan.gateway.middleware import GatewayAuthenticationBackend, McpGuardMiddleware
from agentscan.gateway.models import ErrorCode
from agentscan.gateway.sessions import SessionRecord, SessionRegistry


@dataclass(frozen=True, slots=True)
class Readiness:
    policy_loaded: bool = False
    policy_expired: bool = False
    chain_verified: bool = False
    writer_lease_held: bool = False
    receipt_sink_healthy: bool = False
    upstream_catalog_loaded: bool = False
    upstream_lost: bool = False

    def issues(self) -> tuple[str, ...]:
        tests = (
            (self.policy_loaded, "policy_missing"),
            (not self.policy_expired, "policy_expired"),
            (self.chain_verified, "chain_invalid"),
            (self.writer_lease_held, "writer_lease_missing"),
            (self.receipt_sink_healthy, "receipt_sink_unhealthy"),
            (self.upstream_catalog_loaded, "catalog_unavailable"),
            (not self.upstream_lost, "upstream_unavailable"),
        )
        return tuple(code for ready, code in tests if not ready)


@dataclass(frozen=True, slots=True)
class GatewayRequestContext:
    trace_id: str
    request_id: str
    method: str
    identity: VerifiedIdentity | UnverifiedIdentity
    session: SessionRecord | None
    protocol_version: str
    client_name: str | None = None
    client_version: str | None = None


class ToolRuntime(Protocol):
    async def list_tools(self, context: GatewayRequestContext) -> Sequence[Tool]: ...
    async def call_tool(
        self,
        context: GatewayRequestContext,
        name: str,
        arguments: Mapping[str, Any],
        *,
        meta: Mapping[str, Any] | None = None,
    ) -> CallToolResult: ...
    def readiness(self) -> Readiness: ...


class UnavailableToolRuntime:
    async def list_tools(self, context: GatewayRequestContext) -> Sequence[Tool]:
        raise GatewayError(ErrorCode.GATEWAY_UNAVAILABLE, "tool runtime unavailable", 503)

    async def call_tool(
        self,
        context: GatewayRequestContext,
        name: str,
        arguments: Mapping[str, Any],
        *,
        meta: Mapping[str, Any] | None = None,
    ) -> CallToolResult:
        raise GatewayError(ErrorCode.GATEWAY_UNAVAILABLE, "tool runtime unavailable", 503)

    def readiness(self) -> Readiness:
        return Readiness()


def _context_or_error() -> GatewayRequestContext:
    try:
        request = cast(Any, request_ctx.get()).request
        scope = request.scope if hasattr(request, "scope") else request
        context = cast(Any, scope).get("state", {}).get("gateway_request_context")
    except LookupError:
        context = None
    if not isinstance(context, GatewayRequestContext):
        raise GatewayError(
            ErrorCode.GATEWAY_UNAVAILABLE, "gateway request context unavailable", 503
        )
    return context


def _mcp_error(exc: GatewayError) -> McpError:
    return McpError(
        ErrorData(code=exc.jsonrpc_code, message=exc.message, data=exc.as_jsonrpc_data())
    )


class _ManagerASGI:
    """Keep the manager as a raw ASGI endpoint so /mcp does not redirect to /mcp/."""

    def __init__(self, manager: StreamableHTTPSessionManager) -> None:
        self.manager = manager

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        await self.manager.handle_request(scope, receive, send)


def create_app(
    settings: GatewaySettings,
    *,
    identity_verifier: IdentityVerifier,
    sessions: SessionRegistry,
    runtime: ToolRuntime | None = None,
    readiness: Callable[[], Readiness] | None = None,
    metrics: MetricsRegistry | None = None,
    shutdown_event: Any | None = None,
) -> Starlette:
    """Create the authenticated Streamable HTTP gateway app."""
    tool_runtime = runtime if runtime is not None else UnavailableToolRuntime()
    metric_registry = metrics if metrics is not None else MetricsRegistry()
    probe = readiness if readiness is not None else tool_runtime.readiness
    mcp_server = Server(name="agentscan-gateway")

    async def list_tools(_request: ListToolsRequest) -> ServerResult:
        try:
            tools = await tool_runtime.list_tools(_context_or_error())
            return ServerResult(ListToolsResult(tools=list(tools)))
        except GatewayError as exc:
            raise _mcp_error(exc) from None
        except Exception:
            raise _mcp_error(
                GatewayError(ErrorCode.UPSTREAM_ERROR, "Tool runtime failed")
            ) from None

    async def call_tool(request: CallToolRequest) -> ServerResult:
        try:
            context = _context_or_error()
            arguments = request.params.arguments or {}
            result = await tool_runtime.call_tool(
                context,
                request.params.name,
                arguments,
                meta=cast(Mapping[str, Any] | None, request.params.meta),
            )
            return ServerResult(result)
        except GatewayError as exc:
            raise _mcp_error(exc) from None
        except Exception:
            raise _mcp_error(
                GatewayError(ErrorCode.UPSTREAM_ERROR, "Tool runtime failed")
            ) from None

    mcp_server.request_handlers[ListToolsRequest] = list_tools
    mcp_server.request_handlers[CallToolRequest] = call_tool
    session_manager = StreamableHTTPSessionManager(
        app=mcp_server,
        stateless=False,
        json_response=True,
        session_idle_timeout=settings.session_idle_timeout_seconds,
        max_request_body_size=settings.max_request_bytes,
        security_settings=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=list(settings.allowed_hosts),
            allowed_origins=list(settings.allowed_origins),
        ),
    )

    @asynccontextmanager
    async def lifespan(_app: Starlette):
        async with session_manager.run():
            try:
                yield
            finally:
                if shutdown_event is not None:
                    shutdown_event.set()

    async def healthz(_request: Request) -> JSONResponse:
        return JSONResponse({"status": "ok"})

    async def readyz(_request: Request) -> JSONResponse:
        try:
            current = probe()
            if not isinstance(current, Readiness):
                current = Readiness()
        except Exception:
            current = Readiness()
        issues = current.issues()
        if issues:
            # One bounded, machine-readable code; the dashboard validates this shape.
            reason = issues[0]
            return JSONResponse(
                {
                    "status": "not_ready",
                    "agentscan_code": ErrorCode.GATEWAY_UNAVAILABLE.value,
                    "reason": reason,
                },
                status_code=503,
            )
        return JSONResponse({"status": "ready"})

    async def metrics_endpoint(_request: Request) -> PlainTextResponse:
        return PlainTextResponse(
            metric_registry.render(), media_type="text/plain; version=0.0.4; charset=utf-8"
        )

    # Starlette wraps middleware in reverse list order: authentication is outermost.
    app = Starlette(
        routes=[
            Route(
                "/mcp", endpoint=_ManagerASGI(session_manager), methods=["GET", "POST", "DELETE"]
            ),
            Route("/healthz", healthz, methods=["GET"]),
            Route("/readyz", readyz, methods=["GET"]),
            Route("/metrics", metrics_endpoint, methods=["GET"]),
        ],
        middleware=[
            Middleware(
                AuthenticationMiddleware, backend=GatewayAuthenticationBackend(identity_verifier)
            ),
            Middleware(
                McpGuardMiddleware,
                sessions=sessions,
                max_request_bytes=settings.max_request_bytes,
                metrics=metric_registry,
            ),
        ],
        lifespan=lifespan,
    )
    return app
