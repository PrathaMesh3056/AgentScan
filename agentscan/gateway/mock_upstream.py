"""Loopback-only mock MCP upstream for gateway tests and the local demo.

This module is a TEST AND DEMO upstream with fake data only. It is not
production code and must never be pointed at real customers, credentials, or
networks. The app binds only to loopback listeners created by the caller.
"""

from __future__ import annotations

import asyncio
import hmac
import json
import re
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import (
    CallToolRequest,
    CallToolResult,
    ListToolsRequest,
    ListToolsResult,
    ServerResult,
    TextContent,
    Tool,
)
from starlette.applications import Starlette
from starlette.datastructures import Headers
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.types import ASGIApp, Receive, Scope, Send

DEFAULT_TENANT = "tenant-demo"
PUBLIC_TOOL = "delete_customer_record"
STATUS_TOOL = "internal:check_effect"

CUSTOMER_TENANTS: dict[str, str] = {
    "cust-1001": "tenant-demo",
    "cust-1002": "tenant-demo",
    "cust-2001": "tenant-other",
}

_META_KEY_HASH = "agentscan.key_hash"
_META_REQUEST_HASH = "agentscan.request_hash"
_HASH_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")

_DELETE_INPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "customer_id": {"type": "string", "pattern": "^cust-[0-9]{4}$"},
    },
    "required": ["customer_id"],
    "additionalProperties": False,
}

# Bounded, fixed error texts. They never echo arguments or credentials.
_IDEMPOTENCY_REQUIRED = (
    "IDEMPOTENCY_REQUIRED: agentscan.key_hash and agentscan.request_hash meta hashes are required"
)
_IDEMPOTENCY_CONFLICT = "IDEMPOTENCY_CONFLICT: idempotency key was reused with a different request"
_UPSTREAM_ERROR = "UPSTREAM_ERROR: mock upstream request could not be completed"
_TENANT_UNVERIFIED = (
    "RESOURCE_TENANT_UNVERIFIED: customer record does not belong to the authenticated tenant"
)
_INVALID_HASH = "IDEMPOTENCY_REQUIRED: key_hash and request_hash must be sha256: hashes"


@dataclass(frozen=True, slots=True)
class MockUpstreamConfig:
    """Fake-data configuration for the mock upstream app."""

    gateway_credential: str
    tenant: str = DEFAULT_TENANT
    call_delay_seconds: float = 0.0
    crash_after_start: bool = False


@dataclass(frozen=True, slots=True)
class MockEffectRecord:
    """One recorded effect transition; fake data only."""

    key_hash: str
    request_hash: str
    status: Literal["started", "success", "denied"]
    observed_at: str


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _is_valid_hash(value: Any) -> bool:
    return isinstance(value, str) and _HASH_PATTERN.fullmatch(value) is not None


def _canonical_text(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


class MockUpstreamState:
    """Fake customer state and effect records for the mock upstream."""

    def __init__(self, customers: dict[str, str] | None = None) -> None:
        self.customers: dict[str, str] = dict(customers) if customers else dict(CUSTOMER_TENANTS)
        self.deleted: set[str] = set()
        self.records: list[MockEffectRecord] = []

    def effect(self, key_hash: str, request_hash: str) -> dict[str, Any]:
        """Build the check_effect payload for one idempotency key."""
        success = self._latest(key_hash, "success")
        if success is not None:
            return {
                "status": "applied",
                "key_hash": key_hash,
                "request_hash": success.request_hash,
                "confirmation_id": f"mock-{uuid.uuid4()}",
                "observed_at": success.observed_at,
            }
        started = self._latest(key_hash, "started")
        if started is not None:
            return {
                "status": "unknown",
                "key_hash": key_hash,
                "request_hash": request_hash,
                "confirmation_id": f"mock-{uuid.uuid4()}",
                "observed_at": started.observed_at,
            }
        return {
            "status": "no_effect",
            "key_hash": key_hash,
            "request_hash": request_hash,
            "confirmation_id": f"mock-{uuid.uuid4()}",
            "observed_at": _utc_now_iso(),
        }

    def _latest(self, key_hash: str, status: str) -> MockEffectRecord | None:
        found: MockEffectRecord | None = None
        for record in self.records:
            if record.key_hash == key_hash and record.status == status:
                found = record
        return found


def _error_result(text: str) -> CallToolResult:
    return CallToolResult(content=[TextContent(type="text", text=text)], isError=True)


def _meta_hashes(request: CallToolRequest) -> tuple[Any, Any]:
    meta = request.params.meta
    extras = meta.model_extra if meta is not None else None
    if not isinstance(extras, dict):
        return None, None
    return extras.get(_META_KEY_HASH), extras.get(_META_REQUEST_HASH)


class _ManagerASGI:
    """Raw ASGI endpoint so /mcp does not redirect to /mcp/."""

    def __init__(self, manager: StreamableHTTPSessionManager) -> None:
        self.manager = manager

    async def __call__(self, scope: dict[str, Any], receive: Receive, send: Send) -> None:
        await self.manager.handle_request(scope, receive, send)


class _MockAuthMiddleware:
    """Authenticate /mcp with the gateway credential and tenant header."""

    def __init__(self, app: ASGIApp, credential: str, tenant: str) -> None:
        self.app = app
        self._credential = credential
        self._tenant = tenant

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("path") != "/mcp":
            await self.app(scope, receive, send)
            return
        headers = Headers(scope=scope)
        presented = headers.get("authorization", "")
        expected = f"Bearer {self._credential}"
        authorized = hmac.compare_digest(presented.encode("utf-8"), expected.encode("utf-8"))
        tenant = headers.get("x-agentscan-tenant", "")
        authorized = authorized and hmac.compare_digest(
            tenant.encode("utf-8"), self._tenant.encode("utf-8")
        )
        if not authorized:
            # Never echo the presented credential back to the caller.
            body = b'{"error":"unauthorized"}'
            await send(
                {
                    "type": "http.response.start",
                    "status": 401,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"content-length", str(len(body)).encode("ascii")),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": body})
            return
        await self.app(scope, receive, send)


def create_mock_upstream_app(config: MockUpstreamConfig) -> Starlette:
    """Create the loopback-only mock upstream app; fake data only."""
    if not isinstance(config.gateway_credential, str) or not config.gateway_credential:
        raise ValueError("mock upstream requires a gateway credential")
    if not isinstance(config.tenant, str) or not config.tenant:
        raise ValueError("mock upstream requires a tenant")
    state = MockUpstreamState()
    lock = asyncio.Lock()
    mock_server = Server(name="agentscan-mock-upstream")

    async def _check_effect(arguments: dict[str, Any]) -> CallToolResult:
        arg_key = arguments.get("key_hash")
        arg_request = arguments.get("request_hash")
        if not _is_valid_hash(arg_key) or not _is_valid_hash(arg_request):
            return _error_result(_INVALID_HASH)
        assert isinstance(arg_key, str) and isinstance(arg_request, str)
        async with lock:
            payload = state.effect(arg_key, arg_request)
        if payload["status"] == "applied" and payload["request_hash"] != arg_request:
            return _error_result(_IDEMPOTENCY_CONFLICT)
        return CallToolResult(
            content=[TextContent(type="text", text=_canonical_text(payload))],
            structuredContent=payload,
            isError=False,
        )

    async def _delete_customer(
        arguments: dict[str, Any], key_hash: str, request_hash: str
    ) -> CallToolResult:
        customer_id = arguments.get("customer_id")
        async with lock:
            tenant = state.customers.get(customer_id) if isinstance(customer_id, str) else None
            if tenant is None:
                return _error_result(_UPSTREAM_ERROR)
            if tenant != config.tenant:
                state.records.append(
                    MockEffectRecord(
                        key_hash=key_hash,
                        request_hash=request_hash,
                        status="denied",
                        observed_at=_utc_now_iso(),
                    )
                )
                return _error_result(_TENANT_UNVERIFIED)
            success = state._latest(key_hash, "success")
            if success is not None:
                if success.request_hash == request_hash:
                    # Same key and same request: return the recorded outcome.
                    return CallToolResult(
                        content=[TextContent(type="text", text=f"deleted {customer_id}")],
                        isError=False,
                    )
                return _error_result(_IDEMPOTENCY_CONFLICT)
            state.records.append(
                MockEffectRecord(
                    key_hash=key_hash,
                    request_hash=request_hash,
                    status="started",
                    observed_at=_utc_now_iso(),
                )
            )
        if config.crash_after_start:
            # Crash after start: state keeps "started" with no "success".
            return _error_result(_UPSTREAM_ERROR)
        if config.call_delay_seconds > 0:
            await asyncio.sleep(config.call_delay_seconds)
        async with lock:
            state.deleted.add(customer_id)
            state.records.append(
                MockEffectRecord(
                    key_hash=key_hash,
                    request_hash=request_hash,
                    status="success",
                    observed_at=_utc_now_iso(),
                )
            )
        return CallToolResult(
            content=[TextContent(type="text", text=f"deleted {customer_id}")],
            isError=False,
        )

    async def handle_call(request: CallToolRequest) -> CallToolResult:
        key_hash, request_hash = _meta_hashes(request)
        if not _is_valid_hash(key_hash) or not _is_valid_hash(request_hash):
            return _error_result(_IDEMPOTENCY_REQUIRED)
        assert isinstance(key_hash, str) and isinstance(request_hash, str)
        arguments = request.params.arguments or {}
        if request.params.name == STATUS_TOOL:
            return await _check_effect(arguments)
        if request.params.name == PUBLIC_TOOL:
            return await _delete_customer(arguments, key_hash, request_hash)
        return _error_result(_UPSTREAM_ERROR)

    async def call_tool(request: CallToolRequest) -> ServerResult:
        try:
            return ServerResult(await handle_call(request))
        except Exception:
            return ServerResult(_error_result(_UPSTREAM_ERROR))

    async def list_tools(_request: ListToolsRequest) -> ServerResult:
        # The internal status operation is never listed publicly.
        tool = Tool(
            name=PUBLIC_TOOL,
            description="Deletes a fake customer record; demo data only",
            inputSchema=dict(_DELETE_INPUT_SCHEMA),
        )
        return ServerResult(ListToolsResult(tools=[tool]))

    mock_server.request_handlers[CallToolRequest] = call_tool
    mock_server.request_handlers[ListToolsRequest] = list_tools

    session_manager = StreamableHTTPSessionManager(
        app=mock_server,
        stateless=False,
        json_response=True,
        security_settings=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=["127.0.0.1:*", "localhost:*", "[::1]:*"],
            allowed_origins=["http://127.0.0.1:*", "http://localhost:*", "http://[::1]:*"],
        ),
    )

    async def healthz(_request: Request) -> JSONResponse:
        return JSONResponse({"status": "ok"})

    @asynccontextmanager
    async def lifespan(_app: Starlette):
        async with session_manager.run():
            yield

    manager_endpoint = _ManagerASGI(session_manager)

    app = Starlette(
        routes=[
            Route("/mcp", endpoint=manager_endpoint, methods=["GET", "POST", "DELETE"]),
            Route("/healthz", healthz, methods=["GET"]),
        ],
        middleware=[
            Middleware(
                _MockAuthMiddleware,
                credential=config.gateway_credential,
                tenant=config.tenant,
            ),
        ],
        lifespan=lifespan,
    )
    app.state.mock_state = state
    return app
