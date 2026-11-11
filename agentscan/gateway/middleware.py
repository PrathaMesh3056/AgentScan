"""Authentication and strict MCP transport guards implemented as ASGI layers."""

from __future__ import annotations

import json
import uuid
from collections.abc import Awaitable, Callable, Mapping
from typing import Any

from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.provider import AccessToken
from starlette.authentication import AuthCredentials, AuthenticationBackend

from agentscan.gateway.canonical import loads_json
from agentscan.gateway.identity import IdentityError, IdentityVerifier, VerifiedIdentity
from agentscan.gateway.models import ErrorCode
from agentscan.gateway.sessions import (
    PINNED_PROTOCOL_VERSION,
    SessionExpired,
    SessionIdentityMismatch,
    SessionNotFound,
    SessionRegistry,
)


class GatewayAuthenticationBackend(AuthenticationBackend):
    def __init__(self, verifier: IdentityVerifier) -> None:
        self.verifier = verifier

    async def authenticate(self, conn: Any) -> tuple[AuthCredentials, AuthenticatedUser] | None:
        state = conn.scope.setdefault("state", {})
        headers = {key.lower(): value for key, value in conn.scope.get("headers", [])}
        authorization = headers.get(b"authorization", b"").decode("latin-1")
        if not authorization or authorization[:7].lower() != "bearer ":
            state["identity_error"] = "missing_token"
            return None
        token = authorization[7:].strip()
        if not token or " " in token:
            state["identity_error"] = "malformed_token"
            return None
        try:
            identity = self.verifier.verify(token)
        except IdentityError as exc:
            state["identity_error"] = exc.reason
            return None
        state["verified_identity"] = identity
        access_token = AccessToken(
            token=token,
            client_id=identity.principal,
            subject=identity.principal,
            scopes=list(identity.scope),
            expires_at=identity.expires_at,
            claims={
                "iss": identity.issuer,
                "tenant": identity.tenant,
                "agent": identity.agent,
                "role": identity.role,
                "delegation": list(identity.delegation_chain),
            },
        )
        return AuthCredentials(scopes=list(identity.scope)), AuthenticatedUser(access_token)


ASGIApp = Callable[
    [dict[str, Any], Callable[..., Awaitable[Any]], Callable[..., Awaitable[Any]]], Awaitable[None]
]


def _header(scope: Mapping[str, Any], name: str) -> str | None:
    target = name.lower().encode("ascii")
    for key, value in scope.get("headers", []):
        if key.lower() == target:
            return value.decode("latin-1")
    return None


class McpGuardMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        *,
        sessions: SessionRegistry,
        max_request_bytes: int,
        metrics: Any = None,
    ) -> None:
        self.app = app
        self.sessions = sessions
        self.max_request_bytes = max_request_bytes
        self.metrics = metrics

    async def _reject(
        self,
        scope: dict[str, Any],
        send: Callable[..., Awaitable[Any]],
        status: int,
        code: str,
        message: str = "Request rejected",
    ) -> None:
        if self.metrics is not None:
            if code == ErrorCode.IDENTITY_MISMATCH.value:
                counter = "identity_mismatches"
            elif code == ErrorCode.IDENTITY_MISSING.value and status == 401:
                counter = "auth_failures"
            else:
                counter = "protocol_failures"
            self.metrics.increment(counter, reason=code.lower())
        body = json.dumps(
            {"agentscan_code": code, "message": message}, separators=(",", ":")
        ).encode()
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})

    async def __call__(
        self,
        scope: dict[str, Any],
        receive: Callable[..., Awaitable[Any]],
        send: Callable[..., Awaitable[Any]],
    ) -> None:
        if scope.get("type") != "http" or scope.get("path") != "/mcp":
            await self.app(scope, receive, send)
            return
        state = scope.setdefault("state", {})
        method = scope.get("method", "").upper()
        payload: Any = None
        body = b""
        if method == "POST":
            chunks: list[bytes] = []
            size = 0
            while True:
                message = await receive()
                if message["type"] == "http.disconnect":
                    return
                chunk = message.get("body", b"")
                size += len(chunk)
                if size > self.max_request_bytes:
                    await self._reject(scope, send, 413, ErrorCode.GATEWAY_UNAVAILABLE.value)
                    return
                chunks.append(chunk)
                if not message.get("more_body", False):
                    break
            body = b"".join(chunks)
            try:
                payload = loads_json(body)
                if not isinstance(payload, dict):
                    raise ValueError("invalid JSON-RPC request")
                rpc_method = payload.get("method")
                params = payload.get("params", {})
                if (
                    payload.get("jsonrpc") != "2.0"
                    or not isinstance(rpc_method, str)
                    or not rpc_method
                    or not isinstance(params, dict)
                ):
                    raise ValueError("invalid JSON-RPC request")
                if rpc_method == "tools/call":
                    if not isinstance(params.get("name"), str) or not params["name"]:
                        raise ValueError("invalid tool name")
                    if "arguments" in params and not isinstance(params["arguments"], dict):
                        raise ValueError("invalid tool arguments")
            except (ValueError, UnicodeDecodeError, TypeError):
                await self._reject(scope, send, 400, ErrorCode.GATEWAY_UNAVAILABLE.value)
                return
        else:
            rpc_method = None

        if not isinstance(scope.get("user"), AuthenticatedUser):
            await self._reject(scope, send, 401, ErrorCode.IDENTITY_MISSING.value)
            return
        identity = state.get("verified_identity")
        if not isinstance(identity, VerifiedIdentity):
            await self._reject(scope, send, 401, ErrorCode.IDENTITY_MISSING.value)
            return
        initializing = method == "POST" and rpc_method == "initialize"
        if method == "POST" and rpc_method == "server/discover":
            await self._reject(scope, send, 400, ErrorCode.UNSUPPORTED_PROTOCOL_VERSION.value)
            return
        if not initializing and _header(scope, "mcp-protocol-version") != PINNED_PROTOCOL_VERSION:
            await self._reject(scope, send, 400, ErrorCode.UNSUPPORTED_PROTOCOL_VERSION.value)
            return

        session_id = _header(scope, "mcp-session-id")
        session = None
        if not initializing:
            if not session_id:
                await self._reject(
                    scope,
                    send,
                    400,
                    ErrorCode.IDENTITY_MISSING.value,
                    "Session required; re-initialize",
                )
                return
            try:
                session = self.sessions.validate(session_id, identity)
            except (SessionNotFound, SessionExpired):
                await self._reject(
                    scope,
                    send,
                    404,
                    ErrorCode.IDENTITY_MISSING.value,
                    "Session expired or unknown; re-initialize",
                )
                return
            except SessionIdentityMismatch:
                await self._reject(scope, send, 403, ErrorCode.IDENTITY_MISMATCH.value)
                return

        rpc_id = payload.get("id") if isinstance(payload, dict) else None
        request_id = (
            str(rpc_id)[:64]
            if isinstance(rpc_id, (str, int)) and not isinstance(rpc_id, bool)
            else "notification"
        )
        from agentscan.gateway.server import GatewayRequestContext

        client_info = payload.get("params", {}).get("clientInfo") if initializing else None
        state["gateway_request_context"] = GatewayRequestContext(
            trace_id=uuid.uuid4().hex,
            request_id=request_id,
            method=rpc_method or method.lower(),
            identity=identity,
            session=session,
            protocol_version=PINNED_PROTOCOL_VERSION,
            client_name=client_info.get("name")
            if isinstance(client_info, dict) and isinstance(client_info.get("name"), str)
            else None,
            client_version=client_info.get("version")
            if isinstance(client_info, dict) and isinstance(client_info.get("version"), str)
            else None,
        )

        replayed = False

        async def guarded_receive() -> Any:
            nonlocal replayed
            if method == "POST" and not replayed:
                replayed = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        if not initializing and method == "DELETE":

            async def delete_send(message: dict[str, Any]) -> None:
                if (
                    message["type"] == "http.response.start"
                    and message.get("status", 500) < 400
                    and session_id
                ):
                    self.sessions.remove(session_id)
                await send(message)

            await self.app(scope, guarded_receive, delete_send)
            return

        if not initializing:
            await self.app(scope, guarded_receive, send)
            return

        start_message: dict[str, Any] | None = None
        response_body = bytearray()
        is_sse = False

        async def init_send(message: dict[str, Any]) -> None:
            nonlocal start_message, is_sse
            if message["type"] == "http.response.start":
                start_message = message
                is_sse = (
                    b"text/event-stream"
                    in dict(message.get("headers", [])).get(b"content-type", b"").lower()
                )
                if is_sse:
                    await send(message)
                return
            if message["type"] == "http.response.body" and start_message is not None and not is_sse:
                response_body.extend(message.get("body", b""))
                if message.get("more_body", False):
                    return
                status = start_message.get("status", 500)
                headers = list(start_message.get("headers", []))
                sid = next(
                    (
                        value.decode("latin-1")
                        for key, value in headers
                        if key.lower() == b"mcp-session-id"
                    ),
                    None,
                )
                try:
                    response = loads_json(bytes(response_body)) if status < 300 else None
                    if (
                        status < 300
                        and sid
                        and isinstance(response, dict)
                        and "error" not in response
                    ):
                        self.sessions.bind(
                            sid,
                            identity,
                            client_info=client_info if isinstance(client_info, dict) else None,
                            protocol_version=PINNED_PROTOCOL_VERSION,
                        )
                        result = response.get("result")
                        if isinstance(result, dict):
                            result["protocolVersion"] = PINNED_PROTOCOL_VERSION
                        encoded = json.dumps(
                            response, separators=(",", ":"), ensure_ascii=False
                        ).encode()
                        headers = [
                            (key, value)
                            for key, value in headers
                            if key.lower() != b"content-length"
                        ]
                        headers.append((b"content-length", str(len(encoded)).encode()))
                        await send({**start_message, "headers": headers})
                        await send(
                            {"type": "http.response.body", "body": encoded, "more_body": False}
                        )
                        return
                except Exception:
                    await self._reject(scope, send, 503, ErrorCode.GATEWAY_UNAVAILABLE.value)
                    return
                await send(start_message)
                await send(
                    {"type": "http.response.body", "body": bytes(response_body), "more_body": False}
                )
                return
            await send(message)

        await self.app(scope, guarded_receive, init_send)
