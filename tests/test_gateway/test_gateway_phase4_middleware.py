from __future__ import annotations

import json
from typing import Any

import pytest
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.provider import AccessToken

from agentscan.gateway.identity import VerifiedIdentity
from agentscan.gateway.middleware import McpGuardMiddleware
from agentscan.gateway.sessions import PINNED_PROTOCOL_VERSION, SessionRegistry


def identity(principal: str = "p") -> VerifiedIdentity:
    return VerifiedIdentity(
        principal,
        "agent",
        "tenant",
        "operator",
        ("tool",),
        ("tool",),
        (),
        "iss",
        "aud",
        9999999999,
        1,
        f"hash:{principal}",
    )


def user(identity_value: VerifiedIdentity) -> AuthenticatedUser:
    return AuthenticatedUser(
        AccessToken(
            token="fake-token",
            client_id=identity_value.principal,
            subject=identity_value.principal,
            scopes=list(identity_value.scope),
            expires_at=identity_value.expires_at,
            claims={"iss": identity_value.issuer},
        )
    )


async def invoke(
    payload: Any,
    *,
    method: str = "POST",
    headers: list[tuple[bytes, bytes]] | None = None,
    authenticated: bool = True,
    downstream_response: tuple[int, list[tuple[bytes, bytes]], bytes] | None = None,
    sessions: SessionRegistry | None = None,
):
    body = json.dumps(payload, separators=(",", ":")).encode() if payload is not None else b""
    request_messages = [{"type": "http.request", "body": body, "more_body": False}]
    scope: dict[str, Any] = {
        "type": "http",
        "path": "/mcp",
        "method": method,
        "headers": headers or [],
        "state": {"verified_identity": identity()},
    }
    if authenticated:
        scope["user"] = user(identity())
    responses: list[dict[str, Any]] = []
    calls: list[int] = []

    async def receive():
        return request_messages.pop(0) if request_messages else {"type": "http.disconnect"}

    async def send(message):
        responses.append(message)

    async def app(_scope, _receive, _send):
        calls.append(1)
        if downstream_response is not None:
            status, response_headers, response_body = downstream_response
            await _send(
                {"type": "http.response.start", "status": status, "headers": response_headers}
            )
            await _send({"type": "http.response.body", "body": response_body, "more_body": False})

    registry = (
        sessions
        if sessions is not None
        else SessionRegistry(idle_timeout_seconds=20, max_lifetime_seconds=60)
    )
    guard = McpGuardMiddleware(app, sessions=registry, max_request_bytes=4096)
    await guard(scope, receive, send)
    return scope, responses, calls


@pytest.mark.parametrize(
    "body",
    [
        b'{"jsonrpc":"2.0","method":"ping","id":1,"id":2}',
        b'{"jsonrpc":"2.0","method":"ping","x":NaN}',
        b"[]",
        b"1",
        b'{"jsonrpc":"2.0"}',
        b'{"jsonrpc":"1.0","method":"ping"}',
        b'{"jsonrpc":"2.0","method":"ping","params":[]}',
        b'{"jsonrpc":"2.0","method":"tools/call","params":{"name":"x","arguments":[]}}',
        b'{"jsonrpc":"2.0","method":"tools/call","params":{"name":3}}',
    ],
)
async def test_invalid_json_rpc_never_reaches_downstream(body: bytes) -> None:
    messages = [{"type": "http.request", "body": body, "more_body": False}]
    sent: list[dict[str, Any]] = []
    reached: list[bool] = []

    async def receive():
        return messages.pop(0)

    async def send(value):
        sent.append(value)

    async def app(*_args):
        reached.append(True)

    scope = {
        "type": "http",
        "path": "/mcp",
        "method": "POST",
        "headers": [],
        "state": {"verified_identity": identity()},
        "user": user(identity()),
    }
    await McpGuardMiddleware(
        app,
        sessions=SessionRegistry(idle_timeout_seconds=20, max_lifetime_seconds=60),
        max_request_bytes=4096,
    )(scope, receive, send)
    assert not reached and sent[0]["status"] == 400


@pytest.mark.parametrize(
    "kwargs,status",
    [({"authenticated": False}, 401), ({"headers": [(b"mcp-protocol-version", b"old")]}, 400)],
)
async def test_auth_and_protocol_fail_before_downstream(
    kwargs: dict[str, Any], status: int
) -> None:
    _scope, response, calls = await invoke({"jsonrpc": "2.0", "method": "ping", "id": 1}, **kwargs)
    assert response[0]["status"] == status and not calls


async def test_initialize_counteroffers_protocol_and_binds() -> None:
    sessions = SessionRegistry(idle_timeout_seconds=20, max_lifetime_seconds=60)
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2024-11-05"}}
    ).encode()
    _scope, response, calls = await invoke(
        {
            "jsonrpc": "2.0",
            "method": "initialize",
            "id": 1,
            "params": {"protocolVersion": "2024-11-05", "clientInfo": {"name": "test"}},
        },
        downstream_response=(
            200,
            [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
                (b"mcp-session-id", b"session-a"),
            ],
            body,
        ),
        sessions=sessions,
    )
    decoded = json.loads(response[-1]["body"])
    assert decoded["result"]["protocolVersion"] == PINNED_PROTOCOL_VERSION
    assert response[0]["headers"][-1][0] == b"content-length"
    assert calls and len(sessions) == 1


async def test_unknown_session_and_server_discover_are_rejected() -> None:
    h = [
        (b"mcp-protocol-version", PINNED_PROTOCOL_VERSION.encode()),
        (b"mcp-session-id", b"unknown"),
    ]
    _, response, calls = await invoke({"jsonrpc": "2.0", "method": "ping", "id": 1}, headers=h)
    assert response[0]["status"] == 404 and not calls
    _, response, calls = await invoke(
        {"jsonrpc": "2.0", "method": "server/discover", "id": 1},
        headers=[(b"mcp-protocol-version", PINNED_PROTOCOL_VERSION.encode())],
    )
    assert response[0]["status"] == 400 and not calls
