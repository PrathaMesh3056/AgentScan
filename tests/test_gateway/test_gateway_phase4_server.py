from __future__ import annotations

import asyncio
import re
import socket
import time
from collections.abc import AsyncIterator, Mapping, Sequence
from contextlib import asynccontextmanager
from typing import Any

import httpx
import jwt
import pytest
import uvicorn
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.types import CallToolResult, TextContent, Tool
from starlette.testclient import TestClient

from agentscan.gateway.config import GatewaySettings
from agentscan.gateway.errors import GatewayError
from agentscan.gateway.identity import IdentityVerifier
from agentscan.gateway.models import ErrorCode
from agentscan.gateway.server import (
    GatewayRequestContext,
    Readiness,
    ToolRuntime,
    UnavailableToolRuntime,
    create_app,
)
from agentscan.gateway.sessions import PINNED_PROTOCOL_VERSION, SessionRegistry


class FakeRuntime:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def list_tools(self, context: GatewayRequestContext) -> Sequence[Tool]:
        assert context.session is not None
        return [Tool(name="echo", description="echo", inputSchema={"type": "object"})]

    async def call_tool(
        self, context: GatewayRequestContext, name: str, arguments: Mapping[str, Any]
    ) -> CallToolResult:
        if name == "fail":
            raise GatewayError(ErrorCode.POLICY_DENIED, "Request denied")
        self.calls.append((name, dict(arguments)))
        return CallToolResult(
            content=[TextContent(type="text", text=str(arguments.get("value", "ok")))]
        )

    def readiness(self) -> Readiness:
        return Readiness(True, False, True, True, True, True)


def _token(
    private: Ed25519PrivateKey, *, sub: str = "principal-a", tenant: str = "tenant-a"
) -> str:
    now = int(time.time())
    return jwt.encode(
        {
            "iss": "issuer-a",
            "sub": sub,
            "aud": "agentscan",
            "exp": now + 600,
            "iat": now,
            "tenant": tenant,
            "agent": "agent-a",
            "role": "operator",
            "scope": ["echo", "fail"],
        },
        private,
        algorithm="EdDSA",
        headers={"kid": "test-key"},
    )


@pytest.fixture
async def gateway():
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(128)
    port = listener.getsockname()[1]
    settings = GatewaySettings.model_validate(
        {
            "tenant": "tenant-a",
            "gateway_id": "gw",
            "chain_id": "chain",
            "writer_id": "writer",
            "audience": "agentscan",
            "trusted_issuer": "issuer-a",
            "listen_host": "127.0.0.1",
            "listen_port": port,
            "upstream_url": "http://127.0.0.1:9999",
            "upstream_server_id": "fake",
            "upstream_credential_env": "FAKE_TOKEN",
            "policy_bundle": "policy.yaml",
            "policy_public_key": "policy.pub",
            "trust_keys": "trust.json",
            "receipt_dir": "receipts",
            "allowed_hosts": [f"127.0.0.1:{port}"],
            "allowed_origins": [f"http://127.0.0.1:{port}"],
        }
    )
    runtime = FakeRuntime()
    app = create_app(
        settings,
        identity_verifier=IdentityVerifier(
            trusted_issuer="issuer-a",
            audience="agentscan",
            tenant="tenant-a",
            trust_keys={"test-key": public},
        ),
        sessions=SessionRegistry(idle_timeout_seconds=300, max_lifetime_seconds=900),
        runtime=runtime,
    )
    server = uvicorn.Server(uvicorn.Config(app, log_level="critical", lifespan="on"))
    task = asyncio.create_task(server.serve(sockets=[listener]))
    for _ in range(200):
        if server.started:
            break
        await asyncio.sleep(0.01)
    assert server.started
    client = httpx.AsyncClient(
        base_url=f"http://127.0.0.1:{port}",
        headers={"Authorization": f"Bearer {_token(private)}", "Accept": "application/json"},
        timeout=3,
    )
    try:
        yield client, runtime, private, port
    finally:
        await client.aclose()
        server.should_exit = True
        try:
            await asyncio.wait_for(task, timeout=5)
        except TimeoutError:
            task.cancel()
        listener.close()


@asynccontextmanager
async def _started_gateway(
    *,
    runtime: ToolRuntime | None = None,
    sessions: SessionRegistry | None = None,
) -> AsyncIterator[tuple[httpx.AsyncClient, ToolRuntime, Ed25519PrivateKey, int, SessionRegistry]]:
    """Start the loopback gateway app with an injectable runtime and session registry."""
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(128)
    port = listener.getsockname()[1]
    settings = GatewaySettings.model_validate(
        {
            "tenant": "tenant-a",
            "gateway_id": "gw",
            "chain_id": "chain",
            "writer_id": "writer",
            "audience": "agentscan",
            "trusted_issuer": "issuer-a",
            "listen_host": "127.0.0.1",
            "listen_port": port,
            "upstream_url": "http://127.0.0.1:9999",
            "upstream_server_id": "fake",
            "upstream_credential_env": "FAKE_TOKEN",
            "policy_bundle": "policy.yaml",
            "policy_public_key": "policy.pub",
            "trust_keys": "trust.json",
            "receipt_dir": "receipts",
            "allowed_hosts": [f"127.0.0.1:{port}"],
            "allowed_origins": [f"http://127.0.0.1:{port}"],
        }
    )
    started_runtime = runtime if runtime is not None else FakeRuntime()
    started_sessions = (
        sessions
        if sessions is not None
        else SessionRegistry(idle_timeout_seconds=300, max_lifetime_seconds=900)
    )
    app = create_app(
        settings,
        identity_verifier=IdentityVerifier(
            trusted_issuer="issuer-a",
            audience="agentscan",
            tenant="tenant-a",
            trust_keys={"test-key": public},
        ),
        sessions=started_sessions,
        runtime=started_runtime,
    )
    server = uvicorn.Server(uvicorn.Config(app, log_level="critical", lifespan="on"))
    task = asyncio.create_task(server.serve(sockets=[listener]))
    for _ in range(200):
        if server.started:
            break
        await asyncio.sleep(0.01)
    assert server.started
    client = httpx.AsyncClient(
        base_url=f"http://127.0.0.1:{port}",
        headers={"Authorization": f"Bearer {_token(private)}", "Accept": "application/json"},
        timeout=3,
    )
    try:
        yield client, started_runtime, private, port, started_sessions
    finally:
        await client.aclose()
        server.should_exit = True
        try:
            await asyncio.wait_for(task, timeout=5)
        except TimeoutError:
            task.cancel()
        listener.close()


@pytest.mark.asyncio
async def test_localhost_transport_initialize_tool_calls_and_health(gateway) -> None:
    client, runtime, _private, port = gateway
    initialized = await asyncio.wait_for(
        client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "test", "version": "1"},
                },
            },
        ),
        5,
    )
    assert initialized.status_code == 200
    assert initialized.json()["result"]["protocolVersion"] == PINNED_PROTOCOL_VERSION
    assert initialized.headers.get("mcp-session-id")
    assert "tools" in initialized.json()["result"]["capabilities"]
    assert "resources" not in initialized.json()["result"]["capabilities"]
    sid = initialized.headers["mcp-session-id"]
    headers = {"Mcp-Session-Id": sid, "MCP-Protocol-Version": PINNED_PROTOCOL_VERSION}
    tools = await client.post(
        "/mcp",
        headers=headers,
        json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    )
    assert tools.status_code == 200 and tools.json()["result"]["tools"][0]["name"] == "echo"
    called = await client.post(
        "/mcp",
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "echo", "arguments": {"value": "hello"}},
        },
    )
    assert called.status_code == 200 and "hello" in called.text
    denied = await client.post(
        "/mcp",
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "fail", "arguments": {}},
        },
    )
    assert denied.json()["error"]["code"] == -32000
    assert denied.json()["error"]["data"]["agentscan_code"] == "POLICY_DENIED"
    initialized_notice = await client.post(
        "/mcp", headers=headers, json={"jsonrpc": "2.0", "method": "notifications/initialized"}
    )
    assert initialized_notice.status_code == 202
    assert (await client.get("/healthz")).json() == {"status": "ok"}
    assert (await client.get("/readyz")).status_code == 200
    metrics = await client.get("/metrics")
    assert metrics.status_code == 200 and "# TYPE" in metrics.text
    assert str(port) not in metrics.text
    assert runtime.calls == [("echo", {"value": "hello"})]


@pytest.mark.asyncio
async def test_localhost_client_path_and_auth_protocol_rejections(gateway) -> None:
    client, _runtime, private, _port = gateway
    no_auth = httpx.AsyncClient(base_url=str(client.base_url))
    try:
        response = await no_auth.post(
            "/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
        )
        assert (
            response.status_code == 401 and response.json()["agentscan_code"] == "IDENTITY_MISSING"
        )
    finally:
        await no_auth.aclose()
    async with (
        streamable_http_client(str(client.base_url) + "/mcp", http_client=client) as (
            read_stream,
            write_stream,
            _get_session_id,
        ),
        ClientSession(read_stream, write_stream) as session,
    ):
        result = await session.initialize()
        assert result.protocolVersion == PINNED_PROTOCOL_VERSION
    wrong = await client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 9, "method": "ping"},
        headers={"Mcp-Session-Id": "missing"},
    )
    assert wrong.status_code == 400
    discover = await client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 10, "method": "server/discover"},
        headers={"MCP-Protocol-Version": PINNED_PROTOCOL_VERSION},
    )
    assert discover.status_code == 400
    assert private is not None


def _metric_value(text: str, metric_name: str, reason: str | None = None) -> int:
    total = 0
    for line in text.splitlines():
        if not line.startswith(metric_name):
            continue
        if reason is not None and f'reason="{reason}"' not in line:
            continue
        parts = line.split()
        if not parts:
            continue
        try:
            total += int(float(parts[-1]))
        except ValueError:
            continue
    return total


async def _initialize(
    client: httpx.AsyncClient, private: Ed25519PrivateKey
) -> tuple[httpx.Response, str]:
    response = await client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": PINNED_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "1"},
            },
        },
    )
    assert response.status_code == 200
    return response, response.headers["mcp-session-id"]


@pytest.mark.asyncio
async def test_localhost_duplicate_key_post_is_rejected_and_runtime_not_called(gateway) -> None:
    client, runtime, _private, _port = gateway
    response = await client.post(
        "/mcp",
        content=b'{"jsonrpc":"2.0","id":1,"method":"ping","method":"ping"}',
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 400
    assert response.json()["agentscan_code"] == "GATEWAY_UNAVAILABLE"
    assert runtime.calls == []


@pytest.mark.asyncio
async def test_localhost_oversize_post_is_rejected_with_413(gateway) -> None:
    client, runtime, _private, _port = gateway
    response = await client.post(
        "/mcp",
        content=b'{"jsonrpc":"2.0","id":1,"method":"ping","params":{"pad":"'
        + b"x" * 70000
        + b'"}}',
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 413
    assert response.json()["agentscan_code"] == "GATEWAY_UNAVAILABLE"
    assert runtime.calls == []


@pytest.mark.asyncio
async def test_localhost_disallowed_host_and_origin_are_rejected(gateway) -> None:
    client, runtime, private, port = gateway
    init, sid = await _initialize(client, private)
    assert init.status_code == 200

    # Bad Host, valid Origin: SDK transport security returns 421.
    bad_host = await client.post(
        "/mcp",
        headers={
            "Mcp-Session-Id": sid,
            "MCP-Protocol-Version": PINNED_PROTOCOL_VERSION,
            "Host": "evil.example.com",
            "Origin": f"http://127.0.0.1:{port}",
        },
        json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    )
    assert bad_host.status_code == 421
    assert runtime.calls == []

    # Valid Host, bad Origin: SDK transport security returns 403.
    bad_origin = await client.post(
        "/mcp",
        headers={
            "Mcp-Session-Id": sid,
            "MCP-Protocol-Version": PINNED_PROTOCOL_VERSION,
            "Host": f"127.0.0.1:{port}",
            "Origin": "https://evil.example.com",
        },
        json={"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}},
    )
    assert bad_origin.status_code == 403
    assert runtime.calls == []


@pytest.mark.asyncio
async def test_localhost_session_identity_mismatch_then_reinitialize(gateway) -> None:
    client, runtime, private, _port = gateway
    init, sid = await _initialize(client, private)
    assert init.status_code == 200

    other_client = httpx.AsyncClient(
        base_url=str(client.base_url),
        headers={
            "Authorization": f"Bearer {_token(private, sub='principal-b', tenant='tenant-a')}",
            "Accept": "application/json",
        },
        timeout=3,
    )
    try:
        before_metrics = await other_client.get("/metrics")
        before_identity = _metric_value(
            before_metrics.text, "agentscan_gateway_identity_mismatches_total", "identity_mismatch"
        )
        before_protocol = _metric_value(
            before_metrics.text, "agentscan_gateway_protocol_failures_total", "identity_mismatch"
        )

        mismatch = await other_client.post(
            "/mcp",
            headers={"Mcp-Session-Id": sid, "MCP-Protocol-Version": PINNED_PROTOCOL_VERSION},
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        )
        assert mismatch.status_code == 403
        assert mismatch.json()["agentscan_code"] == "IDENTITY_MISMATCH"
        assert runtime.calls == []

        after_metrics = await other_client.get("/metrics")
        assert (
            _metric_value(
                after_metrics.text,
                "agentscan_gateway_identity_mismatches_total",
                "identity_mismatch",
            )
            == before_identity + 1
        )
        assert (
            _metric_value(
                after_metrics.text, "agentscan_gateway_protocol_failures_total", "identity_mismatch"
            )
            == before_protocol
        )

        reinit, new_sid = await _initialize(other_client, private)
        assert reinit.status_code == 200
        assert new_sid != sid
        listed = await other_client.post(
            "/mcp",
            headers={"Mcp-Session-Id": new_sid, "MCP-Protocol-Version": PINNED_PROTOCOL_VERSION},
            json={"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}},
        )
        assert listed.status_code == 200
        original = await client.post(
            "/mcp",
            headers={"Mcp-Session-Id": sid, "MCP-Protocol-Version": PINNED_PROTOCOL_VERSION},
            json={"jsonrpc": "2.0", "id": 4, "method": "tools/list", "params": {}},
        )
        assert original.status_code == 200
    finally:
        await other_client.aclose()


@pytest.mark.asyncio
async def test_localhost_protocol_version_headers_are_required_then_ping_works(gateway) -> None:
    client, _runtime, private, _port = gateway
    init, sid = await _initialize(client, private)

    missing = await client.post(
        "/mcp",
        headers={"Mcp-Session-Id": sid},
        json={"jsonrpc": "2.0", "id": 2, "method": "ping", "params": {}},
    )
    assert missing.status_code == 400
    assert missing.json()["agentscan_code"] == "UNSUPPORTED_PROTOCOL_VERSION"

    wrong = await client.post(
        "/mcp",
        headers={"Mcp-Session-Id": sid, "MCP-Protocol-Version": "2024-11-05"},
        json={"jsonrpc": "2.0", "id": 3, "method": "ping", "params": {}},
    )
    assert wrong.status_code == 400
    assert wrong.json()["agentscan_code"] == "UNSUPPORTED_PROTOCOL_VERSION"

    ping = await client.post(
        "/mcp",
        headers={"Mcp-Session-Id": sid, "MCP-Protocol-Version": PINNED_PROTOCOL_VERSION},
        json={"jsonrpc": "2.0", "id": 4, "method": "ping", "params": {}},
    )
    assert ping.status_code == 200


@pytest.mark.asyncio
async def test_localhost_metrics_expose_no_raw_credentials(gateway) -> None:
    client, _runtime, _private, _port = gateway
    metrics = await client.get("/metrics")
    assert metrics.status_code == 200
    assert metrics.headers["content-type"].startswith("text/plain; version=0.0.4")
    assert "# TYPE" in metrics.text
    assert "eyJ" not in metrics.text
    assert "Bearer" not in metrics.text
    assert "principal-a" not in metrics.text


@pytest.mark.asyncio
async def test_localhost_unavailable_runtime_yields_gateway_unavailable() -> None:
    async with _started_gateway(runtime=UnavailableToolRuntime()) as (
        client,
        runtime,
        _private,
        _port,
        _sessions,
    ):
        readyz = await client.get("/readyz")
        assert readyz.status_code == 503
        body = readyz.json()
        assert body["status"] == "not_ready"
        assert body["agentscan_code"] == "GATEWAY_UNAVAILABLE"
        assert body["reason"] in {
            "policy_missing",
            "policy_expired",
            "chain_invalid",
            "writer_lease_missing",
            "receipt_sink_unhealthy",
            "catalog_unavailable",
        }
        assert "," not in body["reason"]
        assert re.fullmatch(r"[a-z0-9_]{1,64}", body["reason"]) is not None
        init, sid = await _initialize(client, _private)
        assert init.status_code == 200
        tools = await client.post(
            "/mcp",
            headers={"Mcp-Session-Id": sid, "MCP-Protocol-Version": PINNED_PROTOCOL_VERSION},
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        )
        assert tools.status_code == 200
        denied = await client.post(
            "/mcp",
            headers={"Mcp-Session-Id": sid, "MCP-Protocol-Version": PINNED_PROTOCOL_VERSION},
            json={
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "echo", "arguments": {"value": "hello"}},
            },
        )
        assert denied.status_code == 200
        assert denied.json()["error"]["code"] == -32000
        assert denied.json()["error"]["data"]["agentscan_code"] == "GATEWAY_UNAVAILABLE"


@pytest.mark.asyncio
async def test_localhost_expired_session_requires_reinitialize() -> None:
    clock = [float(time.time())]
    async with _started_gateway(
        runtime=FakeRuntime(),
        sessions=SessionRegistry(
            idle_timeout_seconds=300, max_lifetime_seconds=900, clock=lambda: clock[0]
        ),
    ) as (client, _runtime, private, _port, _sessions):
        init, sid = await _initialize(client, private)
        assert init.status_code == 200
        clock[0] = int(clock[0]) + 400
        expired = await client.post(
            "/mcp",
            headers={"Mcp-Session-Id": sid, "MCP-Protocol-Version": PINNED_PROTOCOL_VERSION},
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        )
        assert expired.status_code == 404
        assert expired.json()["agentscan_code"] == "IDENTITY_MISSING"
        reinit, new_sid = await _initialize(client, private)
        assert reinit.status_code == 200
        assert new_sid != sid


class _SecretRuntime:
    async def list_tools(self, context: GatewayRequestContext) -> Sequence[Tool]:
        raise RuntimeError("secret/path/token-value")

    async def call_tool(
        self, context: GatewayRequestContext, name: str, arguments: Mapping[str, Any]
    ) -> CallToolResult:
        raise RuntimeError("secret/path/token-value")

    def readiness(self) -> Readiness:
        return Readiness(True, False, True, True, True, True)


@pytest.mark.asyncio
async def test_localhost_runtime_exception_is_contained() -> None:
    async with _started_gateway(runtime=_SecretRuntime()) as (
        client,
        _runtime,
        private,
        _port,
        _sessions,
    ):
        init, sid = await _initialize(client, private)
        assert init.status_code == 200

        listed = await client.post(
            "/mcp",
            headers={"Mcp-Session-Id": sid, "MCP-Protocol-Version": PINNED_PROTOCOL_VERSION},
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        )
        assert listed.status_code == 200
        listed_body = listed.json()
        assert listed_body["error"]["code"] == -32000
        assert listed_body["error"]["data"]["agentscan_code"] == "UPSTREAM_ERROR"
        assert "secret/path" not in listed.text
        assert "token-value" not in listed.text

        called = await client.post(
            "/mcp",
            headers={"Mcp-Session-Id": sid, "MCP-Protocol-Version": PINNED_PROTOCOL_VERSION},
            json={
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "echo", "arguments": {"value": "hello"}},
            },
        )
        assert called.status_code == 200
        called_body = called.json()
        assert called_body["error"]["code"] == -32000
        assert called_body["error"]["data"]["agentscan_code"] == "UPSTREAM_ERROR"
        assert "secret/path" not in called.text
        assert "token-value" not in called.text


@pytest.mark.asyncio
async def test_localhost_rejection_counters_are_status_aware(gateway) -> None:
    client, _runtime, _private, _port = gateway

    no_auth = httpx.AsyncClient(base_url=str(client.base_url), timeout=3)
    try:
        before = await no_auth.get("/metrics")
        before_auth = _metric_value(
            before.text, "agentscan_gateway_auth_failures_total", "identity_missing"
        )
        unauthenticated = await no_auth.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        )
        assert unauthenticated.status_code == 401
        after = await no_auth.get("/metrics")
        assert (
            _metric_value(after.text, "agentscan_gateway_auth_failures_total", "identity_missing")
            == before_auth + 1
        )
    finally:
        await no_auth.aclose()

    before_protocol_client = await client.get("/metrics")
    before_protocol = _metric_value(
        before_protocol_client.text, "agentscan_gateway_protocol_failures_total", "identity_missing"
    )
    before_auth_protocol = _metric_value(
        before_protocol_client.text, "agentscan_gateway_auth_failures_total", "identity_missing"
    )
    missing_session = await client.post(
        "/mcp",
        headers={
            "Mcp-Session-Id": "missing-session",
            "MCP-Protocol-Version": PINNED_PROTOCOL_VERSION,
        },
        json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    )
    assert missing_session.status_code == 404
    after_protocol_client = await client.get("/metrics")
    assert (
        _metric_value(
            after_protocol_client.text,
            "agentscan_gateway_protocol_failures_total",
            "identity_missing",
        )
        == before_protocol + 1
    )
    assert (
        _metric_value(
            after_protocol_client.text, "agentscan_gateway_auth_failures_total", "identity_missing"
        )
        == before_auth_protocol
    )


def _minimal_fail_closed_settings() -> GatewaySettings:
    return GatewaySettings.model_validate(
        {
            "tenant": "tenant-a",
            "gateway_id": "gw",
            "chain_id": "chain",
            "writer_id": "writer",
            "audience": "agentscan",
            "trusted_issuer": "issuer-a",
            "listen_host": "127.0.0.1",
            "listen_port": 8765,
            "upstream_url": "http://127.0.0.1:9999",
            "upstream_server_id": "fake",
            "upstream_credential_env": "FAKE_TOKEN",
            "policy_bundle": "policy.yaml",
            "policy_public_key": "policy.pub",
            "trust_keys": "trust.json",
            "receipt_dir": "receipts",
        }
    )


def _minimal_fail_closed_dependencies() -> tuple[IdentityVerifier, SessionRegistry]:
    return (
        IdentityVerifier(
            trusted_issuer="issuer-a", audience="agentscan", tenant="tenant-a", trust_keys={}
        ),
        SessionRegistry(idle_timeout_seconds=300, max_lifetime_seconds=900),
    )


def test_readyz_fail_closed_defaults() -> None:
    settings = _minimal_fail_closed_settings()
    identity_verifier, sessions = _minimal_fail_closed_dependencies()
    app = create_app(settings, identity_verifier=identity_verifier, sessions=sessions)
    with TestClient(app) as client:
        response = client.get("/readyz")
        assert response.status_code == 503
        body = response.json()
        assert body["status"] == "not_ready"
        assert body["agentscan_code"] == "GATEWAY_UNAVAILABLE"
        assert body["reason"] == "policy_missing"
        assert "," not in body["reason"]
        assert re.fullmatch(r"[a-z0-9_]{1,64}", body["reason"]) is not None


def test_readyz_fail_closed_for_non_readiness_probe_results() -> None:
    settings = _minimal_fail_closed_settings()
    identity_verifier, sessions = _minimal_fail_closed_dependencies()
    for probe in (lambda: None, lambda: {"policy_loaded": True}, lambda: "ready"):
        app = create_app(
            settings,
            identity_verifier=identity_verifier,
            sessions=sessions,
            readiness=probe,  # type: ignore[arg-type]
        )
        with TestClient(app) as client:
            response = client.get("/readyz")
            assert response.status_code == 503
            body = response.json()
            assert body["status"] == "not_ready"
            assert body["reason"] == "policy_missing"
            assert "," not in body["reason"]
            assert re.fullmatch(r"[a-z0-9_]{1,64}", body["reason"]) is not None


def test_readyz_fail_closed_for_raising_probe() -> None:
    settings = _minimal_fail_closed_settings()
    identity_verifier, sessions = _minimal_fail_closed_dependencies()

    def raising_probe() -> Readiness:
        raise RuntimeError("secret/path")

    app = create_app(
        settings,
        identity_verifier=identity_verifier,
        sessions=sessions,
        readiness=raising_probe,
    )
    with TestClient(app) as client:
        response = client.get("/readyz")
        assert response.status_code == 503
        body = response.json()
        assert body["status"] == "not_ready"
        assert "secret/path" not in response.text


def test_readyz_ready_for_complete_probe() -> None:
    settings = _minimal_fail_closed_settings()
    identity_verifier, sessions = _minimal_fail_closed_dependencies()
    app = create_app(
        settings,
        identity_verifier=identity_verifier,
        sessions=sessions,
        readiness=lambda: Readiness(True, False, True, True, True, True),
    )
    with TestClient(app) as client:
        response = client.get("/readyz")
        assert response.status_code == 200
        assert response.json() == {"status": "ready"}


class _FalsyReadyProbe:
    def __bool__(self) -> bool:
        return False

    def __call__(self) -> Readiness:
        return Readiness(True, False, True, True, True, True)


class _FalsyRuntime:
    def __bool__(self) -> bool:
        return False

    async def list_tools(self, context: GatewayRequestContext) -> Sequence[Tool]:
        raise AssertionError("not used")

    async def call_tool(
        self, context: GatewayRequestContext, name: str, arguments: Mapping[str, Any]
    ) -> CallToolResult:
        raise AssertionError("not used")

    def readiness(self) -> Readiness:
        return Readiness(True, False, True, True, True, True)


def test_readyz_uses_runtime_fallback_with_is_not_none() -> None:
    settings = _minimal_fail_closed_settings()
    identity_verifier, sessions = _minimal_fail_closed_dependencies()
    app = create_app(
        settings,
        identity_verifier=identity_verifier,
        sessions=sessions,
        runtime=_FalsyRuntime(),
        readiness=None,
    )
    with TestClient(app) as client:
        response = client.get("/readyz")
        assert response.status_code == 200
        assert response.json() == {"status": "ready"}


def test_readyz_honors_falsy_injected_probe() -> None:
    settings = _minimal_fail_closed_settings()
    identity_verifier, sessions = _minimal_fail_closed_dependencies()
    app = create_app(
        settings,
        identity_verifier=identity_verifier,
        sessions=sessions,
        runtime=UnavailableToolRuntime(),
        readiness=_FalsyReadyProbe(),
    )
    with TestClient(app) as client:
        response = client.get("/readyz")
        assert response.status_code == 200
        assert response.json() == {"status": "ready"}
