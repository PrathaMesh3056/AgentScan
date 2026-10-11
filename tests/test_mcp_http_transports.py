"""MCP resumption and legacy discovery use bounded, correlated protocol IO."""

from __future__ import annotations

import asyncio
import json
import queue
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest

from agentscan.core.connectors.mcp import McpSseConnector, _SseDecoder, mcp_sse_http_url
from agentscan.core.models import Target


def event(data=None, *, identifier=None, name=None, newline="\n"):
    lines = []
    if identifier is not None:
        lines.append(f"id: {identifier}")
    if name is not None:
        lines.append(f"event: {name}")
    if data is not None:
        lines.append("data: " + (json.dumps(data) if not isinstance(data, str) else data))
    return (newline.join(lines) + newline * 2).encode()


def rpc_result(identifier=1, text="correlated reply"):
    return {"jsonrpc": "2.0", "id": identifier, "result": {"content": [{"text": text}]}}


class FiniteStream(httpx.AsyncByteStream):
    def __init__(self, chunks, *, disconnect=False, delay=0):
        self.chunks = chunks
        self.disconnect = disconnect
        self.delay = delay
        self.closed = False

    async def __aiter__(self):
        for chunk in self.chunks:
            if self.delay:
                await asyncio.sleep(self.delay)
            yield chunk
        if self.disconnect:
            raise httpx.ReadError("synthetic stream disconnect")

    async def aclose(self):
        self.closed = True


class QueueStream(httpx.AsyncByteStream):
    def __init__(self, initial):
        self.queue = asyncio.Queue()
        self.queue.put_nowait(initial)
        self.closed = False

    async def __aiter__(self):
        while True:
            chunk = await self.queue.get()
            if chunk is None:
                return
            yield chunk

    async def aclose(self):
        self.closed = True


def direct_connector(handler, *, timeout=2, max_bytes=4096):
    connector = McpSseConnector(
        Target(url="mcp+sse://mcp.example/mcp", timeout=timeout, max_response_bytes=max_bytes)
    )
    connector._client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        follow_redirects=False,
        headers={"Mcp-Session-Id": "synthetic-session", "MCP-Protocol-Version": "2025-06-18"},
    )
    connector._transport = "modern"
    connector._session_id = "synthetic-session"
    return connector


@pytest.mark.parametrize("disconnect", [False, True])
@pytest.mark.parametrize("newline", ["\n", "\r\n", "\r"])
async def test_modern_resumes_observed_cursor_same_endpoint_without_replaying_post(
    disconnect, newline
):
    requests = []
    notification = {"jsonrpc": "2.0", "method": "notifications/message"}
    first = FiniteStream(
        [event(notification, identifier="cursor-1", newline=newline)], disconnect=disconnect
    )

    def reply(request):
        requests.append(request)
        if request.method == "DELETE":
            return httpx.Response(204)
        if request.method == "POST":
            return httpx.Response(200, headers={"Content-Type": "text/event-stream"}, stream=first)
        assert str(request.url) == "http://mcp.example/mcp"
        assert request.headers["Last-Event-ID"] == "cursor-1"
        assert request.headers["Mcp-Session-Id"] == "synthetic-session"
        assert request.headers["MCP-Protocol-Version"] == "2025-06-18"
        return httpx.Response(
            200,
            headers={"Content-Type": "text/event-stream"},
            content=(
                event(rpc_result(999, "wrong response"), identifier="cursor-2")
                + event(rpc_result())
            ),
        )

    connector = direct_connector(reply)
    try:
        result = await connector._rpc("tools/call", {"name": "synthetic", "arguments": {}})
        assert result == rpc_result()
    finally:
        await connector.__aexit__()
    assert [item.method for item in requests] == ["POST", "GET", "DELETE"]
    assert first.closed


@pytest.mark.parametrize(
    "frame",
    [
        event({"jsonrpc": "2.0", "method": "notifications/message"}),
        b"id: incomplete\ndata: {}\n",
        b"id: bad\x00id\n\n",
        event(identifier="x" * 257),
        event(identifier="é"),
        event(identifier="cursor") + event(identifier=""),
    ],
)
async def test_modern_never_resumes_without_safe_completed_cursor(frame):
    requests = []

    def reply(request):
        requests.append(request)
        if request.method == "DELETE":
            return httpx.Response(204)
        return httpx.Response(200, headers={"Content-Type": "text/event-stream"}, content=frame)

    connector = direct_connector(reply)
    try:
        with pytest.raises(ValueError):
            await connector._rpc("tools/call")
    finally:
        await connector.__aexit__()
    assert [item.method for item in requests] == ["POST", "DELETE"]


async def test_modern_response_budget_is_shared_across_resumption():
    requests = []

    def reply(request):
        requests.append(request)
        if request.method == "DELETE":
            return httpx.Response(204)
        content = b":" + b"x" * 600 + b"\n\n"
        content += event(identifier="cursor") if request.method == "POST" else event(rpc_result())
        return httpx.Response(200, headers={"Content-Type": "text/event-stream"}, content=content)

    connector = direct_connector(reply, max_bytes=1024)
    try:
        with pytest.raises(ValueError, match="size limit"):
            await connector._rpc("tools/call")
    finally:
        await connector.__aexit__()
    assert [item.method for item in requests] == ["POST", "GET", "DELETE"]


async def test_modern_resumption_uses_original_global_deadline():
    requests = []

    def reply(request):
        requests.append(request)
        if request.method == "DELETE":
            return httpx.Response(204)
        content = event(identifier="cursor") if request.method == "POST" else event(rpc_result())
        return httpx.Response(
            200,
            headers={"Content-Type": "text/event-stream"},
            stream=FiniteStream([content], delay=0.6),
        )

    connector = direct_connector(reply, timeout=1)
    try:
        with pytest.raises(TimeoutError):
            await connector._rpc("tools/call")
    finally:
        await connector.__aexit__()
    assert [item.method for item in requests] == ["POST", "GET", "DELETE"]


async def test_modern_stops_after_two_get_resumptions():
    requests = []

    def reply(request):
        requests.append(request)
        if request.method == "DELETE":
            return httpx.Response(204)
        return httpx.Response(
            200, headers={"Content-Type": "text/event-stream"}, content=event(identifier="cursor")
        )

    connector = direct_connector(reply)
    try:
        with pytest.raises(ValueError, match="not replayed"):
            await connector._rpc("tools/call")
    finally:
        await connector.__aexit__()
    assert [item.method for item in requests] == ["POST", "GET", "GET", "DELETE"]


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(302, headers={"Location": "http://outside.example/mcp"}),
        httpx.Response(405),
        httpx.Response(200, json=rpc_result()),
    ],
)
async def test_modern_rejects_redirect_or_unavailable_non_sse_resume(response):
    requests = []

    def reply(request):
        requests.append(request)
        if request.method == "DELETE":
            return httpx.Response(204)
        if request.method == "GET":
            return response
        return httpx.Response(
            200, headers={"Content-Type": "text/event-stream"}, content=event(identifier="cursor")
        )

    connector = direct_connector(reply)
    try:
        with pytest.raises((ValueError, httpx.HTTPStatusError)):
            await connector._rpc("tools/call")
    finally:
        await connector.__aexit__()
    assert [item.method for item in requests] == ["POST", "GET", "DELETE"]
    assert all(item.url.host == "mcp.example" for item in requests)


async def test_failed_matching_rpc_is_not_resumed_or_replayed():
    requests = []

    def reply(request):
        requests.append(request)
        if request.method == "DELETE":
            return httpx.Response(204)
        return httpx.Response(
            200,
            headers={"Content-Type": "text/event-stream"},
            content=event(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "error": {"code": -32603, "message": "synthetic failure"},
                },
                identifier="cursor",
            ),
        )

    connector = direct_connector(reply)
    try:
        with pytest.raises(ValueError, match="failed"):
            await connector._rpc("tools/call")
    finally:
        await connector.__aexit__()
    assert [item.method for item in requests] == ["POST", "DELETE"]


@pytest.mark.parametrize("sse", [False, True])
async def test_server_request_cannot_masquerade_as_matching_success(sse):
    requests = []
    # A request uses `method`; adding `result` cannot turn it into a response.
    malformed = {**rpc_result(), "method": "sampling/createMessage"}

    def reply(request):
        requests.append(request)
        if request.method == "DELETE":
            return httpx.Response(204)
        if sse:
            return httpx.Response(
                200,
                headers={"Content-Type": "text/event-stream"},
                content=event(malformed, identifier="cursor"),
            )
        return httpx.Response(200, json=malformed)

    connector = direct_connector(reply)
    try:
        with pytest.raises(ValueError, match="failed"):
            await connector._rpc("tools/call")
    finally:
        await connector.__aexit__()
    assert [item.method for item in requests] == ["POST", "DELETE"]


@pytest.mark.parametrize(
    "parts",
    [
        [b"id: cursor\r", b"\ndata: {}\r", b"\n\r", b"\n"],
        [b"id: cursor\rdata: {}\r\r"],
        [b"id: cursor\ndata: {}\n\n"],
    ],
)
def test_sse_framing_across_all_line_endings(parts):
    decoder = _SseDecoder()
    frames = [item for part in parts for item in decoder.feed(part)]
    assert len(frames) == 1
    assert frames[0].event_id == "cursor" and frames[0].data == "{}"


@pytest.mark.parametrize(
    "url",
    [
        "mcp+sse://user:pass@mcp.example/sse",
        "mcp+sse://mcp.example/sse#fragment",
        "mcp+sse://mcp.example:0/sse",
        "mcp+sse://mcp.example:65536/sse",
        "mcp+sse:///sse",
        "mcp+sse://mcp.example\\outside/sse",
    ],
)
def test_selected_http_endpoint_cannot_use_credentials_fragment_or_invalid_origin(url):
    with pytest.raises(ValueError):
        mcp_sse_http_url(url)


class LegacyMock:
    def __init__(
        self,
        advertised="/messages?session=synthetic",
        *,
        initial_status=405,
        quiet=False,
        tool_error=False,
    ):
        self.stream = QueueStream(event(advertised, name="endpoint"))
        self.initial_status = initial_status
        self.requests = []
        self.quiet = quiet
        self.tool_error = tool_error
        self.tool_seen = asyncio.Event()

    async def reply(self, request):
        self.requests.append(request)
        if request.method == "GET":
            return httpx.Response(
                200, headers={"Content-Type": "text/event-stream"}, stream=self.stream
            )
        body = json.loads(request.content)
        if request.url.path == "/sse":
            return httpx.Response(self.initial_status)
        rid, method = body.get("id"), body["method"]
        if rid is not None and not self.quiet:
            if method == "initialize":
                result = {"protocolVersion": "2024-11-05", "capabilities": {}}
            elif method == "tools/list":
                result = {"tools": [{"name": "synthetic-tool"}]}
            else:
                self.tool_seen.set()
                self.stream.queue.put_nowait(
                    event({"jsonrpc": "2.0", "method": "notifications/message"}, name="message")
                )
                self.stream.queue.put_nowait(event(rpc_result(999, "unrelated"), name="message"))
                if self.tool_error:
                    self.stream.queue.put_nowait(
                        event(
                            {
                                "jsonrpc": "2.0",
                                "id": rid,
                                "error": {"code": -32603, "message": "synthetic"},
                            },
                            name="message",
                        )
                    )
                    return httpx.Response(202)
                result = {"content": [{"text": "legacy correlated reply"}]}
            self.stream.queue.put_nowait(
                event({"jsonrpc": "2.0", "id": rid, "result": result}, name="message")
            )
        elif method == "tools/call":
            self.tool_seen.set()
        return httpx.Response(202)


def legacy_connector(monkeypatch, mock, *, timeout=2, max_bytes=4096):
    original_client = httpx.AsyncClient
    monkeypatch.setattr(
        httpx,
        "AsyncClient",
        lambda **options: original_client(transport=httpx.MockTransport(mock.reply), **options),
    )
    return McpSseConnector(
        Target(
            url="mcp+sse://mcp.example/sse",
            auth_header="Bearer synthetic-credential",
            extra_headers={"X-API-Key": "synthetic-second-credential"},
            timeout=timeout,
            max_response_bytes=max_bytes,
        )
    )


@pytest.mark.parametrize("initial_status", [404, 405])
async def test_legacy_initial_discovery_correlated_reply_and_close(monkeypatch, initial_status):
    mock = LegacyMock(initial_status=initial_status)
    connector = legacy_connector(monkeypatch, mock)
    async with connector:
        assert connector._transport == "legacy"
        assert (await connector.send_message("synthetic probe"))[
            "response"
        ] == "legacy correlated reply"
        assert not connector._legacy_pending
    assert connector._client is None and connector._legacy_reader is None
    assert mock.stream.closed
    assert sum(item.method == "GET" for item in mock.requests) == 1
    messages = [
        item for item in mock.requests if item.method == "POST" and item.url.path == "/messages"
    ]
    assert [json.loads(item.content)["method"] for item in messages] == [
        "initialize",
        "notifications/initialized",
        "tools/list",
        "tools/call",
    ]
    assert all(item.url.host == "mcp.example" for item in mock.requests)
    assert all(
        item.headers["Authorization"] == "Bearer synthetic-credential" for item in mock.requests
    )
    assert all(item.headers["X-API-Key"] == "synthetic-second-credential" for item in mock.requests)


@pytest.mark.parametrize(
    "advertised",
    [
        "http://outside.example/messages",
        "//outside.example/messages",
        "https://mcp.example/messages",
        "http://mcp.example:99/messages",
        "http://user:password@mcp.example/messages",
        "/messages#fragment",
        "../messages",
        "/safe/../messages",
        "/safe/%2e%2e/messages",
        "/safe/%252e/messages",
        "/safe%2fmessages",
        "/safe%5cmessages",
        "/messages%0a",
        "/messages%00",
        "/messages%7f",
        "http://mcp.example:0/messages",
        "",
        "/messages\\outside",
    ],
)
async def test_legacy_rejects_unsafe_endpoint_before_authenticated_message(monkeypatch, advertised):
    mock = LegacyMock(advertised)
    connector = legacy_connector(monkeypatch, mock)
    with pytest.raises(ValueError):
        await connector.__aenter__()
    assert connector._client is None and connector._legacy_reader is None
    assert mock.stream.closed
    assert [item.method for item in mock.requests] == ["POST", "GET"]


@pytest.mark.parametrize("initial_status", [400, 401, 403, 429, 500])
async def test_legacy_fallback_never_follows_auth_quota_or_server_error(
    monkeypatch, initial_status
):
    mock = LegacyMock(initial_status=initial_status)
    connector = legacy_connector(monkeypatch, mock)
    with pytest.raises(httpx.HTTPStatusError):
        await connector.__aenter__()
    assert [item.method for item in mock.requests] == ["POST"]
    assert connector._client is None


async def test_legacy_quiet_handshake_times_out_and_closes_pending_reader(monkeypatch):
    mock = LegacyMock(quiet=True)
    connector = legacy_connector(monkeypatch, mock, timeout=1)
    with pytest.raises(TimeoutError):
        await connector.__aenter__()
    assert mock.stream.closed and not connector._legacy_pending
    assert connector._client is None and connector._legacy_reader is None


async def test_legacy_tool_error_does_not_replay_post_or_redo_discovery(monkeypatch):
    mock = LegacyMock(tool_error=True)
    connector = legacy_connector(monkeypatch, mock)
    async with connector:
        result = await connector.send_message("synthetic probe")
        assert "error" in result and "response" not in result
    assert sum(item.method == "GET" for item in mock.requests) == 1
    assert (
        sum(
            item.method == "POST" and json.loads(item.content)["method"] == "tools/call"
            for item in mock.requests
        )
        == 1
    )
    assert not connector._legacy_pending and mock.stream.closed


async def test_legacy_cancelled_tool_request_cleans_pending_future(monkeypatch):
    mock = LegacyMock()
    connector = legacy_connector(monkeypatch, mock)
    async with connector:
        mock.quiet = True
        task = asyncio.create_task(connector.send_message("synthetic probe"))
        await asyncio.wait_for(mock.tool_seen.wait(), 1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert not connector._legacy_pending
    assert mock.stream.closed and connector._legacy_reader is None


async def test_legacy_session_stream_has_total_byte_bound(monkeypatch):
    mock = LegacyMock()
    mock.stream.queue.put_nowait(b":" + b"x" * 1100 + b"\n\n")
    connector = legacy_connector(monkeypatch, mock, max_bytes=1024)
    with pytest.raises((ValueError, ConnectionError)):
        await connector.__aenter__()
    assert mock.stream.closed and connector._client is None


async def test_actual_loopback_legacy_server_handshake_authentication_and_socket_cleanup():
    outgoing = queue.Queue()
    stopped, socket_closed = threading.Event(), threading.Event()
    received = []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def empty_response(self, status):
            self.send_response(status)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            received.append((self.command, self.path, body["method"]))
            if self.headers.get("Authorization") != "Bearer synthetic-local-token":
                self.empty_response(401)
                return
            if self.path == "/sse":
                self.empty_response(405)
                return
            self.empty_response(202)
            rid = body.get("id")
            if rid is None:
                return
            if body["method"] == "initialize":
                result = {"protocolVersion": "2024-11-05", "capabilities": {}}
            elif body["method"] == "tools/list":
                result = {"tools": [{"name": "synthetic-fixture-tool"}]}
            else:
                result = {"content": [{"text": "actual local legacy reply"}]}
            outgoing.put(event({"jsonrpc": "2.0", "id": rid, "result": result}, name="message"))

        def do_GET(self):
            received.append((self.command, self.path, None))
            if self.headers.get("Authorization") != "Bearer synthetic-local-token":
                self.empty_response(401)
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()

            def send_chunk(data):
                self.wfile.write(f"{len(data):x}\r\n".encode() + data + b"\r\n")
                self.wfile.flush()

            try:
                send_chunk(event("/messages?session=synthetic", name="endpoint"))
                while not stopped.is_set():
                    try:
                        data = outgoing.get(timeout=0.05)
                    except queue.Empty:
                        data = b": keepalive\n\n"
                    send_chunk(data)
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
            finally:
                socket_closed.set()
                self.close_connection = True

    fixture = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    fixture.daemon_threads = True
    thread = threading.Thread(target=lambda: fixture.serve_forever(poll_interval=0.05), daemon=True)
    thread.start()
    connector = McpSseConnector(
        Target(
            url=f"mcp+sse://127.0.0.1:{fixture.server_port}/sse",
            timeout=3,
            auth_header="Bearer synthetic-local-token",
        )
    )
    try:
        async with connector:
            result = await connector.send_message("synthetic local probe")
            assert result["response"] == "actual local legacy reply"
        assert await asyncio.to_thread(socket_closed.wait, 1)
        assert connector._client is None and connector._legacy_reader is None
        assert [item[2] for item in received if item[0] == "POST"] == [
            "initialize",
            "initialize",
            "notifications/initialized",
            "tools/list",
            "tools/call",
        ]
    finally:
        stopped.set()
        fixture.shutdown()
        fixture.server_close()
        thread.join(timeout=1)
