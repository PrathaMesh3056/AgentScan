# agentscan/core/connectors/mcp.py
#
# Model Context Protocol (MCP) connectors over Stdio and SSE/HTTP.

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import sys
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, unquote, urljoin, urlparse, urlunparse

import httpx
from loguru import logger

from agentscan.core.connectors.base import (
    Connector,
    flatten_conversation,
)
from agentscan.core.egress import canonical_origin
from agentscan.core.models import Target, _installed_version


def _jsonrpc_request(
    req_id: int, method: str, params: dict[str, Any] | None = None
) -> dict[str, Any]:
    msg: dict[str, Any] = {"jsonrpc": "2.0", "id": req_id, "method": method}
    if params is not None:
        msg["params"] = params
    return msg


def _mcp_text_from_result(result: Any) -> str:
    """Lift MCP tools/call or resources/read payloads into a single string."""
    if result is None:
        return ""
    if isinstance(result, str):
        return result
    if not isinstance(result, dict):
        return json.dumps(result)
    content = result.get("content")
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, dict) and item.get("text"):
                parts.append(str(item["text"]))
            elif isinstance(item, str):
                parts.append(item)
        if parts:
            return "\n".join(parts)
    contents = result.get("contents")
    if isinstance(contents, list):
        parts = []
        for item in contents:
            if isinstance(item, dict) and item.get("text"):
                parts.append(str(item["text"]))
        if parts:
            return "\n".join(parts)
    if "message" in result:
        return str(result["message"])
    return json.dumps(result)


def _parse_mcp_stdio_command(url: str) -> list[str]:
    """
    mcp://stdio?command=python&arg=-u&arg=server.py
    mcp+stdio://stdio?command=npx
    """
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    command = (qs.get("command") or qs.get("cmd") or [sys.executable])[0]
    args = [unquote(a) for a in qs.get("arg", [])]
    return [command, *args]


def mcp_sse_http_url(url: str) -> str:
    """mcp+sse://host/path → http://host/path (https when scheme is mcp+sses)."""
    parsed = urlparse(url)
    if (
        parsed.scheme.lower() not in {"mcp+sse", "mcp+sses"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or "\\" in url
        or any(ord(char) <= 32 or ord(char) == 127 for char in url)
    ):
        raise ValueError("MCP HTTP endpoints require a hostname and no credentials or fragment")
    if parsed.port == 0:
        raise ValueError("MCP endpoint port must be between 1 and 65535")
    scheme = "https" if parsed.scheme.lower() == "mcp+sses" else "http"
    return urlunparse((scheme, parsed.netloc, parsed.path or "/", parsed.params, parsed.query, ""))


@dataclass
class _SseEvent:
    event: str | None
    data: str
    event_id: str | None


class _SseDecoder:
    """Incremental SSE framing; callers enforce aggregate byte/time bounds."""

    def __init__(self) -> None:
        self.buffer = b""
        self.lines: list[str] = []
        self.event: str | None = None
        self.event_id: str | None = None
        self._ignore_lf = False

    def feed(self, chunk: bytes) -> Iterator[_SseEvent]:
        if self._ignore_lf and chunk:
            if chunk.startswith(b"\n"):
                chunk = chunk[1:]
            self._ignore_lf = False
        self.buffer += chunk
        while True:
            positions = [
                position for marker in (b"\r", b"\n") if (position := self.buffer.find(marker)) >= 0
            ]
            if not positions:
                break
            position = min(positions)
            line, terminator = self.buffer[:position], self.buffer[position : position + 1]
            self.buffer = self.buffer[position + 1 :]
            if terminator == b"\r":
                if self.buffer.startswith(b"\n"):
                    self.buffer = self.buffer[1:]
                elif not self.buffer:
                    self._ignore_lf = True
            if not line:
                if self.lines or self.event_id is not None or self.event is not None:
                    yield _SseEvent(self.event, "\n".join(self.lines), self.event_id)
                self.lines, self.event, self.event_id = [], None, None
                continue
            if line.startswith(b":"):
                continue
            field, separator, value = line.partition(b":")
            if separator and value.startswith(b" "):
                value = value[1:]
            if field == b"data":
                self.lines.append(value.decode("utf-8"))
            elif field == b"event":
                self.event = value.decode("utf-8")
            elif field == b"id":
                identifier = value.decode("utf-8")
                if len(identifier) > 256 or any(not 33 <= ord(char) <= 126 for char in identifier):
                    raise ValueError("Invalid MCP stream event identifier")
                self.event_id = identifier


@dataclass
class _ResumeState:
    total_bytes: int = 0
    last_event_id: str | None = None


class _LegacyTransportRequired(Exception):
    """Initial POST explicitly indicated a potentially legacy transport."""


class _McpClientMixin:
    """Shared initialize / tools.list / tools.call sequence for MCP transports."""

    _rpc_id: int
    _tools: list[dict[str, Any]]
    _resources: list[dict[str, Any]]

    async def _rpc(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        raise NotImplementedError(
            f"{type(self).__name__} must implement _rpc(). "
            "Did you forget to subclass McpStdioConnector or McpSseConnector?"
        )

    async def _notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        raise NotImplementedError(
            f"{type(self).__name__} must implement _notify(). "
            "Did you forget to subclass McpStdioConnector or McpSseConnector?"
        )

    async def _handshake(self) -> None:
        self._rpc_id = 0
        self._tools = []
        self._resources = []
        initialized = await self._rpc(
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "agentscan", "version": _installed_version()},
            },
        )
        negotiated = initialized.get("result", {}).get("protocolVersion")
        if negotiated not in {"2024-11-05", "2025-03-26", "2025-06-18"}:
            raise ValueError("Unsupported MCP protocol version")
        client = getattr(self, "_client", None)
        if client is not None:
            client.headers["MCP-Protocol-Version"] = negotiated
        await self._notify("notifications/initialized")
        self._tools = await self._list_all("tools/list", "tools")
        capabilities = initialized.get("result", {}).get("capabilities", {})
        if isinstance(capabilities, dict) and "resources" in capabilities:
            self._resources = await self._list_all("resources/list", "resources")

    async def _list_all(self, method: str, key: str) -> list[dict[str, Any]]:
        entries: list[dict[str, Any]] = []
        cursor: str | None = None
        seen: set[str] = set()
        catalog_bytes = 0
        limit = getattr(getattr(self, "target", None), "max_response_bytes", 4 * 1024 * 1024)
        for _ in range(100):
            response = await self._rpc(method, {"cursor": cursor} if cursor else None)
            result = response.get("result")
            if not isinstance(result, dict) or not isinstance(result.get(key), list):
                raise ValueError("Invalid MCP catalog response")
            catalog_bytes += len(json.dumps(result).encode())
            if catalog_bytes > limit or len(entries) + len(result[key]) > 10000:
                raise ValueError("MCP catalog exceeds size limit")
            for item in result[key]:
                if not isinstance(item, dict):
                    raise ValueError("Invalid MCP catalog entry")
                entries.append(item)
            cursor = result.get("nextCursor")
            if cursor is None:
                return entries
            if not isinstance(cursor, str) or not cursor or len(cursor) > 4096 or cursor in seen:
                raise ValueError("Invalid or repeated MCP catalog cursor")
            seen.add(cursor)
        raise ValueError("MCP catalog exceeds pagination limit")

    async def _probe_message(
        self, message: str, extra_body: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        extra = dict(extra_body or {})
        method = extra.pop("method", None)
        if method == "resources/read" or (
            not self._tools and message.startswith(("mcp:", "resource:"))
        ):
            uri = extra.pop("uri", message)
            raw = await self._rpc("resources/read", {"uri": uri})
            result = raw.get("result", raw)
            text = _mcp_text_from_result(result)
            return {"response": text, "raw": raw, "mcp_method": "resources/read"}

        tool_name = extra.pop("name", None) or extra.pop("tool", None)
        if tool_name is None and self._tools:
            tool_name = str(self._tools[0].get("name") or "")
        if not tool_name:
            return {"error": "MCP server exposes no callable tool for this probe", "status_code": 0}

        arguments: dict[str, Any] = {"message": message}
        arguments.update(extra)
        raw = await self._rpc("tools/call", {"name": tool_name, "arguments": arguments})
        result = raw.get("result", raw)
        if isinstance(result, dict) and result.get("isError") is True:
            return {"error": "MCP tool reported an error", "status_code": 0}
        text = _mcp_text_from_result(result)
        if not text:
            text = json.dumps(result)
        return {"response": text, "raw": raw, "tool": tool_name}


class McpStdioConnector(_McpClientMixin, Connector):
    """MCP server over newline-delimited UTF-8 JSON-RPC."""

    def __init__(self, target: Target) -> None:
        self.target = target
        self._proc: asyncio.subprocess.Process | None = None
        self._stderr_task: asyncio.Task | None = None
        self._lock = asyncio.Lock()
        self._rpc_id = 0
        self._tools = []
        self._resources = []

    async def __aenter__(self) -> McpStdioConnector:
        argv = _parse_mcp_stdio_command(self.target.url)
        self._proc = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=os.environ.copy(),
            limit=self.target.max_response_bytes + 1,
        )
        assert self._proc.stderr is not None
        stderr = self._proc.stderr

        async def drain_stderr():
            while await stderr.read(8192):
                pass  # Never forward untrusted process logs or collect an unbounded buffer.

        self._stderr_task = asyncio.create_task(drain_stderr())
        try:
            await asyncio.wait_for(self._handshake(), timeout=self.target.timeout)
        except BaseException:
            await self.__aexit__()
            raise
        return self

    async def __aexit__(self, *exc: Any) -> None:
        process, self._proc = self._proc, None
        if process is not None and process.returncode is None:
            with contextlib.suppress(ProcessLookupError):
                process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=2)
            except TimeoutError:
                with contextlib.suppress(ProcessLookupError):
                    process.kill()
                await asyncio.wait_for(process.wait(), timeout=2)
        if self._stderr_task is not None:
            self._stderr_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._stderr_task
            self._stderr_task = None

    async def _write_frame(self, payload: dict[str, Any]) -> None:
        assert self._proc is not None and self._proc.stdin is not None
        raw = json.dumps(payload).encode("utf-8")
        if len(raw) > self.target.max_response_bytes:
            raise ValueError("MCP request exceeds size limit")
        self._proc.stdin.write(raw + b"\n")
        await self._proc.stdin.drain()

    async def _read_frame(self) -> dict[str, Any]:
        assert self._proc is not None and self._proc.stdout is not None
        body = await asyncio.wait_for(self._proc.stdout.readline(), timeout=self.target.timeout)
        if not body:
            raise ConnectionError("MCP stdio process closed stdout")
        if len(body) > self.target.max_response_bytes or not body.endswith(b"\n"):
            raise ValueError("MCP response exceeds size limit or is unterminated")
        message = json.loads(body.decode("utf-8"))
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            raise ValueError("Invalid MCP JSON-RPC response")
        return message

    async def _rpc(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        async with self._lock, asyncio.timeout(self.target.timeout):
            self._rpc_id += 1
            req_id = self._rpc_id
            await self._write_frame(_jsonrpc_request(req_id, method, params))
            while True:
                msg = await self._read_frame()
                if "method" in msg and "id" in msg:
                    await self._write_frame(
                        {
                            "jsonrpc": "2.0",
                            "id": msg["id"],
                            "error": {"code": -32601, "message": "Client method unsupported"},
                        }
                    )
                    continue
                if type(msg.get("id")) is int and msg["id"] == req_id:
                    if "error" in msg or "result" not in msg:
                        raise ValueError("MCP request returned a protocol error")
                    return msg

    async def _notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        async with self._lock:
            payload: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
            if params is not None:
                payload["params"] = params
            await self._write_frame(payload)

    async def send_message(
        self, message: str, extra_body: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        if self._proc is None:
            raise RuntimeError("MCP stdio connector not initialised.")
        try:
            return await self._probe_message(message, extra_body)
        except Exception as e:  # noqa: BLE001
            logger.error("MCP stdio call failed: {}", type(e).__name__)
            return {"error": "MCP stdio request failed", "status_code": 0}

    async def send_conversation(self, messages: list[dict[str, str]]) -> dict[str, Any]:
        return await self.send_message(flatten_conversation(messages))


class McpSseConnector(_McpClientMixin, Connector):
    """Streamable HTTP with bounded GET resumption and initial legacy fallback."""

    def __init__(self, target: Target) -> None:
        self.target = target
        self.http_url = mcp_sse_http_url(target.url)
        self._client: httpx.AsyncClient | None = None
        self._session_id: str | None = None
        self._session_expired = False
        self._rpc_id = 0
        self._tools = []
        self._resources = []
        self._lock = asyncio.Lock()
        self._transport: str | None = None
        self._legacy_endpoint: str | None = None
        self._legacy_ready: asyncio.Future[str] | None = None
        self._legacy_reader: asyncio.Task[None] | None = None
        self._legacy_pending: dict[int, asyncio.Future[dict[str, Any]]] = {}
        self._legacy_bytes = 0

    async def __aenter__(self) -> McpSseConnector:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "Accept-Encoding": "identity",
        }
        if self.target.auth_header:
            if ":" in self.target.auth_header:
                key, _, value = self.target.auth_header.partition(":")
                headers[key.strip()] = value.strip()
            else:
                headers["Authorization"] = self.target.auth_header
        headers.update(self.target.extra_headers)
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.target.timeout),
            headers=headers,
            follow_redirects=False,
            trust_env=False,
        )
        try:
            await asyncio.wait_for(self._handshake(), timeout=self.target.timeout)
        except BaseException:
            await self.__aexit__()
            raise
        return self

    async def __aexit__(self, *exc: Any) -> None:
        if self._legacy_reader is not None:
            self._legacy_reader.cancel()
            with contextlib.suppress(asyncio.CancelledError, TimeoutError):
                await asyncio.wait_for(self._legacy_reader, 2)
            self._legacy_reader = None
        for future in self._legacy_pending.values():
            if not future.done():
                future.cancel()
        self._legacy_pending.clear()
        self._legacy_ready = None
        self._legacy_endpoint = None
        if self._client:
            try:
                if self._session_id:
                    with contextlib.suppress(httpx.HTTPError, TimeoutError):
                        async with asyncio.timeout(2):
                            # Do not buffer an untrusted DELETE response body.
                            async with self._client.stream("DELETE", self.http_url):
                                pass
            finally:
                await self._client.aclose()
                self._client = None
                self._session_id = None

    def _check_response(self, response: httpx.Response) -> None:
        if response.is_redirect:
            raise ValueError("MCP redirects require an explicitly selected endpoint")
        if response.status_code == 404 and self._session_id:
            self._session_expired = True
            self._session_id = None
            assert self._client is not None
            self._client.headers.pop("Mcp-Session-Id", None)
        response.raise_for_status()
        if response.headers.get("content-encoding", "identity").lower() != "identity":
            raise ValueError("Compressed MCP responses are not accepted")

    async def _read_sse_reply(
        self, response: httpx.Response, expected: int, state: _ResumeState
    ) -> dict[str, Any] | None:
        decoder = _SseDecoder()
        async for chunk in response.aiter_bytes():
            state.total_bytes += len(chunk)
            if state.total_bytes > self.target.max_response_bytes:
                raise ValueError("MCP response exceeds size limit")
            for event in decoder.feed(chunk):
                if event.event_id is not None:
                    state.last_event_id = event.event_id or None
                if not event.data:
                    continue
                obj = json.loads(event.data)
                if isinstance(obj, dict) and type(obj.get("id")) is int and obj["id"] == expected:
                    return self._validate_rpc(obj, expected)
        return None

    async def _post_rpc(self, payload: dict[str, Any]) -> dict[str, Any]:
        assert self._client is not None
        if len(json.dumps(payload).encode("utf-8")) > self.target.max_response_bytes:
            raise ValueError("MCP request exceeds size limit")
        expected = payload.get("id")
        state = _ResumeState()
        async with self._client.stream("POST", self.http_url, json=payload) as response:
            if (
                self._transport is None
                and payload.get("method") == "initialize"
                and not self._session_id
                and response.status_code in {404, 405}
            ):
                raise _LegacyTransportRequired()
            self._check_response(response)
            if payload.get("method") == "initialize" and (
                session := response.headers.get("Mcp-Session-Id")
            ):
                if len(session) > 256 or not all(33 <= ord(char) <= 126 for char in session):
                    raise ValueError("Invalid MCP session identifier")
                self._session_id = session
                self._client.headers["Mcp-Session-Id"] = session
            if expected is None:
                if response.status_code != 202:
                    raise ValueError("MCP notification was not accepted")
                return {}
            self._transport = "modern"
            content_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
            if content_type == "application/json":
                buffer = b""
                async for chunk in response.aiter_bytes():
                    state.total_bytes += len(chunk)
                    if state.total_bytes > self.target.max_response_bytes:
                        raise ValueError("MCP response exceeds size limit")
                    buffer += chunk
                return self._validate_rpc(json.loads(buffer), expected)
            if content_type != "text/event-stream":
                raise ValueError("Unsupported MCP response content type")
            try:
                result = await self._read_sse_reply(response, expected, state)
            except httpx.TransportError:
                result = None
            if result is not None:
                return result
        # Resume only the interrupted reply, on the exact selected endpoint.
        # The original POST is never repeated and all reads share one budget.
        for _ in range(2):
            if state.last_event_id is None:
                break
            async with self._client.stream(
                "GET",
                self.http_url,
                headers={"Accept": "text/event-stream", "Last-Event-ID": state.last_event_id},
            ) as resumed:
                self._check_response(resumed)
                if (
                    resumed.headers.get("content-type", "").split(";", 1)[0].strip().lower()
                    != "text/event-stream"
                ):
                    raise ValueError("MCP resumption requires an SSE response")
                try:
                    result = await self._read_sse_reply(resumed, expected, state)
                except httpx.TransportError:
                    result = None
                if result is not None:
                    return result
        raise ValueError("MCP stream ended without its matching response; POST was not replayed")

    def _legacy_message_endpoint(self, advertised: str) -> str:
        if (
            not advertised
            or len(advertised) > 4096
            or "\\" in advertised
            or any(ord(char) <= 32 or ord(char) == 127 for char in advertised)
        ):
            raise ValueError("Unsafe legacy MCP endpoint")
        advertised_path = urlparse(advertised).path
        self._validate_legacy_path(advertised_path)
        endpoint = urljoin(self.http_url, advertised)
        parsed = urlparse(endpoint)
        self._validate_legacy_path(parsed.path)
        if (
            parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or parsed.port == 0
            or canonical_origin(endpoint) != canonical_origin(self.http_url)
        ):
            raise ValueError(
                "Legacy MCP message endpoint must be a safe URI on the selected origin"
            )
        return endpoint

    @staticmethod
    def _validate_legacy_path(raw: str) -> None:
        path = unquote(raw)
        if (
            "\\" in path
            or "%" in path
            or any(ord(char) <= 32 or ord(char) == 127 for char in path)
            or any(segment in {".", ".."} for segment in path.split("/"))
            or "%2f" in raw.lower()
            or "%5c" in raw.lower()
        ):
            raise ValueError("Legacy MCP endpoint path contains unsafe escaping or traversal")

    async def _read_legacy_stream(self) -> None:
        assert self._client is not None and self._legacy_ready is not None
        failure: Exception = ConnectionError("Legacy MCP event stream closed")
        try:
            async with self._client.stream(
                "GET", self.http_url, headers={"Accept": "text/event-stream"}
            ) as response:
                self._check_response(response)
                if (
                    response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
                    != "text/event-stream"
                ):
                    raise ValueError("Legacy MCP discovery requires an SSE response")
                decoder = _SseDecoder()
                async for chunk in response.aiter_bytes():
                    self._legacy_bytes += len(chunk)
                    if self._legacy_bytes > self.target.max_response_bytes:
                        raise ValueError("Legacy MCP session exceeds size limit")
                    for event in decoder.feed(chunk):
                        if self._legacy_endpoint is None:
                            if event.event != "endpoint":
                                raise ValueError(
                                    "Legacy MCP first event must advertise its endpoint"
                                )
                            self._legacy_endpoint = self._legacy_message_endpoint(event.data)
                            self._legacy_ready.set_result(self._legacy_endpoint)
                            continue
                        if event.event == "endpoint":
                            raise ValueError("Legacy MCP endpoint cannot change during a session")
                        if event.event != "message" or not event.data:
                            continue
                        obj = json.loads(event.data)
                        if not isinstance(obj, dict) or obj.get("jsonrpc") != "2.0":
                            raise ValueError("Invalid legacy MCP JSON-RPC message")
                        rid = obj.get("id")
                        if type(rid) is int and rid in self._legacy_pending and "method" not in obj:
                            future = self._legacy_pending[rid]
                            if not future.done():
                                try:
                                    future.set_result(self._validate_rpc(obj, rid))
                                except ValueError as exc:
                                    future.set_exception(exc)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            failure = exc
        finally:
            if not self._legacy_ready.done():
                self._legacy_ready.set_exception(failure)
            for future in self._legacy_pending.values():
                if not future.done():
                    future.set_exception(failure)

    async def _start_legacy(self) -> None:
        self._transport = "legacy"
        self._legacy_ready = asyncio.get_running_loop().create_future()
        self._legacy_reader = asyncio.create_task(self._read_legacy_stream())
        await self._legacy_ready

    async def _legacy_post(self, payload: dict[str, Any]) -> None:
        assert self._client is not None and self._legacy_endpoint is not None
        if len(json.dumps(payload).encode("utf-8")) > self.target.max_response_bytes:
            raise ValueError("MCP request exceeds size limit")
        async with self._client.stream("POST", self._legacy_endpoint, json=payload) as response:
            self._check_response(response)
            if response.status_code not in {200, 202, 204}:
                raise ValueError("Legacy MCP message was not accepted")
            total = 0
            async for chunk in response.aiter_bytes():
                total += len(chunk)
                if total > self.target.max_response_bytes:
                    raise ValueError("Legacy MCP acceptance exceeds size limit")

    async def _legacy_rpc(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self._legacy_reader is None or self._legacy_reader.done():
            raise ConnectionError("Legacy MCP event stream is unavailable")
        if len(self._legacy_pending) >= 16:
            raise ValueError("Legacy MCP pending request limit reached")
        rid = payload["id"]
        future = asyncio.get_running_loop().create_future()
        self._legacy_pending[rid] = future
        try:
            await self._legacy_post(payload)
            return await future
        finally:
            self._legacy_pending.pop(rid, None)
            if not future.done():
                future.cancel()
            elif not future.cancelled():
                future.exception()  # Consume errors even if the POST itself failed.

    @staticmethod
    def _validate_rpc(obj: Any, expected: int) -> dict[str, Any]:
        if (
            not isinstance(obj, dict)
            or obj.get("jsonrpc") != "2.0"
            or type(obj.get("id")) is not int
            or obj["id"] != expected
            or "method" in obj
            or "error" in obj
            or "result" not in obj
        ):
            raise ValueError("Invalid or failed MCP response")
        return obj

    async def _rpc(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        async with self._lock, asyncio.timeout(self.target.timeout):
            self._rpc_id += 1
            payload = _jsonrpc_request(self._rpc_id, method, params)
            if self._transport == "legacy":
                return await self._legacy_rpc(payload)
            try:
                return await self._post_rpc(payload)
            except _LegacyTransportRequired:
                await self._start_legacy()
                return await self._legacy_rpc(payload)

    async def _notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        payload: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            payload["params"] = params
        async with self._lock, asyncio.timeout(self.target.timeout):
            if self._transport == "legacy":
                await self._legacy_post(payload)
            else:
                await self._post_rpc(payload)

    async def send_message(
        self, message: str, extra_body: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        if self._client is None:
            raise RuntimeError("MCP SSE connector not initialised.")
        try:
            return await self._probe_message(message, extra_body)
        except Exception as e:  # noqa: BLE001
            if self._session_expired:
                self._session_expired = False
                # Reestablish the session without replaying the failed tool call.
                try:
                    await asyncio.wait_for(self._handshake(), timeout=self.target.timeout)
                except Exception:
                    await self.__aexit__()
                return {
                    "error": "MCP session expired; the failed request was not replayed",
                    "status_code": 0,
                }
            logger.error("MCP HTTP call failed: {}", type(e).__name__)
            return {"error": "MCP HTTP request failed", "status_code": 0}

    async def send_conversation(self, messages: list[dict[str, str]]) -> dict[str, Any]:
        return await self.send_message(flatten_conversation(messages))
