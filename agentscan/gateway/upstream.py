"""Authenticated MCP Streamable HTTP client for the runtime gateway.

The client owns one long-lived MCP session per upstream server. It never
forwards the agent token upstream: it authenticates with the gateway credential
plus the configured tenant header. Every failure is mapped to a bounded,
sanitized exception that never carries a URL, credential, or exception detail.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
from collections.abc import Awaitable, Mapping
from contextlib import AsyncExitStack
from dataclasses import dataclass
from datetime import timedelta
from types import TracebackType
from typing import Any, Literal, TypeVar
from urllib.parse import urlsplit

import httpx
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.exceptions import McpError
from mcp.types import CallToolResult, TextContent, Tool

from agentscan.gateway.canonical import loads_json

_HASH_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_MAX_LIST_PAGES = 100
_META_KEY_HASH = "agentscan.key_hash"
_META_REQUEST_HASH = "agentscan.request_hash"

_T = TypeVar("_T")


class UpstreamError(RuntimeError):
    """Sanitized upstream failure; messages never contain URLs or credentials."""

    def __init__(self, message: str = "upstream error", *, may_have_sent: bool = False) -> None:
        super().__init__(message)
        self.may_have_sent = may_have_sent


class UpstreamUnavailable(UpstreamError):
    def __init__(
        self, message: str = "upstream unavailable", *, may_have_sent: bool = False
    ) -> None:
        super().__init__(message, may_have_sent=may_have_sent)


class UpstreamTimeout(UpstreamError):
    def __init__(
        self, message: str = "upstream request timed out", *, may_have_sent: bool = False
    ) -> None:
        super().__init__(message, may_have_sent=may_have_sent)


class UpstreamProtocolError(UpstreamError):
    def __init__(
        self, message: str = "upstream protocol error", *, may_have_sent: bool = False
    ) -> None:
        super().__init__(message, may_have_sent=may_have_sent)


class UpstreamAuthenticationError(UpstreamUnavailable):
    def __init__(
        self,
        message: str = "upstream rejected the gateway credential",
        *,
        may_have_sent: bool = False,
    ) -> None:
        super().__init__(message, may_have_sent=may_have_sent)


@dataclass(frozen=True, slots=True)
class UpstreamEffect:
    """Validated confirmation from an upstream idempotent status operation."""

    status: Literal["no_effect", "applied", "unknown"]
    key_hash: str
    request_hash: str
    confirmation_id: str
    observed_at: str


def _is_loopback_host(hostname: str) -> bool:
    name = hostname.strip("[]").lower()
    if name == "localhost":
        return True
    try:
        return ipaddress.ip_address(name).is_loopback
    except ValueError:
        return False


def _validate_url(url: str) -> None:
    if not isinstance(url, str) or not url:
        raise ValueError("invalid upstream url")
    try:
        parts = urlsplit(url)
    except ValueError as exc:
        raise ValueError("invalid upstream url") from exc
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("invalid upstream url")
    if parts.username is not None or parts.password is not None:
        raise ValueError("invalid upstream url")
    if parts.query or parts.fragment:
        raise ValueError("invalid upstream url")
    if parts.scheme == "http" and not _is_loopback_host(parts.hostname):
        raise ValueError("invalid upstream url")


class UpstreamClient:
    """Long-lived authenticated MCP Streamable HTTP session to one upstream.

    The MCP transport owns anyio task groups whose cancel scopes cancel their
    parent task when a connection dies.  This client therefore runs the whole
    transport stack in a dedicated supervisor task: an upstream outage stops
    that task (and flips ``alive`` to ``False``) but can never cancel the ASGI
    server task that is serving agent requests.
    """

    def __init__(
        self,
        *,
        url: str,
        server_id: str,
        credential: str,
        tenant: str,
        timeout_seconds: float = 5.0,
    ) -> None:
        _validate_url(url)
        if not isinstance(server_id, str) or not server_id:
            raise ValueError("invalid upstream server id")
        if not isinstance(credential, str) or not credential:
            raise ValueError("invalid upstream credential")
        if not isinstance(tenant, str) or not tenant:
            raise ValueError("invalid upstream tenant")
        if (
            not isinstance(timeout_seconds, (int, float))
            or isinstance(timeout_seconds, bool)
            or timeout_seconds <= 0
        ):
            raise ValueError("invalid upstream timeout")
        self._url = url
        self._server_id = server_id
        self._credential = credential
        self._tenant = tenant
        self._timeout_seconds = float(timeout_seconds)
        self._lock = asyncio.Lock()
        self._supervisor: asyncio.Task[None] | None = None
        self._session: ClientSession | None = None
        self._ready: asyncio.Future[None] | None = None
        self._stop: asyncio.Event | None = None
        self._lost = asyncio.Event()
        self._closing = False
        self._failure: UpstreamError | None = None

    @property
    def server_id(self) -> str:
        return self._server_id

    @property
    def started(self) -> bool:
        return self.alive

    @property
    def alive(self) -> bool:
        """True while the upstream transport is connected and usable."""
        return (
            self._session is not None and not self._lost.is_set() and not self._closing
        )

    def _require_started(self) -> ClientSession:
        session = self._session
        if session is None or self._lost.is_set() or self._closing:
            raise UpstreamUnavailable()
        return session

    async def __aenter__(self) -> UpstreamClient:
        await self.start()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc, traceback
        await self.aclose()

    async def start(self) -> None:
        """Open the long-lived MCP session; on failure close everything."""
        if self._closing:
            raise UpstreamUnavailable()
        if self._supervisor is not None:
            if self.alive:
                return
            raise UpstreamUnavailable() from self._failure
        # Probe before entering any MCP/anyio context. Entering the streamable
        # client starts task groups whose cancel scopes must stay in the
        # supervisor task; a post-timeout probe in a worker thread corrupts
        # them on Linux.
        probe = await asyncio.to_thread(self._probe_reachable, min(0.5, self._timeout_seconds))
        if probe is False:
            raise UpstreamUnavailable()
        self._lost.clear()
        self._stop = asyncio.Event()
        self._ready = asyncio.get_running_loop().create_future()
        self._supervisor = asyncio.create_task(
            self._supervise(), name=f"agentscan-upstream-{self._server_id}"
        )
        try:
            async with asyncio.timeout(self._timeout_seconds):
                await self._ready
        except TimeoutError:
            await self._terminate()
            raise UpstreamTimeout() from None
        except asyncio.CancelledError:
            await self._terminate()
            raise
        except UpstreamError:
            await self._terminate()
            raise
        except Exception:
            await self._terminate()
            raise UpstreamUnavailable() from None

    async def _supervise(self) -> None:
        """Own the MCP transport; contain its cancellation inside this task."""
        stack = AsyncExitStack()
        ready = self._ready
        failure: UpstreamError | None = None
        try:
            client = await stack.enter_async_context(
                httpx.AsyncClient(
                    headers={
                        "Authorization": f"Bearer {self._credential}",
                        "X-AgentScan-Tenant": self._tenant,
                    },
                    follow_redirects=False,
                    trust_env=False,
                    timeout=httpx.Timeout(self._timeout_seconds),
                )
            )
            read, write, _get_session_id = await stack.enter_async_context(
                streamable_http_client(self._url, http_client=client)
            )
            session = await stack.enter_async_context(ClientSession(read, write))
            try:
                async with asyncio.timeout(self._timeout_seconds):
                    await session.initialize()
            except TimeoutError:
                failure = UpstreamTimeout()
            else:
                self._session = session
                if ready is not None and not ready.done():
                    ready.set_result(None)
                stop = self._stop
                if stop is not None:
                    await stop.wait()
        except asyncio.CancelledError:
            # The MCP transport cancelled its parent task group because the
            # connection died, or aclose() stopped the supervisor. Record a
            # bounded failure; never let this cancellation reach the server.
            failure = UpstreamUnavailable()
        except UpstreamError as exc:
            failure = exc
        except Exception:
            failure = UpstreamUnavailable()
        finally:
            self._session = None
            self._lost.set()
            self._failure = failure
            if ready is not None and not ready.done():
                ready.set_exception(failure if failure is not None else UpstreamUnavailable())
            await self._close_stack(stack)

    @staticmethod
    async def _close_stack(stack: AsyncExitStack) -> None:
        """Close transport resources without letting teardown escape."""
        try:
            await stack.aclose()
        except asyncio.CancelledError:
            # The transport's own cancel scope is unwinding; the connection is
            # already gone, so there is nothing left to close.
            pass
        except Exception:
            # Teardown errors are already represented by the bounded failure.
            pass
        except BaseExceptionGroup:
            # anyio aggregates concurrent teardown failures in a group.
            pass

    async def _await_with_liveness(self, operation: Awaitable[_T], *, may_have_sent: bool) -> _T:
        """Await one MCP operation, failing fast when the transport is lost."""
        call = asyncio.ensure_future(operation)
        lost = asyncio.ensure_future(self._lost.wait())
        try:
            done, _pending = await asyncio.wait(
                {call, lost}, return_when=asyncio.FIRST_COMPLETED
            )
            if call in done:
                return call.result()
            raise UpstreamUnavailable(may_have_sent=may_have_sent)
        finally:
            for task in (call, lost):
                if not task.done():
                    task.cancel()
            for task in (call, lost):
                try:
                    await task
                except asyncio.CancelledError:
                    continue
                except Exception:
                    continue
                except BaseExceptionGroup:
                    continue

    async def _terminate(self) -> None:
        """Stop the supervisor task and wait for its transport cleanup."""
        supervisor = self._supervisor
        self._supervisor = None
        self._session = None
        stop, self._stop = self._stop, None
        ready, self._ready = self._ready, None
        if stop is not None:
            stop.set()
        if ready is not None and ready.done() and not ready.cancelled():
            # start() already observed the same failure; mark it retrieved.
            ready.exception()
        if supervisor is None:
            return
        try:
            await asyncio.wait_for(
                asyncio.shield(supervisor), timeout=max(1.0, self._timeout_seconds)
            )
        except TimeoutError:
            supervisor.cancel()
            await self._drain(supervisor)
        except asyncio.CancelledError:
            supervisor.cancel()
            await self._drain(supervisor)
        except Exception:
            pass
        except BaseExceptionGroup:
            pass

    @staticmethod
    async def _drain(task: asyncio.Task[None]) -> None:
        try:
            await task
        except asyncio.CancelledError:
            pass
        except Exception:
            pass
        except BaseExceptionGroup:
            pass

    def _probe_reachable(self, timeout_seconds: float) -> bool | None:
        """Quick TCP probe: True reachable, False refused immediately, None timed out."""
        parts = urlsplit(self._url)
        host = parts.hostname or ""
        fallback = 443 if parts.scheme == "https" else 80
        port = parts.port if parts.port is not None else fallback
        try:
            with socket.create_connection((host, port), timeout=timeout_seconds):
                return True
        except TimeoutError:
            return None
        except OSError:
            return False

    async def aclose(self) -> None:
        """Idempotent, best-effort shutdown; never raises."""
        self._closing = True
        self._lost.set()
        self._session = None
        await self._terminate()

    async def list_tools(self) -> tuple[Tool, ...]:
        """List every upstream tool, following cursors up to the page cap."""
        session = self._require_started()
        async with self._lock:
            tools: list[Tool] = []
            cursor: str | None = None
            seen: set[str] = set()
            for _ in range(_MAX_LIST_PAGES):
                try:
                    async with asyncio.timeout(self._timeout_seconds):
                        result = await self._await_with_liveness(
                            session.list_tools(cursor=cursor), may_have_sent=False
                        )
                except asyncio.CancelledError:
                    # Caller cancellation belongs to the request path; the
                    # runtime decides whether it is request-scoped or shutdown.
                    raise
                except TimeoutError as exc:
                    raise UpstreamTimeout() from exc
                except httpx.TimeoutException as exc:
                    raise UpstreamTimeout() from exc
                except McpError as exc:
                    raise UpstreamProtocolError() from exc
                except httpx.HTTPError as exc:
                    raise UpstreamUnavailable() from exc
                except OSError as exc:
                    raise UpstreamUnavailable() from exc
                except Exception as exc:
                    raise UpstreamUnavailable() from exc
                tools.extend(result.tools)
                next_cursor = result.nextCursor
                if next_cursor is None:
                    return tuple(tools)
                if next_cursor in seen:
                    raise UpstreamProtocolError()
                seen.add(next_cursor)
                cursor = next_cursor
        raise UpstreamProtocolError()

    async def call_tool(
        self,
        name: str,
        arguments: Mapping[str, Any],
        *,
        meta: Mapping[str, Any] | None = None,
        timeout_seconds: float | None = None,
    ) -> CallToolResult:
        """Forward one tool call; upstream tool errors are returned, not raised."""
        session = self._require_started()
        if not isinstance(name, str) or not name:
            raise ValueError("invalid tool name")
        deadline = self._timeout_seconds if timeout_seconds is None else float(timeout_seconds)
        payload = dict(arguments)
        request_meta = dict(meta) if meta else None
        async with self._lock:
            try:
                async with asyncio.timeout(deadline):
                    return await self._await_with_liveness(
                        session.call_tool(
                            name,
                            payload,
                            read_timeout_seconds=timedelta(seconds=deadline),
                            meta=request_meta,
                        ),
                        may_have_sent=True,
                    )
            except asyncio.CancelledError:
                # Caller cancellation belongs to the request path; the runtime
                # converts it to a stable result unless the server is stopping.
                raise
            except TimeoutError as exc:
                raise UpstreamTimeout(may_have_sent=True) from exc
            except httpx.TimeoutException as exc:
                raise UpstreamTimeout(may_have_sent=True) from exc
            except McpError as exc:
                # The MCP client raises its own 408 McpError when its read
                # timeout fires, so map it to a timeout rather than a protocol
                # failure. Which layer fires first is a scheduling race.
                if exc.error.code == httpx.codes.REQUEST_TIMEOUT:
                    raise UpstreamTimeout(may_have_sent=True) from exc
                raise UpstreamProtocolError(may_have_sent=True) from exc
            except httpx.ConnectError as exc:
                # The connection was never established, so nothing was sent.
                raise UpstreamUnavailable(may_have_sent=False) from exc
            except httpx.HTTPError as exc:
                raise UpstreamProtocolError(may_have_sent=True) from exc
            except OSError as exc:
                raise UpstreamUnavailable(may_have_sent=True) from exc
            except Exception as exc:
                raise UpstreamUnavailable(may_have_sent=True) from exc

    async def check_effect(
        self,
        operation: str,
        *,
        key_hash: str,
        request_hash: str,
    ) -> UpstreamEffect:
        """Query the upstream status operation for a prior idempotent effect."""
        if not isinstance(operation, str) or not operation:
            raise ValueError("invalid status operation")
        if not _HASH_PATTERN.fullmatch(key_hash) or not _HASH_PATTERN.fullmatch(request_hash):
            raise ValueError("invalid idempotency hash")
        result = await self.call_tool(
            operation,
            {"key_hash": key_hash, "request_hash": request_hash},
            meta={_META_KEY_HASH: key_hash, _META_REQUEST_HASH: request_hash},
        )
        if result.isError:
            raise UpstreamProtocolError()
        payload = self._effect_payload(result)
        if payload is None:
            raise UpstreamProtocolError()
        status = payload.get("status")
        if status not in ("no_effect", "applied", "unknown"):
            raise UpstreamProtocolError()
        returned_key = payload.get("key_hash")
        if not isinstance(returned_key, str) or returned_key != key_hash:
            raise UpstreamProtocolError()
        returned_request = payload.get("request_hash")
        if not isinstance(returned_request, str) or returned_request != request_hash:
            raise UpstreamProtocolError()
        confirmation_id = payload.get("confirmation_id")
        if not isinstance(confirmation_id, str) or not confirmation_id:
            raise UpstreamProtocolError()
        observed_at = payload.get("observed_at")
        if not isinstance(observed_at, str) or not observed_at:
            raise UpstreamProtocolError()
        return UpstreamEffect(
            status=status,  # type: ignore[arg-type]
            key_hash=returned_key,
            request_hash=returned_request,
            confirmation_id=confirmation_id,
            observed_at=observed_at,
        )

    def _effect_payload(self, result: CallToolResult) -> Mapping[str, Any] | None:
        structured = result.structuredContent
        if isinstance(structured, Mapping):
            return structured
        for item in result.content:
            if isinstance(item, TextContent):
                try:
                    parsed = loads_json(item.text)
                except (TypeError, ValueError):
                    return None
                return parsed if isinstance(parsed, Mapping) else None
        return None
