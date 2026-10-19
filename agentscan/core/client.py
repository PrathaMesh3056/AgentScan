# agentscan/core/client.py
#
# The single client every attack module uses to reach a target.
#
# It is now a thin FACADE over pluggable transport connectors (see connectors.py):
#   - default            → HttpJsonConnector       (POST {"message": ...} to target.url)
#   - request_template   → RequestTemplateConnector (replay a captured cURL/HAR request)
#
# The public API is unchanged, so every attack module works over EITHER transport
# without any change:
#
#     async with AgentScanClient(target) as client:
#         response = await client.send_message("your payload here")
#         text = response.get("response", "")

from __future__ import annotations

import asyncio
import contextlib
import contextvars
import hashlib
import json
from typing import Any

from agentscan.core.connectors import Connector, select_connector
from agentscan.core.context import active_context
from agentscan.core.models import Target
from agentscan.core.outcomes import TargetRequestError, record_execution_error
from agentscan.core.trace import recorder
from agentscan.core.trajectory import trajectory_recorder


def _validate_response(resp: dict[str, Any]) -> None:
    status = resp.get("status_code", 200)
    from agentscan.telemetry.otel import record_connector_request

    with contextlib.suppress(Exception):
        record_connector_request(status if isinstance(status, int) else 0)
    if resp.get("error") or (isinstance(status, int) and (status == 0 or status >= 400)):
        # Arbitrary returned error bodies can contain credentials or private
        # target data. Do not promote them into logs, module reasons or raises.
        if type(status) is int and 400 <= status <= 599:
            reason = f"Target returned HTTP {status}"
        elif status == 0 and resp.get("error") == "Target or redirect host is not enrolled":
            reason = "Target or redirect host is not enrolled"
        elif status == 0:
            reason = "Connection failed before a valid target response"
        else:
            reason = "Target reported an error response"
        record_execution_error(reason)
        raise TargetRequestError(reason)


_GLOBAL_SEMAPHORE: contextvars.ContextVar[asyncio.Semaphore | None] = contextvars.ContextVar(
    "_GLOBAL_SEMAPHORE", default=None
)


def consume_target_request() -> None:
    context = active_context.get()
    if context is not None:
        if context.request_budget is not None and context.target_requests >= context.request_budget:
            record_execution_error("Target request budget exhausted.")
            raise TargetRequestError("Target request budget exhausted.")
        context.target_requests += 1


def set_global_concurrency_limit(limit: int | None) -> None:
    """Set or clear a global concurrency limiter across all AgentScanClient requests."""
    sem = asyncio.Semaphore(limit) if limit and limit > 0 else None
    _GLOBAL_SEMAPHORE.set(sem)


class AgentScanClient:
    """
    Facade that selects a transport connector from the target and delegates to it.

    The connector is chosen once at construction: if `target.request_template` is
    set, a captured request is replayed; otherwise the default JSON POST is used.
    """

    def __init__(self, target: Target) -> None:
        self.target = target
        self._connector: Connector = select_connector(target)
        self._auto_init = False
        self._connected = False
        self._connect_lock = asyncio.Lock()

    async def __aenter__(self) -> AgentScanClient:
        await self._connector.__aenter__()
        self._connected = True
        return self

    async def __aexit__(self, *exc: Any) -> None:
        try:
            await self._connector.__aexit__(*exc)
        finally:
            self._connected = False

    @classmethod
    def from_target(cls, target: Target) -> AgentScanClient:
        """Factory method to construct an AgentScanClient from a Target."""
        client = cls(target)
        client._auto_init = True
        return client

    async def open(self) -> AgentScanClient:
        """Explicitly open the underlying connector."""
        await self._connector.__aenter__()
        self._connected = True
        return self

    async def close(self) -> None:
        """Explicitly close the underlying connector."""
        try:
            await self._connector.__aexit__(None, None, None)
        finally:
            self._connected = False

    async def _ensure_connected(self) -> None:
        """Lazily initialize connector only if created via from_target."""
        if self._auto_init and not self._connected:
            async with self._connect_lock:
                if not self._connected:
                    await self.open()

    async def send_message(
        self, message: str, extra_body: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Send a single message/payload to the target. Returns a response dict."""
        await self._ensure_connected()
        sem = _GLOBAL_SEMAPHORE.get()
        if sem is not None:
            async with sem:
                resp = await self._connector.send_message(message, extra_body)
        else:
            resp = await self._connector.send_message(message, extra_body)

        self._record_exchange("message", message, resp)
        _validate_response(resp)
        return resp

    def _record_exchange(self, kind: str, payload: str, response: dict[str, Any]) -> None:
        if self.target.factuality_baseline is not None:
            # Approved facts and unexpected target answers may be sensitive.
            # This profile retains digests even when ordinary redaction is off.
            if recorder.enabled:
                request_bytes = payload.encode("utf-8", errors="replace")
                try:
                    response_bytes = json.dumps(
                        response, sort_keys=True, ensure_ascii=True, allow_nan=False
                    ).encode("utf-8")
                    reply = (
                        f"[factuality response sha256={hashlib.sha256(response_bytes).hexdigest()}; "
                        f"bytes={len(response_bytes)}]"
                    )
                except (TypeError, ValueError, RecursionError, UnicodeError):
                    reply = "[factuality response omitted: no serializable digest]"
                recorder.record(
                    kind,
                    f"[factuality request sha256={hashlib.sha256(request_bytes).hexdigest()}; "
                    f"bytes={len(request_bytes)}]",
                    {"response": reply},
                    redact=False,
                )
            return
        trajectory_recorder.record(payload, response)
        if recorder.enabled:
            recorder.record(kind, payload, response)

    async def inspect_mcp_tools(self) -> list[dict[str, Any]] | None:
        """Inspect the selected connector's snapshot without calling any tool.

        Discovery is not a conversation and raw metadata is not added to traces.
        This does not discover another endpoint or refresh a live catalog.
        """
        await self._ensure_connected()
        return await self._connector.get_mcp_tools()

    async def send_indirect_document(
        self, task: str, document: str, probe_id: str, source_id: str
    ) -> dict[str, Any]:
        """Use explicit ingestion capability; never synthesize chat/tool history."""
        await self._ensure_connected()
        sem = _GLOBAL_SEMAPHORE.get()
        if sem is not None:
            async with sem:
                resp = await self._connector.send_indirect_document(
                    task, document, probe_id, source_id
                )
        else:
            resp = await self._connector.send_indirect_document(task, document, probe_id, source_id)
        if self.target.factuality_baseline is not None:
            self._record_exchange("indirect_document", task + "\n" + document, resp)
        else:
            trajectory_recorder.record(task, resp)
            if recorder.enabled:
                recorder.record(
                    "indirect_document", task + "\n[untrusted document]\n" + document, resp
                )
        _validate_response(resp)
        return resp

    async def send_conversation(self, messages: list[dict[str, str]]) -> dict[str, Any]:
        """Send a multi-turn conversation history to the target."""
        await self._ensure_connected()
        sem = _GLOBAL_SEMAPHORE.get()
        if sem is not None:
            async with sem:
                resp = await self._connector.send_conversation(messages)
        else:
            resp = await self._connector.send_conversation(messages)

        payload = next(
            (m.get("content", "") for m in reversed(messages) if m.get("role") == "user"),
            " || ".join(f"{m.get('role')}: {m.get('content', '')}" for m in messages),
        )
        if self.target.factuality_baseline is not None:
            rendered = " || ".join(f"{m.get('role')}: {m.get('content', '')}" for m in messages)
            self._record_exchange("conversation", rendered, resp)
        else:
            trajectory_recorder.record(payload, resp)
            if recorder.enabled:
                rendered = " || ".join(f"{m.get('role')}: {m.get('content', '')}" for m in messages)
                recorder.record("conversation", rendered, resp)
        _validate_response(resp)
        return resp
