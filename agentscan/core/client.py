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
import contextvars
from typing import Any

from agentscan.core.connectors import Connector, select_connector
from agentscan.core.models import Target
from agentscan.core.trace import recorder
from agentscan.core.trajectory import trajectory_recorder

_GLOBAL_SEMAPHORE: contextvars.ContextVar[asyncio.Semaphore | None] = contextvars.ContextVar(
    "_GLOBAL_SEMAPHORE", default=None
)


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

    async def __aenter__(self) -> AgentScanClient:
        await self._connector.__aenter__()
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self._connector.__aexit__(*exc)

    @classmethod
    def from_target(cls, target: Target) -> AgentScanClient:
        """Factory method to construct an AgentScanClient from a Target."""
        client = cls(target)
        client._auto_init = True
        return client

    async def open(self) -> AgentScanClient:
        """Explicitly open the underlying connector."""
        await self._connector.__aenter__()
        return self

    async def close(self) -> None:
        """Explicitly close the underlying connector."""
        await self._connector.__aexit__(None, None, None)

    async def _ensure_connected(self) -> None:
        """Lazily initialize connector only if created via from_target."""
        if self._auto_init and getattr(self._connector, "_client", None) is None:
            await self._connector.__aenter__()

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

        trajectory_recorder.record(message, resp)
        if recorder.enabled:
            recorder.record("message", message, resp)
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
        trajectory_recorder.record(payload, resp)
        if recorder.enabled:
            rendered = " || ".join(f"{m.get('role')}: {m.get('content', '')}" for m in messages)
            recorder.record("conversation", rendered, resp)
        return resp
