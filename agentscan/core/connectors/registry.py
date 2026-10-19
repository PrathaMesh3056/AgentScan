# agentscan/core/connectors/registry.py
#
# In-process mock connector, scoped connector overrides, and transport dispatcher.

from __future__ import annotations

import contextlib
import contextvars
from collections.abc import Callable
from typing import Any
from urllib.parse import urlparse

from agentscan.core.connectors.base import Connector, flatten_conversation
from agentscan.core.connectors.browser import BrowserConnector
from agentscan.core.connectors.http import HttpJsonConnector, RequestTemplateConnector
from agentscan.core.connectors.mcp import McpSseConnector, McpStdioConnector
from agentscan.core.connectors.websocket import WebSocketConnector
from agentscan.core.models import Target
from agentscan.core.outcomes import ModuleUnavailableError


class CallableConnector(Connector):
    """Talks to an in-process agent function `(message) -> reply`. No network."""

    def __init__(self, agent: Callable[[str], str]) -> None:
        self._agent = agent

    async def send_message(
        self, message: str, extra_body: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        return {"response": self._agent(message)}

    async def send_conversation(self, messages: list[dict[str, str]]) -> dict[str, Any]:
        return await self.send_message(flatten_conversation(messages))


# A scoped override so a whole scan can be routed to an in-process agent (used by
# the benchmark). Set via use_connector(); select_connector() honours it.
_forced_connector_var: contextvars.ContextVar[Connector | None] = contextvars.ContextVar(
    "_forced_connector", default=None
)


@contextlib.contextmanager
def use_connector(connector: Connector) -> Any:
    """Force every connector for the duration of the block (benchmark/testing)."""
    token = _forced_connector_var.set(connector)
    try:
        yield
    finally:
        _forced_connector_var.reset(token)


def select_connector(target: Target) -> Connector:
    """
    Pick the transport for a target:
    forced override → browser widget → captured request → ws/mcp schemes → HTTP JSON.
    """
    forced = _forced_connector_var.get()
    if forced is not None:
        if target.factuality_baseline is not None:
            raise ModuleUnavailableError(
                "Approved-answer profiles do not permit connector overrides."
            )
        return forced
    if target.browser is not None:
        return BrowserConnector(target)
    if target.request_template is not None:
        return RequestTemplateConnector(target)
    scheme = urlparse(target.url).scheme.lower()
    if scheme in ("ws", "wss"):
        return WebSocketConnector(target)
    if scheme in ("mcp", "mcp+stdio"):
        return McpStdioConnector(target)
    if scheme in ("mcp+sse", "mcp+sses"):
        return McpSseConnector(target)
    return HttpJsonConnector(target)
