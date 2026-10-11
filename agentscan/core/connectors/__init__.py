# agentscan/core/connectors/__init__.py
#
# Transport connectors package — how AgentScan reaches target agents.
#
# Attack modules reach targets through a Connector selected by AgentScanClient.
# Chat methods are shared across transports. Boundary-specific methods require
# an explicit connector capability; unsupported boundaries have no chat fallback.
#
#   HttpJsonConnector        — the default: POST {"message": ...} to a documented endpoint.
#   RequestTemplateConnector — replay a captured request (cURL/HAR).
#   BrowserConnector         — drives a chat widget in a real browser via Playwright.
#   McpStdioConnector        — MCP over stdio JSON-RPC.
#   McpSseConnector          — MCP over HTTP/SSE.
#   WebSocketConnector       — bidirectional WebSocket session.
#   CallableConnector        — in-process agent function for testing/benchmarks.

from __future__ import annotations

from agentscan.core.connectors.base import (
    DEFAULT_RETRIES,
    RETRY_BACKOFF_SECONDS,
    RETRY_ON_STATUS,
    Connector,
    flatten_conversation,
    get_by_path,
    parse_response,
    parse_sse,
    set_by_path,
)
from agentscan.core.connectors.browser import (
    BrowserConnector,
    _BrowserSession,
    _launch_page,
    _session,
    browser_session_active,
    close_browser_session,
    open_browser_session,
)
from agentscan.core.connectors.http import (
    HttpJsonConnector,
    RequestTemplateConnector,
)
from agentscan.core.connectors.mcp import (
    McpSseConnector,
    McpStdioConnector,
    _jsonrpc_request,
    _mcp_text_from_result,
    _McpClientMixin,
    _parse_mcp_stdio_command,
    mcp_sse_http_url,
)
from agentscan.core.connectors.registry import (
    CallableConnector,
    _forced_connector_var,
    select_connector,
    use_connector,
)
from agentscan.core.connectors.websocket import (
    WebSocketConnector,
    _normalise_ws_frame,
)

__all__ = [
    "DEFAULT_RETRIES",
    "RETRY_BACKOFF_SECONDS",
    "RETRY_ON_STATUS",
    "BrowserConnector",
    "CallableConnector",
    "Connector",
    "HttpJsonConnector",
    "McpSseConnector",
    "McpStdioConnector",
    "RequestTemplateConnector",
    "WebSocketConnector",
    "_BrowserSession",
    "_McpClientMixin",
    "_forced_connector_var",
    "_jsonrpc_request",
    "_launch_page",
    "_mcp_text_from_result",
    "_normalise_ws_frame",
    "_parse_mcp_stdio_command",
    "_session",
    "browser_session_active",
    "close_browser_session",
    "flatten_conversation",
    "get_by_path",
    "mcp_sse_http_url",
    "open_browser_session",
    "parse_response",
    "parse_sse",
    "select_connector",
    "set_by_path",
    "use_connector",
]
