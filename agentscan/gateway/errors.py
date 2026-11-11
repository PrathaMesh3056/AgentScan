"""Stable error representation shared by the HTTP and MCP adapters."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agentscan.gateway.models import ErrorCode


@dataclass(frozen=True, slots=True)
class GatewayError(Exception):
    code: ErrorCode
    message: str = "Gateway request failed"
    http_status: int = 400
    jsonrpc_code: int = -32000

    def as_jsonrpc_data(self) -> dict[str, str]:
        return {"agentscan_code": self.code.value}


HTTP_STATUS: dict[ErrorCode, int] = {
    ErrorCode.IDENTITY_MISSING: 401,
    ErrorCode.IDENTITY_MISMATCH: 403,
    ErrorCode.UNSUPPORTED_PROTOCOL_VERSION: 400,
    ErrorCode.GATEWAY_UNAVAILABLE: 503,
}


def http_error(
    code: ErrorCode, message: str = "Gateway request failed"
) -> tuple[int, dict[str, str]]:
    """Return a stable, secret-free HTTP error response."""
    return HTTP_STATUS.get(code, 400), {"agentscan_code": code.value, "message": message}


def jsonrpc_error(code: ErrorCode, message: str = "Gateway request failed") -> dict[str, Any]:
    return {"code": -32000, "message": message, "data": {"agentscan_code": code.value}}


def tool_error_result(code: ErrorCode, message: str = "Tool request failed") -> Any:
    """Build the Phase 5-compatible isError tool result without leaking details."""
    from mcp.types import CallToolResult, TextContent

    return CallToolResult(
        content=[TextContent(type="text", text=f"{code.value}: {message}")], isError=True
    )
