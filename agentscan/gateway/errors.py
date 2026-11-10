"""Stable error representation shared by the HTTP and MCP adapters."""

from __future__ import annotations

from dataclasses import dataclass

from agentscan.gateway.models import ErrorCode


@dataclass(frozen=True, slots=True)
class GatewayError(Exception):
    code: ErrorCode
    message: str = "Gateway request failed"
    http_status: int = 400
    jsonrpc_code: int = -32000

    def as_jsonrpc_data(self) -> dict[str, str]:
        return {"agentscan_code": self.code.value}
