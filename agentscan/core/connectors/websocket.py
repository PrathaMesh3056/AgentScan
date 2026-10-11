# agentscan/core/connectors/websocket.py
#
# WebSocket connector for streaming bidirectional agent sessions.

from __future__ import annotations

import asyncio
import json
from typing import Any

from loguru import logger

from agentscan.core.connectors.base import Connector, flatten_conversation
from agentscan.core.models import Target


def _normalise_ws_frame(raw: Any) -> dict[str, Any]:
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")
    if isinstance(raw, str):
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError:
            return {"response": raw, "raw": raw}
        if isinstance(obj, dict):
            if "response" in obj:
                return obj
            for key in ("text", "message", "content", "reply"):
                if isinstance(obj.get(key), str):
                    return {"response": obj[key], "raw": obj}
            return {"response": json.dumps(obj), "raw": obj}
        return {"response": str(obj), "raw": obj}
    return {"response": str(raw), "raw": raw}


class WebSocketConnector(Connector):
    """Persistent WebSocket send/recv mapped to {response: ...}."""

    def __init__(self, target: Target) -> None:
        self.target = target
        self._ws: Any = None

    async def __aenter__(self) -> WebSocketConnector:
        try:
            import websockets
        except ImportError as e:
            raise RuntimeError("WebSocket connector requires the 'websockets' package.") from e
        extra: dict[str, Any] = {}
        if self.target.extra_headers:
            extra["additional_headers"] = self.target.extra_headers
        self._ws = await websockets.connect(
            self.target.url, open_timeout=self.target.timeout, **extra
        )
        return self

    async def __aexit__(self, *exc: Any) -> None:
        if self._ws is not None:
            await self._ws.close()
            self._ws = None

    async def send_message(
        self, message: str, extra_body: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        if self._ws is None:
            raise RuntimeError("WebSocket connector not initialised.")
        body: dict[str, Any] = {"message": message}
        if extra_body:
            body.update(extra_body)
        try:
            await self._ws.send(json.dumps(body))
            raw = await asyncio.wait_for(self._ws.recv(), timeout=self.target.timeout)
        except Exception as e:  # noqa: BLE001
            logger.error(f"WebSocket send/recv failed: {e}")
            return {"error": str(e), "status_code": 0}
        return _normalise_ws_frame(raw)

    async def send_conversation(self, messages: list[dict[str, str]]) -> dict[str, Any]:
        return await self.send_message(flatten_conversation(messages))
