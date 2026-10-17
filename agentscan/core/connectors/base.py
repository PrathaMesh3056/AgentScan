# agentscan/core/connectors/base.py
#
# Base Connector interface, retry constants, and payload parsing helpers.

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Any

import httpx

# ── Retry configuration (shared) ──────────────────────────────────────────────

DEFAULT_RETRIES = 2
RETRY_BACKOFF_SECONDS = 1.0  # doubles on each retry: 1s, 2s
RETRY_ON_STATUS = {429, 502, 503, 504}


# ── Dotted-path helpers (for JSON request/response templating) ────────────────


def set_by_path(obj: Any, path: str, value: Any) -> None:
    """
    Set a value inside a nested dict/list using a dotted path.
    Supports list indices (including negative): "messages.-1.content".
    """
    keys = path.split(".")
    cur = obj
    for k in keys[:-1]:
        cur = cur[int(k)] if isinstance(cur, list) else cur[k]
    last = keys[-1]
    if isinstance(cur, list):
        cur[int(last)] = value
    else:
        cur[last] = value


def get_by_path(obj: Any, path: str) -> Any:
    """Read a value from a nested dict/list by dotted path, or None if absent."""
    cur = obj
    try:
        for k in path.split("."):
            cur = cur[int(k)] if isinstance(cur, list) else cur[k]
    except (KeyError, IndexError, TypeError, ValueError):
        return None
    return cur


def flatten_conversation(messages: list[dict[str, str]]) -> str:
    """
    Render a multi-turn history into a single prompt string.

    Needed because most real agent endpoints are single-message and stateless
    (they take {"message": ...} with no server-side memory), so the only way to
    convey prior turns is to inline them into one message.
    """
    return "\n".join(f"[{m.get('role', 'user')}]: {m.get('content', '')}" for m in messages)


# ── SSE / streaming response parsing ──────────────────────────────────────────

_SSE_TEXT_KEYS = ("content", "text", "delta", "token", "reply", "message", "response")


def parse_sse(text: str) -> str:
    """
    Reassemble the full reply from a Server-Sent Events stream.

    Handles the common chat shape `data: {"content": "...", "done": false}` by
    concatenating the text field of each chunk; ignores `[DONE]` sentinels.
    """
    parts: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line.startswith("data:"):
            continue
        data = line[len("data:") :].strip()
        if not data or data == "[DONE]":
            continue
        try:
            obj = json.loads(data)
        except json.JSONDecodeError:
            parts.append(data)
            continue
        if isinstance(obj, str):
            parts.append(obj)
        elif isinstance(obj, dict):
            choices = obj.get("choices")
            if isinstance(choices, list) and choices:
                delta = choices[0].get("delta", {}) if isinstance(choices[0], dict) else {}
                content = delta.get("content") if isinstance(delta, dict) else None
                if isinstance(content, str):
                    parts.append(content)
                    continue
            for k in _SSE_TEXT_KEYS:
                v = obj.get(k)
                if isinstance(v, str):
                    parts.append(v)
                    break
    return "".join(parts)


def parse_response(response: httpx.Response) -> dict[str, Any]:
    """
    Turn an httpx response into a dict the attack modules can read.

    - text/event-stream (or a body that looks like SSE) → reassemble the stream
      and expose it under "response" so streamed bots aren't false-negatives.
    - JSON → return as-is.
    - anything else → {"raw": <text>}.
    """
    ctype = response.headers.get("content-type", "")
    if response.status_code >= 400:
        return {
            "error": f"Target returned HTTP {response.status_code}",
            "status_code": response.status_code,
            "raw": response.text,
        }
    text = response.text
    if "text/event-stream" in ctype or text.lstrip().startswith("data:"):
        return {"response": parse_sse(text), "raw": text}
    try:
        result = response.json()
        if isinstance(result, dict):
            return result
        return {
            "error": "Target JSON response must be an object",
            "status_code": response.status_code,
        }
    except Exception:
        return {"raw": text, "status_code": response.status_code}


# ── Connector interface ───────────────────────────────────────────────────────


class Connector(ABC):
    """
    Transport contract every connector implements. Attack modules depend only on
    this surface, so swapping the transport never touches a module.
    """

    async def __aenter__(self) -> Connector:
        return self

    async def __aexit__(self, *exc: Any) -> None:
        return None

    async def get_mcp_tools(self) -> list[dict[str, Any]] | None:
        """Completed MCP handshake snapshot, or None when unsupported/unavailable."""
        return None

    @property
    def supports_indirect_document(self) -> bool:
        """Explicit capability; ordinary chat/history transport is insufficient."""
        return False

    async def send_indirect_document(
        self, task: str, document: str, probe_id: str, source_id: str
    ) -> dict[str, Any]:
        from agentscan.core.outcomes import ModuleUnavailableError

        raise ModuleUnavailableError(
            "This connector has no target-owned document ingestion adapter."
        )

    @abstractmethod
    async def send_message(
        self, message: str, extra_body: dict[str, Any] | None = None
    ) -> dict[str, Any]: ...

    @abstractmethod
    async def send_conversation(self, messages: list[dict[str, str]]) -> dict[str, Any]: ...
