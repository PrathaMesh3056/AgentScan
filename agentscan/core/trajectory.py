# agentscan/core/trajectory.py
#
# Always-on per-turn trajectory recorder for SSP classification.
# Unlike TrafficRecorder (opt-in via --verbose), this runs on every scan.

from __future__ import annotations

from typing import Any

from agentscan.core.context import ContextLocal
from agentscan.core.models import TurnRecord
from agentscan.core.trace import extract_reply_text, redact_sensitive_data


def extract_tool_names(response: dict[str, Any]) -> list[str]:
    """Extract normalized tool/function names from common response shapes."""
    tool_data: Any | None = None
    if "tool_calls" in response:
        tool_data = response["tool_calls"]
    elif "function_call" in response:
        tool_data = response["function_call"]
    else:
        choices = response.get("choices")
        if isinstance(choices, list) and choices and isinstance(choices[0], dict):
            message = choices[0].get("message", {})
            if not isinstance(message, dict):
                return []
            if "tool_calls" in message:
                tool_data = message["tool_calls"]
            elif "function_call" in message:
                tool_data = message["function_call"]

    if tool_data is None:
        return []

    items: list[Any]
    if isinstance(tool_data, dict):
        items = [tool_data]
    elif isinstance(tool_data, list):
        items = tool_data
    else:
        return []

    names: list[str] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        fn = item.get("function")
        if isinstance(fn, dict) and fn.get("name"):
            names.append(str(fn["name"]))
        elif item.get("name"):
            names.append(str(item["name"]))
    return names


class TrajectoryRecorder:
    """Process-wide singleton. Always records — no enabled flag."""

    def __init__(self) -> None:
        self._turns: list[TurnRecord] = []

    def reset(self) -> None:
        self._turns.clear()

    def record(self, payload: str, response: dict[str, Any], redact: bool = True) -> None:
        turn = len(self._turns) + 1
        safe_payload = redact_sensitive_data(payload) if redact else payload
        reply = extract_reply_text(response)
        safe_response = redact_sensitive_data(reply) if redact else reply
        self._turns.append(
            TurnRecord(
                turn=turn,
                payload=safe_payload,
                response=safe_response,
                tool_calls=extract_tool_names(response),
            )
        )

    def turns(self) -> list[TurnRecord]:
        return list(self._turns)


trajectory_recorder = ContextLocal("trajectory", TrajectoryRecorder)
