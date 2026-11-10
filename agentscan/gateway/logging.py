"""Structured stdlib logging skeleton with configurable canary redaction."""

from __future__ import annotations

import json
import logging
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any


class RedactionFilter(logging.Filter):
    def __init__(self, canaries: Iterable[str] = ()) -> None:
        super().__init__()
        self._canaries = tuple(value for value in canaries if value)

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        for canary in self._canaries:
            message = message.replace(canary, "[REDACTED]")
        record.msg = message
        record.args = ()
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        event: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "event": record.getMessage(),
        }
        for key in (
            "request_id",
            "trace_id",
            "tool",
            "decision",
            "reason",
            "latency_ms",
            "phase",
            "error_code",
        ):
            value = getattr(record, key, None)
            if value is not None:
                event[key] = value
        return json.dumps(event, separators=(",", ":"), ensure_ascii=False)
