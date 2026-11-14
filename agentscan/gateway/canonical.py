"""Canonical JSON primitives used by policy and receipt signing."""

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any


def canonical_json(value: Any) -> bytes:
    """Encode JSON deterministically as UTF-8 and reject NaN/Infinity."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _unique_object(pairs: Iterable[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"invalid JSON number: {value}")


def loads_json(text: str | bytes) -> Any:
    """Parse JSON while rejecting duplicate keys and non-finite numbers."""
    return json.loads(text, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
