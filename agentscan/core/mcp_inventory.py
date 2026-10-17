"""Exact operator-baseline comparisons of advertised MCP tool metadata.

An inventory deviation describes a catalog policy mismatch. It is not evidence
that a tool ran, that a server is malicious, or that permissions are enforced.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

MCP_INVENTORY_ALGORITHM: Literal["mcp-tool-json-sha256-v1"] = "mcp-tool-json-sha256-v1"
_NAME = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z", re.ASCII)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_MAX_JSON_BYTES = 4 * 1024 * 1024
_MAX_JSON_NODES = 100_000
_MAX_JSON_DEPTH = 64
_MAX_CATALOG_TOOLS = 10_000
_MAX_DEVIATIONS = 100


def _valid_name(value: Any) -> bool:
    return isinstance(value, str) and _NAME.fullmatch(value) is not None


class McpInventoryBaseline(BaseModel):
    """Independently approved catalog for one exact operator-selected endpoint."""

    model_config = ConfigDict(extra="forbid")

    endpoint: str = Field(strict=True, min_length=1, max_length=8192)
    tools: dict[str, str]
    algorithm: Literal["mcp-tool-json-sha256-v1"] = MCP_INVENTORY_ALGORITHM

    @field_validator("endpoint")
    @classmethod
    def endpoint_is_explicit(cls, value: str) -> str:
        if value != value.strip() or any(ord(char) <= 32 or ord(char) == 127 for char in value):
            raise ValueError("Use an exact endpoint without whitespace or control characters.")
        return value

    @field_validator("tools", mode="before")
    @classmethod
    def exact_approved_tools(cls, value: Any) -> dict[str, str]:
        if not isinstance(value, dict) or len(value) > 1000:
            raise ValueError("Use an object containing at most 1000 approved tools.")
        if any(
            not _valid_name(name)
            or not isinstance(digest, str)
            or _SHA256.fullmatch(digest) is None
            for name, digest in value.items()
        ):
            raise ValueError("Approved tools need exact ASCII names and lowercase SHA256 hashes.")
        return value


def _canonical_tool_bytes(tool: dict[str, Any]) -> bytes:
    # Validate before serialization: JSON's default accepts non-finite floats,
    # coerces non-string object keys and can recurse through hostile structures.
    nodes = 0
    active: set[int] = set()

    def visit(value: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > _MAX_JSON_NODES or depth > _MAX_JSON_DEPTH:
            raise ValueError("MCP tool metadata exceeds structural limits.")
        if value is None or type(value) in (str, bool, int):
            return
        if type(value) is float:
            if not math.isfinite(value):
                raise ValueError("MCP tool metadata contains a non-finite number.")
            return
        if type(value) not in (dict, list):
            raise ValueError("MCP tool metadata must contain only JSON values.")
        identity = id(value)
        if identity in active:
            raise ValueError("MCP tool metadata contains a cycle.")
        active.add(identity)
        try:
            if isinstance(value, dict):
                if any(type(key) is not str for key in value):
                    raise ValueError("MCP tool metadata keys must be strings.")
                for child in value.values():
                    visit(child, depth + 1)
            else:
                for child in value:
                    visit(child, depth + 1)
        finally:
            active.remove(identity)

    visit(tool, 0)
    try:
        encoded = json.dumps(
            tool, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":")
        ).encode("ascii")
    except (ValueError, TypeError, OverflowError) as error:
        raise ValueError("MCP tool metadata cannot be canonicalized.") from error
    if len(encoded) > _MAX_JSON_BYTES:
        raise ValueError("MCP tool metadata exceeds the byte limit.")
    return encoded


def _validated_tool_bytes(tool: dict[str, Any]) -> bytes:
    if not isinstance(tool, dict) or not _valid_name(tool.get("name")):
        raise ValueError("MCP tool requires a valid exact name.")
    if "description" in tool and not isinstance(tool["description"], str):
        raise ValueError("MCP tool description must be a string.")
    schema = tool.get("inputSchema")
    if not isinstance(schema, dict) or schema.get("type") != "object":
        raise ValueError("MCP tool inputSchema must declare an object schema.")
    for field in ("outputSchema", "annotations"):
        if field in tool and not isinstance(tool[field], dict):
            raise ValueError(f"MCP tool {field} must be an object.")
    return _canonical_tool_bytes(tool)


def fingerprint_mcp_tool(tool: dict[str, Any]) -> str:
    """Hash the entire versioned canonical JSON tool, including unknown metadata."""
    return hashlib.sha256(_validated_tool_bytes(tool)).hexdigest()


def compare_mcp_inventory(
    tools: list[dict[str, Any]], baseline: McpInventoryBaseline
) -> dict[str, Any]:
    """Compare a complete snapshot; reject every invalid catalog before reporting."""
    if not isinstance(tools, list) or len(tools) > _MAX_CATALOG_TOOLS:
        raise ValueError("MCP catalog exceeds the tool limit or is not a list.")
    observed: dict[str, str] = {}
    catalog_bytes = 0
    for tool in tools:
        encoded = _validated_tool_bytes(tool)
        catalog_bytes += len(encoded)
        if catalog_bytes > _MAX_JSON_BYTES:
            raise ValueError("MCP catalog metadata exceeds the aggregate byte limit.")
        digest = hashlib.sha256(encoded).hexdigest()
        name = tool["name"]
        if name in observed:
            raise ValueError("MCP catalog contains duplicate tool identities.")
        observed[name] = digest

    counts = {"unexpected_tool": 0, "metadata_changed": 0, "missing_tool": 0}
    deviations: list[dict[str, str]] = []
    matched = 0
    for name in sorted(observed.keys() | baseline.tools.keys()):
        expected, actual = baseline.tools.get(name), observed.get(name)
        if expected == actual:
            matched += 1
            continue
        kind = (
            "unexpected_tool"
            if expected is None
            else "missing_tool"
            if actual is None
            else "metadata_changed"
        )
        counts[kind] += 1
        if len(deviations) < _MAX_DEVIATIONS:
            entry = {"kind": kind, "name": name}
            if expected is not None:
                entry["expected_sha256"] = expected
            if actual is not None:
                entry["observed_sha256"] = actual
            deviations.append(entry)
    total = sum(counts.values())
    return {
        "algorithm": MCP_INVENTORY_ALGORITHM,
        "observed_tool_count": len(observed),
        "approved_tool_count": len(baseline.tools),
        "matched_tool_count": matched,
        "deviation_count": total,
        "deviation_counts": counts,
        "deviations": deviations,
        "truncated": total > len(deviations),
    }
