"""Tool catalog: schema hashing, tool identity, drift detection, and visibility.

This module is pure: no I/O, no MCP client, no receipts. It owns the mapping
between signed policy tool entries and the upstream tool snapshot.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal

from mcp.types import Tool

from agentscan.gateway.canonical import canonical_json
from agentscan.gateway.policy import Policy, ToolPolicy

_MAX_DETAIL_NAME = 64
_SCHEMA_HASH_PREFIX = "sha256:"


class CatalogError(ValueError):
    """Invalid catalog input. Messages are bounded and safe to display."""


def _canonical_bytes(value: Mapping[str, Any], message: str) -> bytes:
    if not isinstance(value, Mapping):
        raise CatalogError(message)
    _reject_non_string_keys(value)
    try:
        return canonical_json(value)
    except (TypeError, ValueError) as exc:
        raise CatalogError(message) from exc


def _reject_non_string_keys(value: Any) -> None:
    if isinstance(value, Mapping):
        keys = list(value)
        if any(not isinstance(key, str) for key in keys):
            raise CatalogError("schema mapping keys must be strings")
        if len(set(keys)) != len(keys):
            raise CatalogError("schema mapping contains duplicate keys")
        for item in value.values():
            _reject_non_string_keys(item)
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            _reject_non_string_keys(item)


def tool_schema_hash(input_schema: Mapping[str, Any]) -> str:
    """Hash the canonical JSON form of a tool input schema."""
    encoded = _canonical_bytes(input_schema, "tool input schema is not canonicalizable")
    return _SCHEMA_HASH_PREFIX + hashlib.sha256(encoded).hexdigest()


def tool_identity_hash(server_id: str, tool_name: str, input_schema: Mapping[str, Any]) -> str:
    """Hash server id, tool name, and schema; display name and description are not identity."""
    if not isinstance(server_id, str) or not server_id:
        raise CatalogError("server id must be a non-empty string")
    if not isinstance(tool_name, str) or not tool_name:
        raise CatalogError("tool name must be a non-empty string")
    encoded = _canonical_bytes(
        {"server_id": server_id, "name": tool_name, "schema": input_schema},
        "tool identity payload is not canonicalizable",
    )
    return _SCHEMA_HASH_PREFIX + hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class CatalogTool:
    """One upstream tool snapshot with derived hashes."""

    server_id: str
    name: str
    description: str
    input_schema: Mapping[str, Any]
    schema_hash: str
    tool_identity: str
    tool: Tool


@dataclass(frozen=True, slots=True)
class CatalogMismatch:
    """One deterministic reason a policy tool does not match the catalog."""

    tool_name: str
    reason: Literal[
        "server_mismatch",
        "missing_upstream",
        "schema_drift",
        "rule_argument_missing",
    ]
    detail: str


_MISMATCH_DETAILS: dict[str, str] = {
    "server_mismatch": "policy server does not match the catalog server",
    "missing_upstream": "tool is missing from the loaded upstream catalog",
    "schema_drift": "tool input schema does not match the approved schema hash",
    "rule_argument_missing": "rule argument is absent from the tool input schema properties",
}


def _bounded_name(name: str) -> str:
    return name[:_MAX_DETAIL_NAME]


def _missing_rule_arguments(entry: CatalogTool, tool: ToolPolicy) -> tuple[str, ...]:
    schema = entry.input_schema
    properties = schema.get("properties") if isinstance(schema, Mapping) else None
    present = properties if isinstance(properties, Mapping) else {}
    missing: list[str] = []
    for rule in tool.rules:
        for name in rule.arguments:
            if name not in present:
                missing.append(name)
    return tuple(missing)


class ToolCatalog:
    """Immutable-by-replacement snapshot of the upstream tool list."""

    def __init__(self, server_id: str) -> None:
        if not isinstance(server_id, str) or not server_id:
            raise CatalogError("server id must be a non-empty string")
        self._server_id = server_id
        self._tools: tuple[CatalogTool, ...] = ()
        self._by_name: dict[str, CatalogTool] = {}
        self._loaded = False

    @property
    def server_id(self) -> str:
        return self._server_id

    @property
    def loaded(self) -> bool:
        return self._loaded

    @property
    def entries(self) -> tuple[CatalogTool, ...]:
        return self._tools

    def get(self, name: str) -> CatalogTool | None:
        return self._by_name.get(name)

    def replace(self, tools: Sequence[Tool]) -> None:
        """Atomically replace the snapshot; on error the prior snapshot survives."""
        entries: list[CatalogTool] = []
        seen: set[str] = set()
        for tool in tools:
            if not isinstance(tool, Tool):
                raise CatalogError("catalog entries must be MCP tools")
            schema = tool.inputSchema
            if not isinstance(schema, Mapping):
                raise CatalogError("tool input schema must be a mapping")
            name = tool.name
            if not isinstance(name, str) or not name:
                raise CatalogError("tool name must be a non-empty string")
            if name in seen:
                raise CatalogError("duplicate tool name in upstream catalog")
            seen.add(name)
            schema_hash = tool_schema_hash(schema)
            identity = tool_identity_hash(self._server_id, name, schema)
            entries.append(
                CatalogTool(
                    server_id=self._server_id,
                    name=name,
                    description=tool.description or "",
                    input_schema=schema,
                    schema_hash=schema_hash,
                    tool_identity=identity,
                    tool=tool,
                )
            )
        # The new snapshot is complete and valid; replace the state in one step.
        self._tools = tuple(entries)
        self._by_name = {entry.name: entry for entry in entries}
        self._loaded = True

    def check_policy(self, policy: Policy) -> tuple[CatalogMismatch, ...]:
        """Return deterministic mismatches between the policy and the snapshot."""
        mismatches: list[CatalogMismatch] = []
        for tool_name, tool in policy.tools.items():
            entry = self._by_name.get(tool_name) if self._loaded else None
            if tool.server != self._server_id:
                mismatches.append(
                    CatalogMismatch(
                        tool_name=tool_name,
                        reason="server_mismatch",
                        detail=_MISMATCH_DETAILS["server_mismatch"],
                    )
                )
            if entry is None:
                mismatches.append(
                    CatalogMismatch(
                        tool_name=tool_name,
                        reason="missing_upstream",
                        detail=_MISMATCH_DETAILS["missing_upstream"],
                    )
                )
                continue
            if tool.schema_hash != entry.schema_hash:
                mismatches.append(
                    CatalogMismatch(
                        tool_name=tool_name,
                        reason="schema_drift",
                        detail=_MISMATCH_DETAILS["schema_drift"],
                    )
                )
            for name in _missing_rule_arguments(entry, tool):
                mismatches.append(
                    CatalogMismatch(
                        tool_name=tool_name,
                        reason="rule_argument_missing",
                        detail=(
                            _MISMATCH_DETAILS["rule_argument_missing"] + f": {_bounded_name(name)}"
                        ),
                    )
                )
        return tuple(mismatches)

    def approved_tools(self, policy: Policy) -> tuple[Tool, ...]:
        """Upstream tools whose policy entry matches exactly, in catalog order."""
        approved: list[Tool] = []
        for entry in self._tools:
            tool = policy.tools.get(entry.name)
            if tool is None:
                continue
            if tool.server != self._server_id:
                continue
            if tool.schema_hash != entry.schema_hash:
                continue
            if _missing_rule_arguments(entry, tool):
                continue
            approved.append(entry.tool)
        return tuple(approved)
