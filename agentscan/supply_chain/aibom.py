# agentscan/supply_chain/aibom.py
#
# CycloneDX 1.6 AIBOM export: pinned packages + model/MCP permission stubs.

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agentscan.core.models import _installed_version
from agentscan.supply_chain.dep_scanner import _is_exact_version, _parse_dependencies


def _purl(name: str, version: str) -> str:
    return f"pkg:pypi/{name}@{version}"


def _package_components(root: str) -> list[dict[str, Any]]:
    components: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for name, version in _parse_dependencies(root):
        key = (name, version)
        if key in seen:
            continue
        seen.add(key)
        exact = _is_exact_version(version)
        components.append(
            {
                "type": "library",
                "bom-ref": f"pkg:pypi/{name}@{version}",
                "name": name,
                **({"version": version, "purl": _purl(name, version)} if exact else {}),
                "properties": [
                    {"name": "agentscan:declared-requirement", "value": version},
                    {
                        "name": "agentscan:version-status",
                        "value": "resolved" if exact else "unresolved",
                    },
                ],
            }
        )
    return components


def _model_stubs(model: str | None = None) -> list[dict[str, Any]]:
    if model is None:
        return []
    return [
        {
            "type": "machine-learning-model",
            "bom-ref": f"model:{model}",
            "name": model,
            "description": (
                "Explicit operator-declared scanner reference model; target usage and installed weights are unverified."
            ),
            "properties": [
                {"name": "agentscan:role", "value": "deep-reference"},
                {
                    "name": "agentscan:provenance",
                    "value": "operator-declared; not observed target inventory",
                },
            ],
        }
    ]


def _mcp_stubs(root: str) -> list[dict[str, Any]]:
    components: list[dict[str, Any]] = []
    for path in Path(root).rglob("*.mcp.json"):
        issue = ""
        try:
            config = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(config, dict):
                raise ValueError("MCP configuration must be an object")
        except (OSError, ValueError) as exc:
            config = {}
            issue = type(exc).__name__
        tools = config.get("tools") if isinstance(config, dict) else None
        tool_names: list[str] = []
        if isinstance(tools, list):
            for tool in tools:
                if isinstance(tool, dict) and tool.get("name"):
                    tool_names.append(str(tool["name"]))
        elif isinstance(config, dict):
            servers = config.get("mcpServers") or config.get("servers") or {}
            if isinstance(servers, dict):
                tool_names.extend(str(k) for k in servers)
            else:
                issue = "invalid server inventory shape"
        ref = f"mcp:{path.as_posix()}"
        components.append(
            {
                "type": "application",
                "bom-ref": ref,
                "name": path.name,
                "description": f"MCP config stub from {path}",
                "properties": [
                    {"name": "agentscan:mcp-path", "value": str(path)},
                    {"name": "agentscan:mcp-tools", "value": ",".join(tool_names)},
                    {"name": "agentscan:auth-present", "value": str(bool(config.get("auth")))},
                    {
                        "name": "agentscan:provenance",
                        "value": "source declaration; deployed permissions unverified",
                    },
                    {
                        "name": "agentscan:inventory-status",
                        "value": "unavailable" if issue else "declared",
                    },
                    {"name": "agentscan:inventory-error", "value": issue},
                ],
            }
        )
    return components


def build_cyclonedx_aibom(path: str, *, reference_model: str | None = None) -> dict[str, Any]:
    """Build a CycloneDX 1.6 JSON document for the project at `path`."""
    root = str(Path(path).resolve())
    now = datetime.now(UTC).isoformat()
    serial = f"urn:uuid:{uuid.uuid4()}"
    components = _package_components(root) + _model_stubs(reference_model) + _mcp_stubs(root)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "properties": [
                {
                    "name": "agentscan:inventory-provenance",
                    "value": "project source declarations; runtime inventory is not assessed",
                }
            ],
            "timestamp": now,
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "agentscan",
                        "version": _installed_version(),
                    }
                ]
            },
            "component": {
                "type": "application",
                "name": Path(root).name,
                "bom-ref": f"app:{Path(root).name}",
            },
        },
        "components": components,
    }


def write_aibom(path: str, output: Path) -> Path:
    doc = build_cyclonedx_aibom(path)
    output.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    return output
