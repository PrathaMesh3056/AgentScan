"""Audit flat and nested MCP declarations without starting configured servers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from loguru import logger

from agentscan.core.models import Finding, Severity
from agentscan.identity.permission_mapper import load_dangerous_keywords
from agentscan.supply_chain.coverage import collect_inputs, record_coverage


def _valid_server(config: Any, *, nested: bool) -> bool:
    if not isinstance(config, dict):
        return False
    if nested:
        command, url = config.get("command"), config.get("url")
        if bool(command) == bool(url):
            return False
        if command and (not isinstance(command, str) or not command.strip()):
            return False
        if url:
            if not isinstance(url, str) or any(ord(char) <= 32 for char in url) or "\\" in url:
                return False
            try:
                parsed = urlsplit(url)
                if parsed.port == 0:
                    return False
                if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                    return False
                if parsed.username or parsed.password or parsed.fragment:
                    return False
            except ValueError:
                return False
        args = config.get("args", [])
        if not isinstance(args, list) or any(not isinstance(v, str) for v in args):
            return False
    for key in ("env", "headers"):
        value = config.get(key, {})
        if not isinstance(value, dict) or any(
            not isinstance(k, str) or not isinstance(v, str) for k, v in value.items()
        ):
            return False
    auth = config.get("auth")
    if "auth" in config and (
        not isinstance(auth, dict)
        or not isinstance(auth.get("type"), str)
        or not auth["type"].strip()
    ):
        return False
    tools, scopes = config.get("tools", []), config.get("scopes", [])
    return (
        isinstance(scopes, list)
        and all(isinstance(scope, str) for scope in scopes)
        and isinstance(tools, list)
        and all(
            isinstance(tool, dict)
            and isinstance(tool.get("name", ""), str)
            and isinstance(tool.get("scopes", []), list)
            and all(isinstance(scope, str) for scope in tool.get("scopes", []))
            for tool in tools
        )
    )


def _declarations(config: Any) -> list[tuple[str, Any, bool]]:
    if not isinstance(config, dict):
        raise ValueError("MCP configuration must be an object")
    if "mcpServers" not in config:
        return [("", config, False)]
    servers = config["mcpServers"]
    if not isinstance(servers, dict) or not servers:
        raise ValueError("MCP server declarations are missing or invalid")
    return [(str(name), server, True) for name, server in servers.items()]


def _audit_server(
    config: dict[str, Any], name: str, nested: bool, file: Path, keywords: list[str]
) -> list[Finding]:
    findings: list[Finding] = []
    label = f"{file.name} / {name}" if name else file.name
    provenance = {
        "file": str(file),
        "server_name": name,
        "source": "mcp_config_declarations",
        "runtime_permissions_verified": False,
    }
    is_stdio = nested and bool(config.get("command"))
    declared_header_auth = any(
        key.lower() in {"authorization", "x-api-key", "api-key"} and value.strip()
        for key, value in config.get("headers", {}).items()
    )
    auth = config.get("auth", {})
    declared_auth = auth.get("type", "").strip().lower() not in {
        "",
        "none",
        "disabled",
        "anonymous",
    }
    if not declared_auth and not is_stdio and not declared_header_auth:
        findings.append(
            Finding(
                attack_id="SC-018",
                attack_name="Unauthenticated MCP server",
                severity=Severity.HIGH,
                owasp_id="LLM06",
                description=(
                    f"MCP config '{label}' does not declare authentication. "
                    "Review authentication in the deployed server and transport; "
                    "this declaration does not establish reachability or enforcement."
                ),
                evidence=f"file={file}",
                remediation="Configure server-side authentication for the remote transport and verify it independently.",
                metadata=dict(provenance),
            )
        )
    entries: list[str] = list(config.get("scopes", []))
    for tool in config.get("tools", []):
        entries.append(tool.get("name", ""))
        entries.extend(tool.get("scopes", []))
    seen: set[str] = set()
    for entry in entries:
        for keyword in keywords:
            lowered = keyword.lower()
            if lowered in entry.lower() and lowered not in seen:
                seen.add(lowered)
                findings.append(
                    Finding(
                        attack_id="SC-020",
                        attack_name="Dangerous capability in MCP config",
                        severity=Severity.CRITICAL,
                        owasp_id="LLM06",
                        description=(
                            f"MCP config '{label}' declares a tool/scope matching "
                            f"the dangerous keyword '{keyword}'. Review and justify "
                            "this high-risk declared capability; runtime permissions are unverified."
                        ),
                        evidence=f"file={file}, entry={entry!r}, keyword={keyword!r}",
                        remediation=f"Remove or scope-limit '{entry}' and verify enforcement at the tool boundary.",
                        metadata={**provenance, "entry": entry, "matched_keyword": keyword},
                    )
                )
    return findings


def scan_mcp_configs(path: str, *, coverage: list[dict] | None = None) -> tuple[list[Finding], int]:
    """Return findings and assessed server declarations, preserving malformed siblings.

    A flat configuration counts as one declaration. Nested remote and stdio
    client declarations are supported; commands and environment values are
    never executed, logged or included in findings.
    """
    root = Path(path)
    issues: list[str] = []
    patterns = ("*.mcp.json", "mcp.json", "mcp_config.json", "claude_desktop_config.json")
    ignored = {".git", ".venv", "venv", "node_modules", "__pycache__", ".test-tmp"}
    if root.is_file():
        pattern = next((p for p in patterns if root.match(p)), "*.mcp.json")
        files = collect_inputs(root, pattern, issues, ignored_dirs=ignored)
    else:
        files = sorted(
            {
                file
                for pattern in patterns
                for file in collect_inputs(root, pattern, issues, ignored_dirs=ignored)
            }
        )
    try:
        keywords = load_dangerous_keywords()
        if not isinstance(keywords, list) or not all(isinstance(k, str) for k in keywords):
            raise ValueError("Invalid capability keyword policy")
        if not keywords:
            issues.append("Dangerous-capability policy is unavailable or empty.")
    except Exception as exc:
        keywords = []
        issues.append(f"Dangerous-capability policy failed: {type(exc).__name__}.")
    findings: list[Finding] = []
    checks = selected = 0
    for file in files:
        try:
            if file.stat().st_size > 1024 * 1024:
                raise ValueError("MCP config exceeds 1 MiB")
            declarations = _declarations(json.loads(file.read_text(encoding="utf-8")))
        except Exception as exc:
            selected += 1
            issues.append(f"{file.name}: {type(exc).__name__}.")
            logger.error("MCP configuration parse failed: {}", type(exc).__name__)
            continue
        for name, config, nested in declarations:
            selected += 1
            if not _valid_server(config, nested=nested) or (nested and not name.strip()):
                issues.append(f"{file.name}: unsupported server declaration.")
                continue
            checks += 1
            findings.extend(_audit_server(config, name, nested, file, keywords))
    record_coverage(
        coverage, "mcp", checks, source="mcp_config_declarations", issues=issues, selected=selected
    )
    if coverage is not None:
        coverage[-1].update(
            {
                "files_selected": len(files),
                "counting_unit": "server declarations",
                "runtime_permissions_verified": False,
            }
        )
    return findings, checks
