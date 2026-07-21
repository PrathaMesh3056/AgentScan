# agentscan/supply_chain/mcp_auditor.py
#
# MCP (Model Context Protocol) configuration auditor.
#
# Finds all *.mcp.json files in a directory tree and checks:
#   SC-018 — missing "auth" key (unauthenticated MCP server)
#   SC-020 — declared scope/tool name matches a dangerous keyword
#             (reuses identity.permission_mapper.load_dangerous_keywords)
#
# Cross-module import note: supply_chain → identity is legitimate.
# Neither is `core`. The rule in scorer.py's docstring is that `core`
# must not depend on identity/supply_chain, not the reverse.

from __future__ import annotations

import json
from pathlib import Path

from loguru import logger

from agentscan.core.models import Finding, Severity
from agentscan.identity.permission_mapper import load_dangerous_keywords

# ── Public scanner ────────────────────────────────────────────────────────────


def scan_mcp_configs(path: str) -> tuple[list[Finding], int]:
    """
    Find all *.mcp.json files under `path` and audit them for security issues.

    Returns:
        (findings, checks_run) where checks_run = number of MCP config files found.
    """
    root = Path(path)
    mcp_files = list(root.rglob("*.mcp.json"))
    checks_run = len(mcp_files)

    dangerous_keywords = load_dangerous_keywords()
    findings: list[Finding] = []

    for mcp_file in mcp_files:
        try:
            config = json.loads(mcp_file.read_text(encoding="utf-8"))
        except Exception as e:
            logger.error(f"Failed to parse MCP config {mcp_file}: {e}")
            continue

        # ── SC-018: missing auth ───────────────────────────────────────────────
        if "auth" not in config:
            findings.append(
                Finding(
                    attack_id="SC-018",
                    attack_name="Unauthenticated MCP server",
                    severity=Severity.HIGH,
                    owasp_id="LLM08",
                    description=(
                        f"MCP config '{mcp_file.name}' is missing an 'auth' key. "
                        f"An unauthenticated MCP server can be accessed by any process "
                        f"on the network, enabling unauthorised tool invocation."
                    ),
                    evidence=f"file={mcp_file}",
                    remediation=(
                        "Add an 'auth' block to the MCP config specifying an "
                        "authentication mechanism (e.g. API key, OAuth2, mTLS)."
                    ),
                    metadata={"file": str(mcp_file)},
                )
            )

        # ── SC-020: dangerous keyword in scope / tool names ───────────────────
        if not dangerous_keywords:
            continue

        # Collect all scope and tool name strings from the config
        scopes_and_tools: list[str] = []
        for tool in config.get("tools", []):
            if isinstance(tool, dict):
                if "name" in tool:
                    scopes_and_tools.append(str(tool["name"]))
                for scope in tool.get("scopes", []):
                    scopes_and_tools.append(str(scope))

        seen_keywords: set[str] = set()
        for entry in scopes_and_tools:
            entry_lower = entry.lower()
            for keyword in dangerous_keywords:
                kw_lower = keyword.lower()
                if kw_lower in entry_lower and kw_lower not in seen_keywords:
                    seen_keywords.add(kw_lower)
                    findings.append(
                        Finding(
                            attack_id="SC-020",
                            attack_name="Dangerous capability in MCP config",
                            severity=Severity.CRITICAL,
                            owasp_id="LLM08",
                            description=(
                                f"MCP config '{mcp_file.name}' declares a tool/scope "
                                f"matching the dangerous keyword '{keyword}'. "
                                f"This grants the agent a high-risk capability that "
                                f"should be explicitly reviewed and justified."
                            ),
                            evidence=(f"file={mcp_file}, entry={entry!r}, keyword={keyword!r}"),
                            remediation=(
                                f"Remove or scope-limit the '{entry}' capability. "
                                f"If required, document the justification and add a "
                                f"compensating control (audit logging, human-in-the-loop)."
                            ),
                            metadata={
                                "file": str(mcp_file),
                                "entry": entry,
                                "matched_keyword": keyword,
                            },
                        )
                    )

    return findings, checks_run
