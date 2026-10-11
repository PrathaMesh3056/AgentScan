# agentscan/mcp/server.py
#
# Model Context Protocol (MCP) stdio JSON-RPC server for AgentScan.
#
# Exposes AgentScan capabilities directly to AI IDEs (Cursor, Windsurf, Zed, Antigravity)
# as native tools over the standard MCP stdio protocol (JSON-RPC 2.0).

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any

from loguru import logger

# Configure stdio logging only when actually starting this server, not on import.


TOOLS_METADATA: list[dict[str, Any]] = [
    {
        "name": "agentscan_list_attacks",
        "description": "List all 23 registered AgentScan security attack modules, their OWASP LLM mappings, and supported scan modes.",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "agentscan_audit",
        "description": "Audit a project repository for AI supply-chain vulnerabilities, known CVEs, hardcoded API secrets, insecure framework configurations (CrewAI, LangGraph, AutoGen), and transitive dependency risks.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Directory to audit (defaults to '.')",
                    "default": ".",
                },
                "offline": {
                    "type": "boolean",
                    "description": "Audit using offline database without network calls",
                    "default": True,
                },
                "show_transitive": {
                    "type": "boolean",
                    "description": "Trace and display root-to-leaf transitive dependency chains",
                    "default": True,
                },
            },
        },
    },
    {
        "name": "agentscan_scan",
        "description": "Run an automated security scan against an LLM agent endpoint for prompt injection, jailbreaks, PII exfiltration, excessive agency, and OWASP LLM vulnerabilities.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_url": {
                    "type": "string",
                    "description": "Target endpoint URL (e.g. http://localhost:8000/chat)",
                },
                "system_prompt": {
                    "type": "string",
                    "description": "Known system prompt for leak verification (optional)",
                },
                "timeout": {
                    "type": "integer",
                    "description": "HTTP request timeout in seconds",
                    "default": 30,
                },
            },
            "required": ["target_url"],
        },
    },
    {
        "name": "agentscan_swarm",
        "description": "Orchestrate collaborative multi-agent red-team swarms (Recon, Bypass, Exploit, Judge) against an AI agent endpoint.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_url": {
                    "type": "string",
                    "description": "Target endpoint URL (e.g. http://localhost:8000/chat)",
                },
                "team": {
                    "type": "string",
                    "description": "Swarm preset name ('trio', 'agency', 'stealth') or YAML path",
                    "default": "trio",
                },
                "model": {
                    "type": "string",
                    "description": "LLM model identifier for agents (e.g. 'gpt-4o-mini', 'ollama/llama3')",
                },
                "rounds": {
                    "type": "integer",
                    "description": "Maximum collaborative execution rounds",
                    "default": 2,
                },
                "offline": {
                    "type": "boolean",
                    "description": "Run in deterministic offline heuristic mode without API keys",
                    "default": True,
                },
            },
            "required": ["target_url"],
        },
    },
]


def handle_list_attacks() -> str:
    from agentscan.attacks.registry import registry

    registry.load_all()
    modules = registry.get_all()
    out = [
        f"AgentScan Attack Registry ({len(modules)} registered modules):",
        "",
        "| Attack ID | Name | OWASP ID | Modes |",
        "|---|---|---|---|",
    ]
    for m in sorted(modules, key=lambda x: x.attack_id):
        modes_str = ", ".join(mode.value for mode in m.supported_modes)
        out.append(f"| {m.attack_id} | {m.attack_name} | {m.owasp_id} | {modes_str} |")
    return "\n".join(out)


def handle_audit(args: dict[str, Any]) -> str:
    from agentscan.supply_chain.config_auditor import scan_config
    from agentscan.supply_chain.dep_scanner import scan_dependencies
    from agentscan.supply_chain.framework_auditor import scan_frameworks
    from agentscan.supply_chain.secret_scanner import scan_secrets

    path_str = str(args.get("path", "."))
    offline = bool(args.get("offline", True))
    show_transitive = bool(args.get("show_transitive", True))

    all_findings = []
    total_checks = 0

    # Dependencies
    dep_findings, dep_checks = scan_dependencies(
        path_str, offline=offline, show_transitive=show_transitive
    )
    all_findings.extend(dep_findings)
    total_checks += dep_checks

    # Configs
    cfg_findings, cfg_checks = scan_config(path_str)
    all_findings.extend(cfg_findings)
    total_checks += cfg_checks

    # Secrets
    sec_findings, sec_checks = scan_secrets(path_str)
    all_findings.extend(sec_findings)
    total_checks += sec_checks

    # Frameworks
    fw_findings, fw_checks = scan_frameworks(path_str)
    all_findings.extend(fw_findings)
    total_checks += fw_checks

    # Native Semgrep AI rules (zero-dependency)
    from agentscan.supply_chain.native_semgrep import scan_native_rules

    rule_findings, rule_checks = scan_native_rules(path_str)
    all_findings.extend(rule_findings)
    total_checks += rule_checks

    from agentscan.core.scorer import calculate_score, score_band

    score = calculate_score(all_findings, total_checks)
    status = score_band(score)

    result = {
        "audit_path": str(Path(path_str).resolve()),
        "score": score,
        "status": status,
        "checks_run": total_checks,
        "findings_count": len(all_findings),
        "findings": [
            {
                "id": f.attack_id,
                "severity": f.severity.value,
                "owasp_id": f.owasp_id,
                "description": f.description,
                "evidence": f.evidence,
                "remediation": f.remediation,
                "metadata": f.metadata,
            }
            for f in all_findings
        ],
    }
    return json.dumps(result, indent=2)


async def handle_scan_async(args: dict[str, Any]) -> str:
    from agentscan.core.models import Target
    from agentscan.core.runner import run_scan

    target_url = str(args["target_url"])
    system_prompt = args.get("system_prompt")
    timeout = int(args.get("timeout", 30))

    target = Target(url=target_url, system_prompt=system_prompt, timeout=timeout)
    report = await run_scan(target)

    result = {
        "target_url": report.target_url,
        "score": report.score,
        "ssp_class": report.ssp_class.value if report.ssp_class else "SERVANT",
        "tests_run": report.tests_run,
        "findings_count": len(report.findings),
        "findings": [
            {
                "id": f.attack_id,
                "severity": f.severity.value,
                "owasp_id": f.owasp_id,
                "description": f.description,
                "evidence": f.evidence,
            }
            for f in report.findings
        ],
    }
    return json.dumps(result, indent=2)


async def handle_swarm_async(args: dict[str, Any]) -> str:
    from agentscan.core.models import Target
    from agentscan.swarm.coordinator import SwarmCoordinator
    from agentscan.swarm.presets import resolve_team

    target_url = str(args["target_url"])
    team_name = str(args.get("team", "trio"))
    model = args.get("model")
    rounds = int(args.get("rounds", 2))
    offline = bool(args.get("offline", True))

    team_cfg = resolve_team(team_name)
    team_cfg.max_rounds = rounds

    coordinator = SwarmCoordinator(
        team_config=team_cfg,
        model_override=model,
        offline=offline,
    )
    target = Target(url=target_url)
    report = await coordinator.run_swarm(target)
    return json.dumps(report.model_dump(mode="json"), indent=2)


def _run_coro_safe(coro: Any) -> Any:
    """Run an async coroutine safely from sync context, handling nested event loops."""
    try:
        asyncio.get_running_loop()
        # Already in an async loop — run in a new thread to avoid RuntimeError
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(asyncio.run, coro).result()
    except RuntimeError:
        return asyncio.run(coro)


def process_jsonrpc_message(msg: dict[str, Any]) -> dict[str, Any] | None:
    req_id = msg.get("id")
    method = msg.get("method")
    params = msg.get("params", {})

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": params.get("protocolVersion")
                if params.get("protocolVersion") in {"2024-11-05", "2025-03-26", "2025-06-18"}
                else "2025-06-18",
                "capabilities": {
                    "tools": {},
                },
                "serverInfo": {
                    "name": "agentscan",
                    "version": __import__(
                        "agentscan.core.models", fromlist=["_installed_version"]
                    )._installed_version(),
                },
            },
        }

    if method == "notifications/initialized":
        return None

    if method == "ping":
        return {"jsonrpc": "2.0", "id": req_id, "result": {}}

    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "tools": TOOLS_METADATA,
            },
        }

    if method == "tools/call":
        tool_name = params.get("name")
        arguments = params.get("arguments", {})

        try:
            if tool_name == "agentscan_list_attacks":
                text = handle_list_attacks()
            elif tool_name == "agentscan_audit":
                text = handle_audit(arguments)
            elif tool_name == "agentscan_scan":
                text = _run_coro_safe(handle_scan_async(arguments))
            elif tool_name == "agentscan_swarm":
                text = _run_coro_safe(handle_swarm_async(arguments))
            else:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32601, "message": f"Tool not found: {tool_name}"},
                }

            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": text,
                        }
                    ]
                },
            }
        except Exception as e:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "isError": True,
                    "content": [{"type": "text", "text": f"Error executing tool {tool_name}: {e}"}],
                },
            }

    if req_id is not None:
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }

    return None


def run_mcp_server() -> None:
    """Run the MCP stdio JSON-RPC loop until EOF."""
    logger.remove()
    logger.add(sys.stderr, level="ERROR")
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            resp = process_jsonrpc_message(req)
            if resp is not None:
                sys.stdout.write(json.dumps(resp) + "\n")
                sys.stdout.flush()
        except json.JSONDecodeError:
            err = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": "Parse error"},
            }
            sys.stdout.write(json.dumps(err) + "\n")
            sys.stdout.flush()
        except Exception as e:
            err = {"jsonrpc": "2.0", "id": None, "error": {"code": -32603, "message": str(e)}}
            sys.stdout.write(json.dumps(err) + "\n")
            sys.stdout.flush()
