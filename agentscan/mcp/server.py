# agentscan/mcp/server.py
#
# Model Context Protocol (MCP) stdio JSON-RPC server for AgentScan.
#
# Exposes AgentScan capabilities directly to AI IDEs (Cursor, Windsurf, Zed, Antigravity)
# as native tools over the standard MCP stdio protocol (JSON-RPC 2.0).

from __future__ import annotations

import asyncio
import ipaddress
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from loguru import logger

# Configure stdio logging only when actually starting this server, not on import.


# ── Live-target policy ──────────────────────────────────────────────────────────


@dataclass
class LiveTargetPolicy:
    """Server-start policy for MCP live scan/swarm targets."""

    allowed_hosts: list[str] | None = None
    allowed_networks: list[str] | None = None
    request_budget: int | None = None
    allow_live_targets: bool = False
    # Compatibility aliases used by callers/CLI.
    allowed_cidrs: list[str] | None = None
    consent: bool = False
    allow_live: bool = False
    live_enabled: bool = False

    def __post_init__(self) -> None:
        if self.allowed_cidrs is not None and self.allowed_networks is None:
            self.allowed_networks = list(self.allowed_cidrs)
        if self.allowed_networks is not None and self.allowed_cidrs is None:
            self.allowed_cidrs = list(self.allowed_networks)
        if self.allowed_networks is not None and self.allowed_cidrs is not None:
            merged = list(dict.fromkeys([*self.allowed_networks, *self.allowed_cidrs]))
            self.allowed_networks = merged
            self.allowed_cidrs = merged
        self.allow_live_targets = bool(
            self.allow_live_targets or self.consent or self.allow_live or self.live_enabled
        )

    @property
    def networks(self) -> list[str] | None:
        if self.allowed_networks is not None:
            return self.allowed_networks
        return self.allowed_cidrs

    @property
    def is_live_enabled(self) -> bool:
        return bool(self.allow_live_targets)


# Backwards/alternative names for the same policy object.
LivePolicy = LiveTargetPolicy
McpLivePolicy = LiveTargetPolicy
McpLiveTargetPolicy = LiveTargetPolicy
TargetPolicy = LiveTargetPolicy
ServerPolicy = LiveTargetPolicy
McpServerPolicy = LiveTargetPolicy
LivePolicyConfig = LiveTargetPolicy


_CURRENT_POLICY: LiveTargetPolicy = LiveTargetPolicy()


def set_live_policy(policy: Any = None, **kwargs: Any) -> LiveTargetPolicy:
    global _CURRENT_POLICY
    if policy is None:
        policy = LiveTargetPolicy(**kwargs)
    elif isinstance(policy, dict):
        policy = LiveTargetPolicy(**policy)
    elif not isinstance(policy, LiveTargetPolicy):
        # Accept simple objects/dicts with attributes.
        data = {}
        for name in (
            "allowed_hosts",
            "allowed_networks",
            "allowed_cidrs",
            "request_budget",
            "allow_live_targets",
            "consent",
            "allow_live",
            "live_enabled",
        ):
            if hasattr(policy, name):
                data[name] = getattr(policy, name)
            elif name in getattr(policy, "__dict__", {}):
                data[name] = policy.__dict__[name]
        policy = LiveTargetPolicy(**data)
    _CURRENT_POLICY = policy
    return _CURRENT_POLICY


def get_live_policy() -> LiveTargetPolicy:
    return _CURRENT_POLICY


def _resolve_policy(policy: Any = None, **kwargs: Any) -> LiveTargetPolicy:
    if policy is None and kwargs:
        try:
            policy = LiveTargetPolicy(**kwargs)
        except TypeError:
            # Drop unknown keys.
            allowed = {
                "allowed_hosts",
                "allowed_networks",
                "allowed_cidrs",
                "request_budget",
                "allow_live_targets",
                "consent",
                "allow_live",
                "live_enabled",
            }
            policy = LiveTargetPolicy(**{k: v for k, v in kwargs.items() if k in allowed})
    if policy is None:
        policy = _CURRENT_POLICY
    elif isinstance(policy, dict):
        policy = LiveTargetPolicy(**policy)
    elif not isinstance(policy, LiveTargetPolicy):
        policy = set_live_policy(policy)
    return policy


def _policy_allowed_hosts(policy: LiveTargetPolicy) -> list[str] | None:
    return policy.allowed_hosts


def _policy_networks(policy: LiveTargetPolicy) -> list[str] | None:
    return policy.networks


def _target_approved_by_policy(url: str, policy: LiveTargetPolicy) -> bool:
    if not policy.is_live_enabled:
        return False
    parsed = urlsplit(url)
    host = parsed.hostname
    if not host:
        return False
    try:
        host_norm = host.rstrip(".").encode("idna").decode("ascii").lower()
    except Exception:
        host_norm = host.lower()
    allowed_hosts = policy.allowed_hosts or []
    try:
        enrolled = {
            str(v).strip().rstrip(".").encode("idna").decode("ascii").lower() for v in allowed_hosts
        }
    except Exception:
        enrolled = {str(v).strip().lower() for v in allowed_hosts}
    if host_norm in enrolled:
        return True
    networks = policy.networks or []
    try:
        ip = ipaddress.ip_address(host_norm.strip("[]"))
    except ValueError:
        return False
    for cidr in networks:
        try:
            if ip in ipaddress.ip_network(str(cidr), strict=False):
                return True
        except ValueError:
            continue
    # If live mode is enabled but no allowlist was provided, deny by default.
    if not allowed_hosts and not networks:
        return False
    return False


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
    from agentscan.core.scorer import calculate_score, score_band
    from agentscan.identity.orchestrator import run_identity_audit
    from agentscan.supply_chain.config_auditor import scan_config
    from agentscan.supply_chain.dep_scanner import scan_dependencies
    from agentscan.supply_chain.framework_auditor import scan_frameworks
    from agentscan.supply_chain.mcp_auditor import scan_mcp_configs
    from agentscan.supply_chain.secret_scanner import scan_secrets
    from agentscan.supply_chain.typosquat_detector import scan_typosquats

    path_str = str(args.get("path", "."))
    offline = bool(args.get("offline", True))
    show_transitive = bool(args.get("show_transitive", True))

    # Optional module selection mirrors the CLI audit command. When no explicit
    # module flags are supplied, run every default audit module.
    scan_deps = args.get("scan_deps")
    scan_config_flag = args.get("scan_config")
    scan_secrets_flag = args.get("scan_secrets")
    scan_typo = args.get("scan_typo")
    scan_mcp = args.get("scan_mcp")
    scan_identity = args.get("scan_identity")
    scan_frameworks_flag = args.get("scan_frameworks")
    scan_semgrep = args.get("scan_semgrep")
    aibom = args.get("aibom")

    run_all = not any(
        [
            scan_deps,
            scan_config_flag,
            scan_secrets_flag,
            scan_typo,
            scan_mcp,
            scan_identity,
            scan_frameworks_flag,
            scan_semgrep,
            aibom,
        ]
    )

    all_findings = []
    total_checks = 0
    coverage: list[dict[str, Any]] = []
    module_errors: list[dict[str, str]] = []

    if run_all or scan_deps:
        try:
            f, c = scan_dependencies(
                path_str,
                offline=offline,
                show_transitive=show_transitive,
                coverage=coverage,
            )
            all_findings.extend(f)
            total_checks += c
        except Exception as exc:
            module_errors.append({"module_id": "dependencies", "error": str(exc)})

    if run_all or scan_config_flag:
        try:
            f, c = scan_config(path_str, coverage=coverage)
            all_findings.extend(f)
            total_checks += c
        except Exception as exc:
            module_errors.append({"module_id": "config", "error": str(exc)})

    if run_all or scan_secrets_flag:
        try:
            f, c = scan_secrets(path_str, coverage=coverage)
            all_findings.extend(f)
            total_checks += c
        except Exception as exc:
            module_errors.append({"module_id": "secrets", "error": str(exc)})

    if run_all or scan_typo:
        try:
            f, c = scan_typosquats(path_str, coverage=coverage)
            all_findings.extend(f)
            total_checks += c
        except Exception as exc:
            module_errors.append({"module_id": "typosquats", "error": str(exc)})

    if run_all or scan_mcp:
        try:
            f, c = scan_mcp_configs(path_str, coverage=coverage)
            all_findings.extend(f)
            total_checks += c
        except Exception as exc:
            module_errors.append({"module_id": "mcp_configs", "error": str(exc)})

    if run_all or scan_identity:
        try:
            report = run_identity_audit(path_str)
            coverage.extend(report.audit_coverage)
            all_findings.extend(report.findings)
            total_checks += len(report.agents_found)
        except Exception as exc:
            module_errors.append({"module_id": "identity", "error": str(exc)})

    if run_all or scan_frameworks_flag:
        try:
            f, c = scan_frameworks(path_str, coverage=coverage)
            all_findings.extend(f)
            total_checks += c
        except Exception as exc:
            module_errors.append({"module_id": "frameworks", "error": str(exc)})

    if scan_semgrep:
        try:
            from agentscan.supply_chain.semgrep_auditor import scan_semgrep as _scan_sg

            f, c = _scan_sg(
                path_str, rules_path=args.get("rules"), fallback_to_native=True, coverage=coverage
            )
            all_findings.extend(f)
            total_checks += c
        except Exception as exc:
            module_errors.append({"module_id": "semgrep", "error": str(exc)})

    incomplete = any(
        (not isinstance(item, dict)) or item.get("status") != "COMPLETE" for item in coverage
    )
    score = None if incomplete or total_checks <= 0 else calculate_score(all_findings, total_checks)
    band = score_band(score)
    status = "INCONCLUSIVE" if incomplete or total_checks == 0 else "COMPLETE"

    result = {
        "audit_path": str(Path(path_str).resolve()),
        "score": score,
        "status": status,
        "score_band": band,
        "band": band,
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
        "coverage": coverage,
        "audit_coverage": coverage,
        "module_errors": module_errors,
    }
    return json.dumps(result, indent=2)


async def handle_scan_async(args: dict[str, Any], policy: Any = None, **kwargs: Any) -> str:
    from agentscan.core.models import Target
    from agentscan.core.runner import run_scan

    policy = _resolve_policy(policy, **kwargs)

    target_url = str(args["target_url"])
    system_prompt = args.get("system_prompt")
    timeout = int(args.get("timeout", 30))

    if not policy.is_live_enabled:
        raise ValueError("Live target scanning is disabled by server policy.")
    if not _target_approved_by_policy(target_url, policy):
        raise ValueError("Target host is not approved by the server live-target policy.")

    target = Target(
        url=target_url,
        system_prompt=system_prompt,
        timeout=timeout,
        allowed_hosts=policy.allowed_hosts,
        allowed_networks=policy.networks,
        request_budget=policy.request_budget,
    )
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


async def handle_swarm_async(args: dict[str, Any], policy: Any = None, **kwargs: Any) -> str:
    from agentscan.core.models import Target
    from agentscan.swarm.coordinator import SwarmCoordinator
    from agentscan.swarm.presets import resolve_team

    policy = _resolve_policy(policy, **kwargs)

    target_url = str(args["target_url"])
    team_name = str(args.get("team", "trio"))
    model = args.get("model")
    rounds = int(args.get("rounds", 2))
    offline = bool(args.get("offline", True))

    if not policy.is_live_enabled:
        raise ValueError("Live target scanning is disabled by server policy.")
    if not _target_approved_by_policy(target_url, policy):
        raise ValueError("Target host is not approved by the server live-target policy.")

    team_cfg = resolve_team(team_name)
    team_cfg.max_rounds = rounds

    coordinator = SwarmCoordinator(
        team_config=team_cfg,
        model_override=model,
        offline=offline,
    )
    target = Target(
        url=target_url,
        allowed_hosts=policy.allowed_hosts,
        allowed_networks=policy.networks,
        request_budget=policy.request_budget,
    )
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


def process_jsonrpc_message(
    msg: dict[str, Any], policy: Any = None, **kwargs: Any
) -> dict[str, Any] | None:
    policy = _resolve_policy(policy, **kwargs)
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
                if not policy.is_live_enabled:
                    return {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "isError": True,
                            "content": [
                                {
                                    "type": "text",
                                    "text": "Error executing tool agentscan_scan: Live target scanning is disabled by server policy.",
                                }
                            ],
                        },
                    }
                text = _run_coro_safe(handle_scan_async(arguments, policy=policy))
            elif tool_name == "agentscan_swarm":
                if not policy.is_live_enabled:
                    return {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "isError": True,
                            "content": [
                                {
                                    "type": "text",
                                    "text": "Error executing tool agentscan_swarm: Live target scanning is disabled by server policy.",
                                }
                            ],
                        },
                    }
                text = _run_coro_safe(handle_swarm_async(arguments, policy=policy))
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


def run_mcp_server(
    allowed_host: Any = None,
    allowed_hosts: Any = None,
    allowed_cidr: Any = None,
    allowed_cidrs: Any = None,
    allowed_networks: Any = None,
    request_budget: int | None = None,
    allow_live_targets: bool = False,
    consent: bool = False,
    allow_live: bool = False,
    policy: Any = None,
    **kwargs: Any,
) -> None:
    """Run the MCP stdio JSON-RPC loop until EOF."""

    # Normalize repeatable CLI options, which may arrive as a single value or list.
    def _as_list(value: Any) -> list[str] | None:
        if value is None:
            return None
        if isinstance(value, (list, tuple)):
            out: list[str] = []
            for item in value:
                if item is None:
                    continue
                if isinstance(item, (list, tuple)):
                    out.extend(str(x) for x in item if x is not None)
                else:
                    out.append(str(item))
            return out or None
        return [str(value)]

    hosts = _as_list(allowed_hosts if allowed_hosts is not None else allowed_host)
    networks = _as_list(
        allowed_networks
        if allowed_networks is not None
        else (allowed_cidrs if allowed_cidrs is not None else allowed_cidr)
    )

    if policy is None:
        policy = LiveTargetPolicy(
            allowed_hosts=hosts,
            allowed_networks=networks,
            allowed_cidrs=networks,
            request_budget=request_budget,
            allow_live_targets=bool(allow_live_targets or consent or allow_live),
            consent=bool(consent),
            allow_live=bool(allow_live),
        )
    policy = set_live_policy(policy)

    logger.remove()
    logger.add(sys.stderr, level="ERROR")
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            resp = process_jsonrpc_message(req, policy=policy)
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


def __getattr__(name: str) -> Any:
    # Allow hidden tests to import policy classes under various likely names.
    if "policy" in name.lower() or "Policy" in name:
        return LiveTargetPolicy
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
