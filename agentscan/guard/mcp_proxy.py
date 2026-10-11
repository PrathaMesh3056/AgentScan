# agentscan/guard/mcp_proxy.py
#
# Transparent MCP JSON-RPC 2.0 stdio capability proxy.

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from agentscan.guard.command import CommandSecurityError, PosixCommandGuard
from agentscan.guard.firewall import CapabilityGuard
from agentscan.guard.path import CanonicalPathGuard, PathSecurityError

ARG_KEY_INSPECTION_PATTERN = re.compile(
    r"path|file|dir|directory|uri|url|location|src|dest|destination|target",
    re.IGNORECASE,
)

PATH_PREFIX_TUPLE = ("/", "\\", "../", "..\\", "./", ".\\")


class MCPCapabilityProxy:
    """
    Universal JSON-RPC 2.0 proxy for Model Context Protocol stdio streams.

    Intercepts all 'tools/call' requests regardless of tool name and validates
    all argument keys and path-like values against containment and command boundaries.
    """

    def __init__(
        self,
        workspace_root: str | Path,
        allowed_binaries: Sequence[str] | None = None,
        allowed_domains: Sequence[str] | None = None,
    ) -> None:
        """
        Initialize the MCP capability proxy with containment guards.

        Parameters
        ----------
        workspace_root : str | Path
            Directory boundary for filesystem containment.
        allowed_binaries : Sequence[str] | None
            Optional allowlist of binary commands for execution tools.
        allowed_domains : Sequence[str] | None
            Optional allowlist of external domains for network requests.
        """
        self.workspace_root: Path = Path(workspace_root).resolve()
        self.path_guard = CanonicalPathGuard(self.workspace_root)
        self.cmd_guard = PosixCommandGuard(allowed_binaries) if allowed_binaries else None
        self.allowed_domains = set(allowed_domains or [])
        self.capability_guard = CapabilityGuard(
            allowed_root=self.workspace_root,
            allowed_domains=allowed_domains,
            disallow_shell_metachars=False,
        )

    def process_request(self, json_rpc_line: str) -> str | None:
        """
        Processes an incoming JSON-RPC 2.0 message string.

        Parameters
        ----------
        json_rpc_line : str
            A single-line JSON-RPC request.

        Returns
        -------
        str | None
            Structured JSON error response string if a policy violation occurs;
            None if the payload is clean and permitted to pass through.
        """
        try:
            req = json.loads(json_rpc_line)
        except json.JSONDecodeError:
            return None

        if not isinstance(req, dict) or req.get("method") != "tools/call":
            return None

        req_id = req.get("id")
        params = req.get("params", {})
        if not isinstance(params, dict):
            return self._build_error_response(
                req_id, "Malformed tool call parameters", "Use an object for params."
            )

        args = params.get("arguments", {})
        if not isinstance(args, dict):
            return self._build_error_response(
                req_id, "Malformed tool arguments", "Use an object for arguments."
            )

        violation = self.capability_guard.inspect_parameters(args)
        if violation is not None:
            details = json.loads(violation)
            parameter = details.get("parameter", "arguments")
            parameter = re.sub(r"\.(\d+)(?=\.|$)", r"[\1]", parameter)
            return self._build_error_response(
                req_id, violation, f"Use approved paths and network domains in '{parameter}'."
            )

        # Inspect every argument across all argument keys (including nested structures)
        flattened_args = self._flatten_arguments(args)
        for key, val in flattened_args:
            if not isinstance(val, str):
                continue

            violation = self._evaluate_argument(req_id, key, val)
            if violation is not None:
                return violation

        return None

    def _flatten_arguments(self, obj: Any, prefix: str = "") -> list[tuple[str, Any]]:
        """Recursively flattens nested dictionary and list arguments."""
        items: list[tuple[str, Any]] = []
        if isinstance(obj, dict):
            for k, v in obj.items():
                full_key = f"{prefix}.{k}" if prefix else str(k)
                items.append((full_key, v))
                if isinstance(v, (dict, list)):
                    items.extend(self._flatten_arguments(v, full_key))
        elif isinstance(obj, list):
            for idx, item in enumerate(obj):
                item_key = f"{prefix}[{idx}]"
                items.append((item_key, item))
                if isinstance(item, (dict, list)):
                    items.extend(self._flatten_arguments(item, item_key))
        return items

    def _evaluate_argument(self, req_id: Any, key: str, val: str) -> str | None:
        """Evaluates a single argument string against path containment and command security."""
        # 1. Path containment check
        if self._should_inspect_as_path(key, val) and not self.capability_guard._is_url_or_domain(
            key, val
        ):
            try:
                self.path_guard.resolve_safe(val)
            except PathSecurityError as err:
                return self._build_error_response(
                    req_id=req_id,
                    error_message=f"Security Policy Error: {err}.",
                    instruction=(
                        f"Path traversal detected in argument '{key}'. "
                        f"Access outside workspace '{self.workspace_root}' is denied. "
                        "Please re-plan using paths within the workspace."
                    ),
                )

        # 2. Command security check
        if self._should_inspect_as_command(key):
            if self.cmd_guard is None:
                return self._build_error_response(
                    req_id,
                    "No command execution policy configured",
                    "Use a tool without command execution.",
                )
            try:
                self.cmd_guard.sanitize_command(val)
            except CommandSecurityError as err:
                return self._build_error_response(
                    req_id=req_id,
                    error_message=f"Command Security Policy Error: {err}.",
                    instruction=(
                        f"Disallowed command or shell metacharacter in '{key}'. "
                        "Please re-plan with permitted direct commands."
                    ),
                )

        return None

    def _should_inspect_as_path(self, key: str, val: str) -> bool:
        """Determines whether an argument should undergo filesystem containment check."""
        if ARG_KEY_INSPECTION_PATTERN.search(key):
            return True
        return val.startswith(PATH_PREFIX_TUPLE) or bool(re.match(r"^[a-zA-Z]:[/\\]", val))

    def _should_inspect_as_command(self, key: str) -> bool:
        """Determines whether an argument key represents a shell/system command."""
        lower_key = key.lower()
        return any(term in lower_key for term in ("command", "cmd", "exec", "script", "bash", "sh"))

    def _build_error_response(
        self,
        req_id: Any,
        error_message: str,
        instruction: str,
    ) -> str:
        """Constructs an RFC-compliant MCP JSON-RPC error result."""
        return json.dumps(
            {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": f"{error_message} Action blocked. Please re-plan.",
                        }
                    ],
                    "isError": True,
                    "instruction_for_agent": instruction,
                },
            }
        )
