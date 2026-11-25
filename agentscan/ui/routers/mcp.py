# agentscan/ui/routers/mcp.py
#
# Model Context Protocol (MCP) tool discovery and invocation endpoints.

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

from agentscan.ui.security import project_path
from agentscan.ui.status_labels import assess_mcp_tool_registration
from agentscan.ui.validation import Fields, directory_field, validation_error_response

router = APIRouter(tags=["mcp"])


@router.get("/api/mcp")
async def api_mcp() -> Any:
    from agentscan.mcp.server import TOOLS_METADATA

    return JSONResponse(
        {
            "status": "ONLINE",
            "protocol_version": "2024-11-05",
            "transport": "stdio / JSON-RPC 2.0",
            "tools_count": len(TOOLS_METADATA),
            # Registered metadata is not proof that a tool invocation succeeds.
            "tool_status": assess_mcp_tool_registration({"tools": TOOLS_METADATA}),
            "tools": TOOLS_METADATA,
        }
    )


@router.post("/api/mcp/invoke")
async def api_mcp_invoke(request: Request, payload: dict[str, Any]) -> Any:
    from agentscan.mcp.server import TOOLS_METADATA, process_jsonrpc_message

    fields = Fields(payload)
    tool_name = fields.text("name", required=True, max_length=128, aliases=("tool",))
    arguments = fields.object("arguments")
    valid_names = {t["name"] for t in TOOLS_METADATA}
    if tool_name == "scan_target":
        tool_name = "agentscan_scan"
    elif tool_name and tool_name not in valid_names:
        tool_name = f"agentscan_{tool_name}"
    if tool_name not in valid_names:
        fields.errors["name"] = "Choose an available MCP tool."
    req_id = payload.get("id", 1)
    if req_id is not None and type(req_id) not in (str, int):
        fields.errors["id"] = "Use a string or integer request ID."
    if error_response := fields.response():
        return error_response
    argument_fields = Fields(arguments)
    if tool_name == "agentscan_audit":
        path_value = argument_fields.text("path", default=".", required=True, max_length=4096)
        for key in ("offline", "show_transitive"):
            argument_fields.boolean(key, default=True)
        if not argument_fields.errors:
            resolved = directory_field(request, path_value, "arguments.path")
            if isinstance(resolved, JSONResponse):
                return resolved
            arguments = {**arguments, "path": resolved}
    elif tool_name in ("agentscan_scan", "agentscan_swarm"):
        schemes = (
            ("http", "https", "ws", "wss", "mcp+sse", "mcp+sses")
            if tool_name == "agentscan_scan"
            else ("http", "https")
        )
        target = argument_fields.url("target_url", schemes=schemes)
        if tool_name == "agentscan_scan":
            argument_fields.integer("timeout", 1, 300, default=30)
            argument_fields.text("system_prompt")
        else:
            team = argument_fields.text("team", default="trio", required=True, max_length=4096)
            argument_fields.integer("rounds", 1, 10, default=2)
            offline = argument_fields.boolean("offline", default=True)
            model = argument_fields.text("model", required=not offline, max_length=136)
            if not offline:
                from agentscan.core.ai_client import AIClientError, local_model_name

                try:
                    local_model_name(model or "")
                except AIClientError:
                    argument_fields.errors["model"] = (
                        "MCP swarm model analysis requires an installed offline ollama/model-name."
                    )
            if not argument_fields.errors and team not in ("trio", "agency", "stealth"):
                assert team is not None
                try:
                    team_path = project_path(request, team)
                except HTTPException as error:
                    return validation_error_response(
                        {
                            "arguments.team": "Choose a team YAML file within the configured project."
                        },
                        error.status_code,
                    )
                if not team_path.is_file() or team_path.suffix.lower() not in (".yml", ".yaml"):
                    argument_fields.errors["team"] = (
                        "Choose a swarm preset or an existing project YAML team file."
                    )
                else:
                    arguments = {**arguments, "team": str(team_path)}
        arguments = {**arguments, "target_url": target}
    if argument_fields.errors:
        return validation_error_response(
            {f"arguments.{key}": message for key, message in argument_fields.errors.items()}
        )
    req = {
        "jsonrpc": "2.0",
        "id": req_id,
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": arguments,
        },
    }
    res = process_jsonrpc_message(req)
    return JSONResponse(res)
