# agentscan/ui/routers/audit.py
#
# Supply-chain and static code audit endpoints, AIBOM generation and dependency graphs.

from __future__ import annotations

import asyncio
import io
import json
from typing import Any

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse, StreamingResponse

from agentscan.ui.state import event_bus, state
from agentscan.ui.validation import Fields, directory_field

router = APIRouter(tags=["audit"])


@router.post("/api/audit")
async def api_audit(request: Request, payload: dict[str, Any]) -> Any:
    fields = Fields(payload)
    path_value = fields.text("path", default=".", required=True, max_length=4096)
    fields.choice("ruleset", ("default",), default="default")
    offline = fields.boolean("offline", default=True)
    show_transitive = fields.boolean("show_transitive", default=True)
    checks = {
        key: fields.boolean(key, default=key != "scan_semgrep")
        for key in (
            "scan_deps",
            "scan_config",
            "scan_secrets",
            "scan_typo",
            "scan_mcp",
            "scan_identity",
            "scan_frameworks",
            "scan_semgrep",
        )
    }
    if not any(checks.values()):
        fields.errors["ruleset"] = "Select at least one audit check."
    if error_response := fields.response():
        return error_response
    resolved = directory_field(request, path_value)
    if isinstance(resolved, JSONResponse):
        return resolved
    path_str = resolved

    # One shared orchestration path with the CLI and MCP server.
    from agentscan.reporting.audit_runner import run_static_audit

    selected = [key for key, enabled in checks.items() if enabled]
    run = await asyncio.to_thread(
        run_static_audit,
        path_str,
        selected,
        offline=offline,
        show_transitive=show_transitive,
    )
    report_data = run.payload()
    report_data["band"] = run.risk_band
    report_data["findings"] = [f.model_dump(mode="json") for f in run.findings]
    state.audit_report = report_data
    await event_bus.publish(
        {
            "type": "audit:complete",
            "data": {
                "findings_count": len(run.findings),
                "score": run.score,
                "band": run.risk_band,
                "status": run.status,
            },
        }
    )
    return JSONResponse(state.audit_report)


@router.get("/api/aibom")
async def api_aibom(
    request: Request,
    path: str = Query(default=".", description="Project directory"),
) -> Any:
    from agentscan.supply_chain.aibom import build_cyclonedx_aibom

    fields = Fields({"path": path})
    value = fields.text("path", required=True, max_length=4096)
    if error_response := fields.response():
        return error_response
    resolved = directory_field(request, value)
    if isinstance(resolved, JSONResponse):
        return resolved
    bom = build_cyclonedx_aibom(resolved)
    return JSONResponse(bom)


@router.get("/api/aibom/download")
async def api_aibom_download(
    request: Request,
    path: str = Query(default=".", description="Project directory"),
) -> Any:
    from agentscan.supply_chain.aibom import build_cyclonedx_aibom

    fields = Fields({"path": path})
    value = fields.text("path", required=True, max_length=4096)
    if error_response := fields.response():
        return error_response
    resolved = directory_field(request, value)
    if isinstance(resolved, JSONResponse):
        return resolved
    bom = build_cyclonedx_aibom(resolved)
    content = json.dumps(bom, indent=2).encode("utf-8")
    return StreamingResponse(
        io.BytesIO(content),
        media_type="application/json",
        headers={"Content-Disposition": 'attachment; filename="aibom.cdx.json"'},
    )


@router.get("/api/dependencies/graph")
async def api_dependencies_graph(
    request: Request,
    path: str = Query(default=".", description="Project directory"),
) -> Any:
    from agentscan.supply_chain.dep_scanner import build_dependency_graph

    fields = Fields({"path": path})
    value = fields.text("path", required=True, max_length=4096)
    if error_response := fields.response():
        return error_response
    resolved = directory_field(request, value)
    if isinstance(resolved, JSONResponse):
        return resolved
    graph = build_dependency_graph(resolved)
    nodes = []
    for n, d in graph.nodes(data=True):
        nodes.append(
            {
                "id": n,
                "label": n,
                "version": d.get("version", ""),
                "is_root": d.get("is_root", False),
            }
        )
    edges = [{"source": u, "target": v} for u, v in graph.edges()]
    return JSONResponse(
        {
            "nodes": nodes,
            "edges": edges,
            "node_count": len(nodes),
            "edge_count": len(edges),
        }
    )
