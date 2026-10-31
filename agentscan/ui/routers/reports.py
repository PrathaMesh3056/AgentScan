# agentscan/ui/routers/reports.py
#
# Core reporting endpoints: report data, trajectory/SSP, traffic logs, RBAC graphs,
# attack registry and guardrails export.

from __future__ import annotations

import asyncio
from typing import Any

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse

from agentscan.core.models import SspClass
from agentscan.core.ssp_mapper import classify_ssp
from agentscan.core.trace import recorder, redact_sensitive_data
from agentscan.identity.manifest_loader import load_manifests
from agentscan.identity.permission_mapper import load_dangerous_keywords, load_role_policies
from agentscan.identity.rbac_graph import build_rbac_graph, graph_to_view
from agentscan.ui.security import project_path
from agentscan.ui.state import state

router = APIRouter(tags=["reports"])

_cached_attacks: list[dict[str, Any]] | None = None


def _attack_catalog_response(attacks: list[dict[str, Any]]) -> JSONResponse:
    from agentscan.attacks.registry import registry

    errors = [
        {
            key: redact_sensitive_data(str(item.get(key, "")))[:512]
            for key in ("module_id", "module_name", "mode", "error")
        }
        for item in registry.load_errors[:100]
    ]
    return JSONResponse(
        {
            "count": len(attacks),
            "attacks": attacks,
            "load_errors": errors,
            "load_errors_count": len(registry.load_errors),
            "load_errors_truncated": len(registry.load_errors) > len(errors),
        }
    )


@router.get("/api/report")
async def api_report() -> Any:
    if state.report is None:
        return JSONResponse({"error": "no report loaded", "report": None}, status_code=200)
    return JSONResponse(state.report.to_dict())


@router.get("/api/trajectory")
async def api_trajectory() -> Any:
    report = state.report
    turns = [t.model_dump(mode="json") for t in (report.trajectory if report else [])]
    ssp = report.ssp_class if report else None
    reference_conversation = report is not None and any(
        item.get("assessment_scope") == "crescendo_complete_known_reference"
        for item in report.module_outcomes
    )
    if ssp is None and turns and not reference_conversation:
        from agentscan.core.models import TurnRecord

        ssp = classify_ssp([TurnRecord.model_validate(t) for t in turns])
    return JSONResponse(
        {
            "ssp_class": ssp.value if isinstance(ssp, SspClass) else ssp,
            "turns": turns,
        }
    )


@router.get("/api/traffic")
async def api_traffic() -> Any:
    traffic = state.scan_recorder or recorder
    entries = [
        {
            "seq": e.seq,
            "module_id": e.module_id,
            "module_name": e.module_name,
            "kind": e.kind,
            "request": e.request,
            "response": e.response,
            "timestamp": e.timestamp,
        }
        for e in traffic.entries
    ]
    return JSONResponse({"enabled": traffic.enabled, "entries": entries})


@router.get("/api/rbac")
async def api_rbac(
    request: Request,
    path: str | None = Query(default=None, description="Directory of *.agent.json manifests"),
) -> Any:
    root = (
        str(project_path(request, path))
        if path
        else (str(state.identity_path) if state.identity_path else None)
    )
    if not root:
        return JSONResponse(
            {"nodes": [], "edges": [], "path": None, "policies": {}, "escalations": []}
        )
    agents = load_manifests(root)
    role_policies = load_role_policies()
    dangerous_keywords = load_dangerous_keywords()
    graph = build_rbac_graph(agents, role_policies, dangerous_keywords)
    view = graph_to_view(graph)
    view["path"] = root
    view["agent_count"] = len(agents)
    view["policies"] = {
        r_name: p.model_dump(mode="json") if hasattr(p, "model_dump") else p
        for r_name, p in role_policies.items()
    }
    from agentscan.identity.rbac_graph import audit_rbac_graph

    escalations = audit_rbac_graph(agents, role_policies, dangerous_keywords)
    view["escalations"] = [
        e.model_dump(mode="json") if hasattr(e, "model_dump") else e for e in escalations
    ]
    return JSONResponse(view)


@router.get("/api/attacks")
async def api_attacks() -> Any:
    global _cached_attacks
    if _cached_attacks is not None:
        return _attack_catalog_response(_cached_attacks)

    from agentscan.attacks.registry import registry

    if not registry._loaded:
        await asyncio.to_thread(registry.load_all)
    modules = registry.get_all()
    modules_data = []
    for m in sorted(modules, key=lambda x: x.attack_id):
        doc = (
            (m.__doc__ or "").strip().split("\n")[0]
            if m.__doc__
            else "Adversarial evaluation module."
        )
        category = "SCAN"
        if hasattr(m, "__module__") and "." in m.__module__:
            category = m.__module__.split(".")[-2].upper()
        modules_data.append(
            {
                "attack_id": m.attack_id,
                "attack_name": m.attack_name,
                "owasp_id": m.owasp_id,
                "modes": [
                    mode.value if hasattr(mode, "value") else str(mode)
                    for mode in getattr(m, "supported_modes", [])
                ],
                "category": category,
                "description": doc,
            }
        )
    _cached_attacks = modules_data
    return _attack_catalog_response(modules_data)


@router.get("/api/guardrails")
async def api_guardrails() -> Any:
    from agentscan.reporting.gateway_exporter import (
        export_bedrock_guardrails,
        export_cloudflare_guardrails,
        export_litellm_guardrails,
    )

    findings = state.report.findings if state.report else []
    litellm_rules = export_litellm_guardrails(findings)
    cloudflare_rules = export_cloudflare_guardrails(findings)
    bedrock_rules = export_bedrock_guardrails(findings)
    return JSONResponse(
        {
            "litellm": litellm_rules,
            "cloudflare": cloudflare_rules,
            "bedrock": bedrock_rules,
            "findings_count": len(findings),
        }
    )
