# agentscan/ui/app.py
#
# Local FastAPI dashboard for reports, RBAC graphs, trajectory/SSP, and traffic.

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncGenerator
from pathlib import Path
from typing import Any

from agentscan.core.models import ScanReport, SspClass
from agentscan.core.ssp_mapper import classify_ssp
from agentscan.core.trace import recorder
from agentscan.identity.manifest_loader import load_manifests
from agentscan.identity.permission_mapper import load_dangerous_keywords, load_role_policies
from agentscan.identity.rbac_graph import build_rbac_graph, graph_to_view

STATIC_DIR = Path(__file__).resolve().parent / "static"


class UiState:
    def __init__(self) -> None:
        self.report_path: Path | None = None
        self.identity_path: Path | None = None
        self.report: ScanReport | None = None

    def load_report(self, path: Path | None) -> ScanReport | None:
        self.report_path = path
        if path is None or not path.exists():
            self.report = None
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        self.report = ScanReport.model_validate(data)
        return self.report


state = UiState()


class EventBus:
    """In-memory publish/subscribe event bus for real-time dashboard updates."""

    def __init__(self) -> None:
        self.subscribers: list[asyncio.Queue[dict[str, Any]]] = []

    def subscribe(self) -> asyncio.Queue[dict[str, Any]]:
        q: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self.subscribers.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue[dict[str, Any]]) -> None:
        if q in self.subscribers:
            self.subscribers.remove(q)

    async def publish(self, event: dict[str, Any]) -> None:
        for q in list(self.subscribers):
            await q.put(event)


event_bus = EventBus()


def create_app(
    report_path: Path | None = None,
    identity_path: Path | None = None,
) -> Any:
    try:
        from fastapi import FastAPI, Query
        from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
        from fastapi.staticfiles import StaticFiles
    except ImportError as e:
        raise RuntimeError(
            "The UI extra is not installed. Run: pip install 'agentscan[ui]' "
            "(or uv sync --extra ui)."
        ) from e

    app = FastAPI(
        title="AgentScan API", docs_url="/docs", redoc_url="/redoc", openapi_url="/openapi.json"
    )
    state.identity_path = identity_path
    state.load_report(report_path)

    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/", include_in_schema=False)
    @app.get("/report", include_in_schema=False)
    @app.get("/overview", include_in_schema=False)
    @app.get("/pipelines", include_in_schema=False)
    @app.get("/findings", include_in_schema=False)
    @app.get("/trajectory", include_in_schema=False)
    @app.get("/rbac", include_in_schema=False)
    @app.get("/identity", include_in_schema=False)
    @app.get("/traffic", include_in_schema=False)
    @app.get("/compliance", include_in_schema=False)
    @app.get("/heal", include_in_schema=False)
    @app.get("/healing", include_in_schema=False)
    @app.get("/team", include_in_schema=False)
    async def index() -> Any:
        return FileResponse(
            STATIC_DIR / "index.html",
            headers={"Cache-Control": "no-store"},
        )

    @app.get("/api/docs", include_in_schema=False)
    async def api_docs_redirect() -> Any:
        from fastapi.responses import RedirectResponse

        return RedirectResponse(url="/docs")

    @app.get("/api/identity")
    async def api_identity(
        path: str | None = Query(default=None, description="Directory of *.agent.json manifests"),
    ) -> Any:
        root = path or (str(state.identity_path) if state.identity_path else None)
        if not root:
            return JSONResponse({"agents": [], "path": None, "count": 0})
        agents = load_manifests(root)
        return JSONResponse(
            {
                "path": root,
                "count": len(agents),
                "agents": [
                    a.model_dump(mode="json") if hasattr(a, "model_dump") else a for a in agents
                ],
            }
        )

    @app.get("/api/compliance")
    async def api_compliance() -> Any:
        from agentscan.reporting.compliance_pack import evaluate_eu_ai_act, evaluate_nist_ai_rmf

        findings = state.report.findings if state.report else []
        eu = evaluate_eu_ai_act(findings)
        nist = evaluate_nist_ai_rmf(findings)
        return JSONResponse(
            {
                "eu_ai_act": eu.model_dump(mode="json"),
                "nist_ai_rmf": nist.model_dump(mode="json"),
            }
        )

    @app.get("/api/heal")
    async def api_heal() -> Any:
        from agentscan.remediation.engine import RemediationEngine
        from agentscan.remediation.patch_generator import (
            generate_github_pr_payload,
            generate_unified_patch,
        )

        findings = state.report.findings if state.report else []
        root = state.report_path.parent if state.report_path else Path(".")
        engine = RemediationEngine(root)
        plan = engine.plan(findings)
        patch = generate_unified_patch(plan, base_dir=root)
        pr_payload = generate_github_pr_payload(plan)
        return JSONResponse(
            {
                "total_actions": plan.total_actions,
                "paths_affected": plan.paths_affected,
                "actions": [a.model_dump(mode="json") for a in plan.actions],
                "patch": patch,
                "pr_payload": pr_payload,
            }
        )

    @app.get("/api/report")
    async def api_report() -> Any:
        if state.report is None:
            return JSONResponse({"error": "no report loaded", "report": None}, status_code=200)
        return JSONResponse(state.report.to_dict())

    @app.get("/api/trajectory")
    async def api_trajectory() -> Any:
        report = state.report
        turns = [t.model_dump(mode="json") for t in (report.trajectory if report else [])]
        ssp = report.ssp_class if report else None
        if ssp is None and turns:
            from agentscan.core.models import TurnRecord

            ssp = classify_ssp([TurnRecord.model_validate(t) for t in turns])
        return JSONResponse(
            {
                "ssp_class": ssp.value if isinstance(ssp, SspClass) else ssp,
                "turns": turns,
            }
        )

    @app.get("/api/traffic")
    async def api_traffic() -> Any:
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
            for e in recorder.entries
        ]
        return JSONResponse({"enabled": recorder.enabled, "entries": entries})

    @app.get("/api/rbac")
    async def api_rbac(
        path: str | None = Query(default=None, description="Directory of *.agent.json manifests"),
    ) -> Any:
        root = path or (str(state.identity_path) if state.identity_path else None)
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

    @app.get("/api/attacks")
    async def api_attacks() -> Any:
        from agentscan.attacks.registry import registry

        registry.load_all()
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
        return JSONResponse({"count": len(modules_data), "attacks": modules_data})

    @app.get("/api/guardrails")
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

    @app.get("/api/swarms")
    async def api_swarms() -> Any:
        from agentscan.swarm.blackboard import SwarmBlackboard
        from agentscan.swarm.presets import PRESETS

        teams_data = {}
        for key, team in PRESETS.items():
            teams_data[key] = {
                "key": key,
                "name": team.name,
                "strategy": team.strategy.value
                if hasattr(team.strategy, "value")
                else str(team.strategy),
                "default_model": team.default_model,
                "max_rounds": team.max_rounds,
                "agents": [
                    {
                        "name": a.name,
                        "role": a.role.value if hasattr(a.role, "value") else str(a.role),
                        "model": a.model or team.default_model,
                    }
                    for a in team.agents
                ],
            }

        blackboard = SwarmBlackboard()
        blackboard.add_intel(
            "target_surface",
            "REST /chat endpoint with tool invocation",
            discovered_by="Recon-Alpha",
        )
        blackboard.add_intel(
            "vulnerability_vector",
            "Multi-turn persona escalation bypass",
            discovered_by="Bypass-Echo",
        )
        blackboard.add_intel(
            "escalation_target",
            "Database admin tool with execute_raw_sql",
            discovered_by="Exploit-Omega",
        )
        return JSONResponse(
            {
                "teams": teams_data,
                "blackboard": {
                    "items": [item.model_dump(mode="json") for item in blackboard.get_all_items()],
                    "summary": blackboard.get_summary(),
                },
            }
        )

    @app.get("/api/certificate")
    async def api_certificate(
        secret_key: str | None = Query(default=None, description="Optional HMAC key"),
    ) -> Any:
        from agentscan.reporting.audit_verifier import sign_audit_report

        if state.report is None:
            return JSONResponse({"error": "no report loaded", "certificate": None}, status_code=200)
        cert = sign_audit_report(state.report.to_dict(), secret_key=secret_key)
        return JSONResponse(cert)

    @app.post("/api/verify-certificate")
    async def api_verify_certificate(payload: dict[str, Any]) -> Any:
        from agentscan.reporting.audit_verifier import verify_audit_certificate

        report_data = payload.get("report") or (state.report.to_dict() if state.report else {})
        certificate_data = payload.get("certificate")
        secret_key = payload.get("secret_key")
        if not certificate_data:
            return JSONResponse(
                {"valid": False, "reason": "Certificate data required in payload"}, status_code=400
            )
        is_valid, reason = verify_audit_certificate(
            report_data, certificate_data, secret_key=secret_key
        )
        return JSONResponse({"valid": is_valid, "reason": reason})

    @app.get("/api/events")
    async def api_events(limit: int | None = None) -> Any:
        """Stream real-time scan findings, traffic, and sentinel alerts via SSE."""
        q = event_bus.subscribe()

        async def event_generator() -> AsyncGenerator[str, None]:
            count = 0
            try:
                # Send initial ping event to confirm connection
                yield "event: ping\ndata: {}\n\n"
                count += 1
                if limit is not None and count >= limit:
                    return

                while True:
                    try:
                        event = await asyncio.wait_for(q.get(), timeout=15.0)
                        event_type = event.get("type", "message")
                        data_str = json.dumps(event.get("data", {}))
                        yield f"event: {event_type}\ndata: {data_str}\n\n"
                        count += 1
                        if limit is not None and count >= limit:
                            return
                    except TimeoutError:
                        yield ": keep-alive\n\n"
            except asyncio.CancelledError:
                pass
            finally:
                event_bus.unsubscribe(q)

        return StreamingResponse(
            event_generator(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    @app.post("/api/events")
    async def api_publish_event(payload: dict[str, Any]) -> Any:
        await event_bus.publish(payload)
        return JSONResponse({"status": "ok"})

    @app.post("/api/reload")
    async def api_reload() -> Any:
        if state.report_path:
            state.load_report(state.report_path)
            await event_bus.publish({"type": "reload", "data": {"status": "reloaded"}})
        return JSONResponse({"status": "reloaded"})

    return app


def build_uvicorn_config(app: Any, host: str = "127.0.0.1", port: int = 8765) -> Any:
    """In-process uvicorn config for the local dashboard (single worker, no reload)."""
    try:
        import uvicorn
    except ImportError as e:
        raise RuntimeError(
            "The UI extra is not installed. Run: pip install 'agentscan[ui]' "
            "(or uv sync --extra ui)."
        ) from e

    return uvicorn.Config(
        app,
        host=host,
        port=port,
        log_level="warning",
        reload=False,
        workers=1,
        access_log=False,
        lifespan="on",
    )


def serve_app(app: Any, host: str = "127.0.0.1", port: int = 8765) -> None:
    """Serve the dashboard with uvicorn in-process (single worker, no reload)."""
    config = build_uvicorn_config(app, host=host, port=port)
    import uvicorn

    uvicorn.Server(config).run()
