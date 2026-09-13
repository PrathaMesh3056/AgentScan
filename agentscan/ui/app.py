# agentscan/ui/app.py
#
# Local FastAPI dashboard for reports, RBAC graphs, trajectory/SSP, and traffic.

from __future__ import annotations

import asyncio
import io
import json
import re
import zipfile
from collections.abc import AsyncGenerator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from loguru import logger

from agentscan.core.models import (
    Finding,
    Framework,
    ScanMode,
    ScanReport,
    SspClass,
    Target,
)
from agentscan.core.ssp_mapper import classify_ssp
from agentscan.core.trace import recorder
from agentscan.identity.manifest_loader import load_manifests
from agentscan.identity.permission_mapper import load_dangerous_keywords, load_role_policies
from agentscan.identity.rbac_graph import build_rbac_graph, graph_to_view
from agentscan.swarm.blackboard import SwarmBlackboard

STATIC_DIR = Path(__file__).resolve().parent / "static"


class UiState:
    def __init__(self) -> None:
        self.report_path: Path | None = None
        self.identity_path: Path | None = None
        self.report: ScanReport | None = None
        self.active_scan: asyncio.Task[Any] | None = None
        self.scan_status: dict[str, Any] = {
            "status": "idle",
            "target": None,
            "progress": 0,
            "current_module": None,
            "findings_count": 0,
        }
        self.swarm_blackboard: SwarmBlackboard = SwarmBlackboard()
        self.sentinel_status: dict[str, Any] = {
            "running": False,
            "target": None,
            "interval": 60,
            "canary_token": None,
            "webhook_url": None,
            "alerts": [],
        }
        self.sentinel_task: asyncio.Task[Any] | None = None
        self.audit_report: dict[str, Any] | None = None
        self.webhook_receiver_status: dict[str, Any] = {
            "status": "online",
            "port": 8766,
            "endpoint": "/webhook/alert",
            "recent_alerts": [],
        }

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
        q: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=256)
        self.subscribers.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue[dict[str, Any]]) -> None:
        if q in self.subscribers:
            self.subscribers.remove(q)

    async def publish(self, event: dict[str, Any]) -> None:
        dead: list[asyncio.Queue[dict[str, Any]]] = []
        for q in list(self.subscribers):
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                dead.append(q)
        for q in dead:
            self.subscribers.remove(q)


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

    from fastapi.middleware.cors import CORSMiddleware

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://127.0.0.1:8765", "http://localhost:8765"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.middleware("http")
    async def _localhost_only(request, call_next):
        host = getattr(request.client, "host", "127.0.0.1") if request.client else "127.0.0.1"
        if host not in ("127.0.0.1", "::1", "localhost", "testclient"):
            from fastapi.responses import JSONResponse as _JR

            return _JR({"error": "AgentScan dashboard is localhost-only"}, status_code=403)
        return await call_next(request)

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
    @app.get("/guardrails", include_in_schema=False)
    @app.get("/compliance", include_in_schema=False)
    @app.get("/heal", include_in_schema=False)
    @app.get("/healing", include_in_schema=False)
    @app.get("/team", include_in_schema=False)
    @app.get("/mcp", include_in_schema=False)
    @app.get("/sentinel", include_in_schema=False)
    @app.get("/audit", include_in_schema=False)
    @app.get("/benchmark", include_in_schema=False)
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

        items = state.swarm_blackboard.get_all_items()
        return JSONResponse(
            {
                "teams": teams_data,
                "blackboard": {
                    "items": [item.model_dump(mode="json") for item in items],
                    "summary": state.swarm_blackboard.get_summary(),
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

    @app.post("/api/scan")
    async def api_start_scan(payload: dict[str, Any]) -> Any:
        target_url = payload.get("target_url") or payload.get("target")
        if not target_url:
            return JSONResponse({"error": "target_url is required"}, status_code=400)
        if not re.match(r"^(https?|wss?|mcp(\+(sse|stdio))?)://", target_url):
            target_url = f"http://{target_url}"

        framework_val = payload.get("framework", "auto")
        try:
            framework = Framework(framework_val)
        except Exception:
            framework = Framework.AUTO

        modes = [ScanMode.SCAN]
        if payload.get("exploit"):
            modes.append(ScanMode.EXPLOIT)
        if payload.get("deep"):
            modes.append(ScanMode.DEEP)

        target_obj = Target(
            url=target_url,
            framework=framework,
            system_prompt=payload.get("system_prompt"),
            auth_header=payload.get("auth_header"),
            attacker_model=payload.get("attacker_model"),
            attacker_turns=payload.get("attacker_turns"),
            attacker_goal=payload.get("attacker_goal"),
            judge_model=payload.get("judge_model") or payload.get("attacker_model"),
            mutate=bool(payload.get("mutate", False)),
        )

        state.scan_status = {
            "status": "running",
            "target": target_url,
            "modes": [m.value for m in modes],
            "findings_count": 0,
            "progress": 5,
            "current_module": "Initializing scan orchestrator...",
        }
        await event_bus.publish({"type": "scan:start", "data": state.scan_status})

        async def _run_in_background() -> None:
            try:
                from agentscan.core.runner import run_scan_multi

                report = await run_scan_multi(target_obj, modes)
                state.report = report
                state.scan_status = {
                    "status": "completed",
                    "target": target_url,
                    "findings_count": len(report.findings),
                    "score": report.score,
                    "progress": 100,
                    "current_module": "Done",
                }
                await event_bus.publish(
                    {
                        "type": "scan:complete",
                        "data": {
                            "status": "completed",
                            "score": report.score,
                            "findings_count": len(report.findings),
                        },
                    }
                )
            except Exception as ex:
                logger.error(f"Background scan error: {ex}")
                state.scan_status = {
                    "status": "failed",
                    "target": target_url,
                    "error": str(ex),
                    "progress": 0,
                    "current_module": "Error",
                }
                await event_bus.publish(
                    {
                        "type": "scan:error",
                        "data": {"status": "failed", "error": str(ex)},
                    }
                )

        state.active_scan = asyncio.create_task(_run_in_background())
        return JSONResponse(
            {
                "status": "started",
                "scan_id": "active-scan-1",
                "target": target_url,
                "modes": [m.value for m in modes],
            }
        )

    @app.get("/api/scan/status")
    async def api_scan_status() -> Any:
        return JSONResponse(state.scan_status)

    @app.post("/api/scan/cancel")
    async def api_scan_cancel() -> Any:
        if state.active_scan and not state.active_scan.done():
            state.active_scan.cancel()
        state.scan_status["status"] = "cancelled"
        await event_bus.publish({"type": "scan:cancel", "data": {"status": "cancelled"}})
        return JSONResponse({"status": "cancelled"})

    @app.post("/api/discovery")
    async def api_discovery(payload: dict[str, Any]) -> Any:
        import yaml

        from agentscan.core.discovery import discover_http, discover_widget

        url = payload.get("url") or payload.get("target") or payload.get("target_url")
        if not url:
            return JSONResponse({"error": "url or target is required"}, status_code=400)
        if not (url.startswith("http://") or url.startswith("https://")):
            url = f"http://{url}"
        mode = payload.get("mode", "auto")
        test_message = payload.get("test_message", "Hello")
        no_exploit = bool(payload.get("no_exploit", False))

        scan_settings = {
            "exploit": not no_exploit,
            "verbose": True,
            "transcript": "transcript.txt",
            "output": "report.html",
        }
        profile: dict[str, Any] | None = None

        if mode in ("auto", "http"):
            try:
                api = await discover_http(url, test_message=test_message)
                if api is not None:
                    default_ok = api["message_path"] == "message" and api["response_path"].split(
                        "."
                    )[-1] in (
                        "response",
                        "text",
                        "message",
                        "output",
                        "content",
                        "raw",
                    )
                    profile = {"url": url}
                    if not default_ok:
                        profile["request_template"] = {
                            "method": "POST",
                            "url": url,
                            "json_body": api["json_body"],
                            "message_path": api["message_path"],
                            "response_path": api["response_path"],
                        }
                    profile.update(scan_settings)
            except Exception as e:
                logger.warning(f"HTTP discovery probe failed: {e}")

        if profile is None and mode in ("auto", "browser"):
            try:
                cfg = await discover_widget(url, headless=True, test_message=test_message)
                if cfg is not None:
                    browser_block = {
                        k: v
                        for k, v in {
                            "open_selector": cfg.open_selector,
                            "input_selector": cfg.input_selector,
                            "response_selector": cfg.response_selector,
                            "send_selector": cfg.send_selector,
                        }.items()
                        if v
                    }
                    profile = {"url": url, "browser": browser_block, **scan_settings}
            except Exception as e:
                logger.warning(f"Browser widget discovery failed: {e}")

        yaml_content = yaml.safe_dump(profile, sort_keys=False) if profile else ""
        endpoints = [url]
        if profile and "request_template" in profile:
            endpoints.append(profile["request_template"].get("url", url))

        return JSONResponse(
            {
                "success": profile is not None,
                "profile": profile,
                "yaml": yaml_content,
                "endpoints": endpoints,
                "routes": endpoints,
                "message": "Discovery completed"
                if profile
                else "Could not auto-detect chat API or browser widget.",
            }
        )

    @app.post("/api/discovery/save")
    async def api_discovery_save(payload: dict[str, Any]) -> Any:
        import json

        import yaml

        profile = payload.get("profile") or payload.get("manifest")
        out_path = Path(payload.get("output_path", "target.yaml"))
        resolved = out_path.resolve()
        cwd = Path.cwd().resolve()
        import tempfile

        temp_dir = Path(tempfile.gettempdir()).resolve()
        if not (str(resolved).startswith(str(cwd)) or str(resolved).startswith(str(temp_dir))):
            return JSONResponse(
                {"error": "output path must be within working directory"}, status_code=400
            )
        if not profile:
            return JSONResponse({"error": "profile or manifest data required"}, status_code=400)
        content = (
            json.dumps(profile, indent=2)
            if str(out_path).endswith(".json")
            else yaml.safe_dump(profile, sort_keys=False)
        )
        out_path.write_text(content, encoding="utf-8")
        return JSONResponse({"success": True, "saved_to": str(out_path)})

    @app.post("/api/audit")
    async def api_audit(payload: dict[str, Any]) -> Any:
        from agentscan.core.scorer import calculate_score, score_band

        path_str = payload.get("path", ".")
        offline = bool(payload.get("offline", True))
        show_transitive = bool(payload.get("show_transitive", True))

        scan_deps = bool(payload.get("scan_deps", True))
        scan_config = bool(payload.get("scan_config", True))
        scan_secrets = bool(payload.get("scan_secrets", True))
        scan_typo = bool(payload.get("scan_typo", True))
        scan_mcp = bool(payload.get("scan_mcp", True))
        scan_identity = bool(payload.get("scan_identity", True))
        scan_frameworks = bool(payload.get("scan_frameworks", True))
        scan_semgrep = bool(payload.get("scan_semgrep", False))

        all_findings: list[Finding] = []
        total_checks = 0

        if scan_deps:
            from agentscan.supply_chain.dep_scanner import scan_dependencies

            f, c = scan_dependencies(path_str, offline=offline, show_transitive=show_transitive)
            all_findings.extend(f)
            total_checks += c

        if scan_config:
            from agentscan.supply_chain.config_auditor import scan_config as _scan_cfg

            f, c = _scan_cfg(path_str)
            all_findings.extend(f)
            total_checks += c

        if scan_secrets:
            from agentscan.supply_chain.secret_scanner import scan_secrets as _scan_sec

            f, c = _scan_sec(path_str)
            all_findings.extend(f)
            total_checks += c

        if scan_typo:
            from agentscan.supply_chain.typosquat_detector import scan_typosquats

            f, c = scan_typosquats(path_str)
            all_findings.extend(f)
            total_checks += c

        if scan_mcp:
            from agentscan.supply_chain.mcp_auditor import scan_mcp_configs

            f, c = scan_mcp_configs(path_str)
            all_findings.extend(f)
            total_checks += c

        if scan_identity:
            from agentscan.identity.orchestrator import run_identity_audit

            rep = run_identity_audit(path_str)
            all_findings.extend(rep.findings)
            total_checks += max(len(rep.agents_found), 1)

        if scan_frameworks:
            from agentscan.supply_chain.framework_auditor import scan_frameworks as _scan_fw

            f, c = _scan_fw(path_str)
            all_findings.extend(f)
            total_checks += c

        if scan_semgrep:
            from agentscan.supply_chain.semgrep_auditor import scan_semgrep as _scan_sg

            f, c = _scan_sg(path_str, fallback_to_native=True)
            all_findings.extend(f)
            total_checks += c

        score = calculate_score(all_findings, max(total_checks, 1))
        band = score_band(score)

        state.audit_report = {
            "path": path_str,
            "findings": [f.model_dump(mode="json") for f in all_findings],
            "score": score,
            "band": band,
            "total_checks": total_checks,
        }
        await event_bus.publish(
            {
                "type": "audit:complete",
                "data": {"findings_count": len(all_findings), "score": score, "band": band},
            }
        )
        return JSONResponse(state.audit_report)

    @app.get("/api/aibom")
    async def api_aibom(
        path: str = Query(default=".", description="Project directory"),
    ) -> Any:
        from agentscan.supply_chain.aibom import build_cyclonedx_aibom

        bom = build_cyclonedx_aibom(path)
        return JSONResponse(bom)

    @app.get("/api/aibom/download")
    async def api_aibom_download(
        path: str = Query(default=".", description="Project directory"),
    ) -> Any:
        from agentscan.supply_chain.aibom import build_cyclonedx_aibom

        bom = build_cyclonedx_aibom(path)
        content = json.dumps(bom, indent=2).encode("utf-8")
        return StreamingResponse(
            io.BytesIO(content),
            media_type="application/json",
            headers={"Content-Disposition": 'attachment; filename="aibom.cdx.json"'},
        )

    @app.get("/api/dependencies/graph")
    async def api_dependencies_graph(
        path: str = Query(default=".", description="Project directory"),
    ) -> Any:
        from agentscan.supply_chain.dep_scanner import build_dependency_graph

        graph = build_dependency_graph(path)
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

    @app.post("/api/calibrate")
    async def api_calibrate(payload: dict[str, Any] | None = None) -> Any:
        from agentscan.core.calibration import run_calibration

        if payload is None:
            payload = {}
        attacker_model = payload.get("attacker_model") or payload.get("model") or "mock-model"
        attacker_goal = payload.get("attacker_goal")
        result = await run_calibration(attacker_model, attacker_goal=attacker_goal)
        return JSONResponse(
            {
                "passed": result.passed,
                "detail": result.detail,
                "baseline_latency_ms": getattr(result, "latency_ms", None),
                "target": payload.get("target") or "http://127.0.0.1:8765",
            }
        )

    @app.get("/api/benchmark")
    @app.post("/api/benchmark/run")
    async def api_benchmark(payload: dict[str, Any] | None = None) -> Any:
        from agentscan.core.benchmark import discriminates, run_benchmark

        rows = await run_benchmark()
        is_discriminating = discriminates(rows)
        return JSONResponse(
            {
                "discriminates": is_discriminating,
                "discrimination_score": (
                    round(sum(1 for r in rows if r.score < 80) / max(len(rows), 1), 2)
                    if rows
                    else 0.0
                ),
                "suites": (
                    sorted(set(getattr(r, "suite", "AGENT_BENCH_V1") for r in rows)) if rows else []
                ),
                "rows": [
                    {
                        "name": r.name,
                        "expectation": r.expectation,
                        "findings": r.findings,
                        "score": r.score,
                    }
                    for r in rows
                ],
            }
        )

    @app.get("/api/sentinel/status")
    @app.get("/api/sentinel")
    async def api_sentinel_status() -> Any:
        return JSONResponse(state.sentinel_status)

    @app.post("/api/sentinel/probe")
    async def api_sentinel_probe(payload: dict[str, Any] | None = None) -> Any:
        from agentscan.core.connectors import HttpJsonConnector
        from agentscan.sentinel.watcher import ContinuousWatcher

        if payload is None:
            payload = {}
        target_url = (
            payload.get("target_url") or payload.get("target") or "http://127.0.0.1:8765/chat"
        )

        canary_token = payload.get("canary_token")
        target = Target(url=target_url)
        watcher = ContinuousWatcher(
            target=target,
            canary_token=canary_token,
            webhook_url=payload.get("webhook_url"),
        )
        connector = HttpJsonConnector(target)
        findings = await watcher.run_iteration(connector)

        event = {
            "timestamp": datetime.now(UTC).isoformat(),
            "target": target_url,
            "findings_count": len(findings),
            "status": "ALERT" if findings else "PASS",
            "findings": [f.model_dump(mode="json") for f in findings],
        }
        state.sentinel_status["alerts"].insert(0, event)
        await event_bus.publish({"type": "sentinel:probe", "data": event})

        return JSONResponse(
            {
                "status": "ALERT" if findings else "PASS",
                "findings": [f.model_dump(mode="json") for f in findings],
                "canary_token": watcher.canary_sentinel.canary_token,
            }
        )

    @app.post("/api/sentinel/start")
    async def api_sentinel_start(payload: dict[str, Any] | None = None) -> Any:
        from agentscan.core.connectors import HttpJsonConnector
        from agentscan.sentinel.canary import generate_canary_token
        from agentscan.sentinel.watcher import ContinuousWatcher

        if payload is None:
            payload = {}
        target_url = (
            payload.get("target_url") or payload.get("target") or "http://127.0.0.1:8765/chat"
        )

        interval = int(payload.get("interval_seconds") or payload.get("interval") or 60)
        max_iters = payload.get("max_iterations")
        if max_iters is not None:
            max_iters = int(max_iters)

        canary_token = payload.get("canary_token") or generate_canary_token()
        webhook_url = payload.get("webhook_url")

        target = Target(url=target_url)
        watcher = ContinuousWatcher(
            target=target,
            interval_seconds=interval,
            max_iterations=max_iters,
            webhook_url=webhook_url,
            canary_token=canary_token,
        )
        connector = HttpJsonConnector(target)

        state.sentinel_status = {
            "running": True,
            "target": target_url,
            "interval": interval,
            "canary_token": canary_token,
            "webhook_url": webhook_url,
            "alerts": state.sentinel_status.get("alerts", []),
        }
        await event_bus.publish({"type": "sentinel:start", "data": state.sentinel_status})

        async def _watcher_loop() -> None:
            def _callback(cycle: int, f_list: list[Finding]) -> None:
                record = {
                    "timestamp": datetime.now(UTC).isoformat(),
                    "cycle": cycle,
                    "target": target_url,
                    "findings_count": len(f_list),
                    "status": "ALERT" if f_list else "PASS",
                    "findings": [f.model_dump(mode="json") for f in f_list],
                }
                state.sentinel_status["alerts"].insert(0, record)
                asyncio.create_task(event_bus.publish({"type": "sentinel:alert", "data": record}))

            try:
                await watcher.run_loop(connector, callback=_callback)
            except Exception as e:
                logger.error(f"Sentinel loop encountered error: {e}")
            finally:
                state.sentinel_status["running"] = False
                await event_bus.publish({"type": "sentinel:stop", "data": {"running": False}})

        state.sentinel_task = asyncio.create_task(_watcher_loop())
        return JSONResponse({"status": "started", "running": True, "canary_token": canary_token})

    @app.post("/api/sentinel/stop")
    async def api_sentinel_stop() -> Any:
        if state.sentinel_task and not state.sentinel_task.done():
            state.sentinel_task.cancel()
        state.sentinel_status["running"] = False
        await event_bus.publish({"type": "sentinel:stop", "data": {"running": False}})
        return JSONResponse({"status": "stopped", "running": False})

    @app.get("/api/mcp")
    async def api_mcp() -> Any:
        from agentscan.mcp.server import TOOLS_METADATA

        return JSONResponse(
            {
                "status": "ONLINE",
                "protocol_version": "2024-11-05",
                "transport": "stdio / JSON-RPC 2.0",
                "tools_count": len(TOOLS_METADATA),
                "tools": TOOLS_METADATA,
            }
        )

    @app.post("/api/mcp/invoke")
    async def api_mcp_invoke(payload: dict[str, Any]) -> Any:
        from agentscan.mcp.server import TOOLS_METADATA, process_jsonrpc_message

        tool_name = payload.get("name") or payload.get("tool")
        valid_names = {t["name"] for t in TOOLS_METADATA}
        if tool_name and tool_name not in valid_names:
            candidate = f"agentscan_{tool_name}"
            if candidate in valid_names:
                tool_name = candidate
            else:
                for vn in valid_names:
                    if tool_name in vn or vn.endswith(tool_name):
                        tool_name = vn
                        break

        arguments = payload.get("arguments", {})
        req = {
            "jsonrpc": "2.0",
            "id": payload.get("id", 1),
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments,
            },
        }
        res = process_jsonrpc_message(req)
        return JSONResponse(res)

    @app.post("/api/swarms/run")
    async def api_swarms_run(payload: dict[str, Any]) -> Any:
        from agentscan.swarm.coordinator import SwarmCoordinator
        from agentscan.swarm.presets import PRESETS, resolve_team

        target_url = (
            payload.get("target_url") or payload.get("target") or "http://127.0.0.1:8765/chat"
        )
        if not (target_url.startswith("http://") or target_url.startswith("https://")):
            target_url = f"http://{target_url}"

        team_name = payload.get("team") or payload.get("strategy") or "trio"
        team_lower = str(team_name).lower().strip()
        if team_lower in ("collaborative", "agency"):
            team_key = "agency"
        elif team_lower in ("adaptive", "stealth"):
            team_key = "stealth"
        elif team_lower in PRESETS or Path(str(team_name)).is_file():
            team_key = str(team_name)
        else:
            team_key = "trio"

        model = payload.get("model")
        rounds = payload.get("rounds") or payload.get("max_rounds")
        rounds_val = int(rounds) if rounds else None
        offline = bool(payload.get("offline", True))

        team_cfg = resolve_team(team_key)
        if rounds_val is not None:
            team_cfg.max_rounds = rounds_val

        coordinator = SwarmCoordinator(
            team_config=team_cfg,
            model_override=model,
            offline=offline,
        )
        coordinator.blackboard = state.swarm_blackboard
        target_obj = Target(url=target_url)

        def _on_turn(r_num: int, agent_name: str, record: Any) -> None:
            turn_data = {
                "round": r_num,
                "agent": agent_name,
                "role": record.agent_role.value
                if hasattr(record.agent_role, "value")
                else str(record.agent_role),
                "prompt": record.prompt,
                "intel_count": len(record.extracted_intel),
                "finding": record.finding.model_dump(mode="json") if record.finding else None,
            }
            asyncio.create_task(event_bus.publish({"type": "swarm:turn", "data": turn_data}))

        report = await coordinator.run_swarm(target_obj, callback=_on_turn)
        await event_bus.publish(
            {
                "type": "swarm:complete",
                "data": {
                    "score": report.score,
                    "findings_count": len(report.findings),
                    "turns_count": len(report.turns),
                },
            }
        )
        return JSONResponse(report.model_dump(mode="json"))

    @app.post("/api/swarms/blackboard/add")
    async def api_swarms_blackboard_add(payload: dict[str, Any]) -> Any:
        key = payload.get("key")
        value = payload.get("value")
        discovered_by = payload.get("discovered_by", "Operator")
        confidence = float(payload.get("confidence", 1.0))
        if not key or value is None:
            return JSONResponse({"error": "key and value are required"}, status_code=400)
        item = state.swarm_blackboard.add_intel(
            key, value, discovered_by=discovered_by, confidence=confidence
        )
        await event_bus.publish({"type": "swarm:intel", "data": item.model_dump(mode="json")})
        return JSONResponse(item.model_dump(mode="json"))

    @app.post("/api/swarms/blackboard/clear")
    async def api_swarms_blackboard_clear() -> Any:
        state.swarm_blackboard = SwarmBlackboard()
        await event_bus.publish({"type": "swarm:intel_clear", "data": {}})
        return JSONResponse({"status": "cleared", "items": [], "cleared": True})

    @app.post("/api/heal/apply")
    async def api_heal_apply(payload: dict[str, Any] | None = None) -> Any:
        from agentscan.remediation.engine import RemediationEngine

        findings = state.report.findings if state.report else []
        root = state.report_path.parent if state.report_path else Path(".")
        if payload and payload.get("root_path"):
            root = Path(payload["root_path"]).resolve()

        kinds = payload.get("kinds") if payload else None
        engine = RemediationEngine(root)
        plan = engine.plan(findings, kinds=kinds)
        engine.apply(plan)

        applied_actions = [
            {
                "finding_id": a.finding_id,
                "kind": a.kind,
                "path": str(a.path),
                "modified": a.before != a.after,
            }
            for a in plan.actions
        ]
        await event_bus.publish(
            {
                "type": "heal:applied",
                "data": {"applied_count": plan.applied_count, "actions": applied_actions},
            }
        )
        return JSONResponse(
            {
                "success": True,
                "applied": plan.applied_count > 0,
                "applied_count": plan.applied_count,
                "actions": applied_actions,
            }
        )

    @app.get("/api/heal/server/status")
    async def api_heal_server_status() -> Any:
        return JSONResponse(state.webhook_receiver_status)

    @app.post("/api/heal/server/simulate")
    async def api_heal_server_simulate(payload: dict[str, Any]) -> Any:
        from agentscan.remediation.engine import RemediationEngine
        from agentscan.remediation.patch_generator import (
            generate_github_pr_payload,
            generate_unified_patch,
        )
        from agentscan.remediation.webhook_receiver import AlertPayload, _parse_findings

        alert = AlertPayload.model_validate(payload)
        findings = _parse_findings(alert)
        root = Path(alert.target_repo).resolve()
        engine = RemediationEngine(root)
        plan = engine.plan(findings)
        patch = generate_unified_patch(plan, base_dir=root)
        pr_payload = generate_github_pr_payload(plan, branch_name=alert.branch_name)

        if alert.apply:
            engine.apply(plan)

        record = {
            "timestamp": datetime.now(UTC).isoformat(),
            "source": alert.source,
            "findings_count": len(findings),
            "actions_planned": plan.total_actions,
            "applied": alert.apply,
            "branch": alert.branch_name,
        }
        state.webhook_receiver_status["recent_alerts"].insert(0, record)
        await event_bus.publish({"type": "heal:alert_ingested", "data": record})

        return JSONResponse(
            {
                "status": "ingested",
                "actions_planned": plan.total_actions,
                "applied": alert.apply,
                "patch": patch,
                "pr_payload": pr_payload,
            }
        )

    @app.get("/api/vault/zip")
    async def api_vault_zip() -> Any:
        from agentscan.remediation.engine import RemediationEngine
        from agentscan.remediation.patch_generator import generate_unified_patch
        from agentscan.reporting.gateway_exporter import (
            export_bedrock_guardrails,
            export_cloudflare_guardrails,
            export_litellm_guardrails,
        )

        zip_buffer = io.BytesIO()
        findings = state.report.findings if state.report else []
        report_dict = state.report.to_dict() if state.report else {"findings": []}

        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
            zip_file.writestr("report.json", json.dumps(report_dict, indent=2))

            score_val = state.report.score if state.report else 100
            summary_md = [
                "# AgentScan Security Vault Export",
                f"**Generated:** {datetime.now(UTC).isoformat()}",
                f"**Target:** {state.report.target_url if state.report else 'Local Workspace'}",
                f"**Score:** {score_val}/100",
                f"**Total Findings:** {len(findings)}",
                "",
                "## Vulnerability Findings",
                "| Attack ID | Severity | OWASP ID | Name |",
                "|---|---|---|---|",
            ]
            for f in findings:
                summary_md.append(
                    f"| {f.attack_id} | {f.severity.value} | {f.owasp_id} | {f.attack_name} |"
                )
            zip_file.writestr("summary.md", "\n".join(summary_md))

            for f in findings:
                fname = f"findings/{f.attack_id}.json"
                zip_file.writestr(fname, json.dumps(f.model_dump(mode="json"), indent=2))

            root = state.report_path.parent if state.report_path else Path(".")
            engine = RemediationEngine(root)
            plan = engine.plan(findings)
            patch = generate_unified_patch(plan, base_dir=root)
            zip_file.writestr("remediation.patch", patch or "# No remediation diffs generated.\n")

            zip_file.writestr("guardrails/litellm.yaml", export_litellm_guardrails(findings))
            zip_file.writestr(
                "guardrails/cloudflare-waf.json", export_cloudflare_guardrails(findings)
            )
            zip_file.writestr(
                "guardrails/bedrock-guardrail.json", export_bedrock_guardrails(findings)
            )

        zip_buffer.seek(0)
        filename = f"agentscan-vault-{datetime.now(UTC).strftime('%Y-%m-%d')}.zip"
        return StreamingResponse(
            zip_buffer,
            media_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @app.post("/api/events")
    async def api_publish_event(payload: dict[str, Any]) -> Any:
        logger.debug("Internal event published via POST /api/events")
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
