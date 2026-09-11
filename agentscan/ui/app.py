# agentscan/ui/app.py
#
# Local FastAPI dashboard for reports, RBAC graphs, trajectory/SSP, and traffic.

from __future__ import annotations

import json
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


def create_app(
    report_path: Path | None = None,
    identity_path: Path | None = None,
) -> Any:
    try:
        from fastapi import FastAPI, Query
        from fastapi.responses import FileResponse, JSONResponse
        from fastapi.staticfiles import StaticFiles
    except ImportError as e:
        raise RuntimeError(
            "The UI extra is not installed. Run: pip install 'agentscan[ui]' "
            "(or uv sync --extra ui)."
        ) from e

    app = FastAPI(title="AgentScan", docs_url=None, redoc_url=None)
    state.identity_path = identity_path
    state.load_report(report_path)

    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/")
    async def index() -> FileResponse:
        return FileResponse(
            STATIC_DIR / "index.html",
            headers={"Cache-Control": "no-store"},
        )

    @app.get("/api/report")
    async def api_report() -> JSONResponse:
        if state.report is None:
            return JSONResponse({"error": "no report loaded", "report": None}, status_code=200)
        return JSONResponse(state.report.to_dict())

    @app.get("/api/trajectory")
    async def api_trajectory() -> JSONResponse:
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
    async def api_traffic() -> JSONResponse:
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
    ) -> JSONResponse:
        root = path or (str(state.identity_path) if state.identity_path else None)
        if not root:
            return JSONResponse({"nodes": [], "edges": [], "path": None})
        agents = load_manifests(root)
        graph = build_rbac_graph(agents, load_role_policies(), load_dangerous_keywords())
        view = graph_to_view(graph)
        view["path"] = root
        view["agent_count"] = len(agents)
        return JSONResponse(view)

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
