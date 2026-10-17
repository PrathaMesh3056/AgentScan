"""Read-only dashboard capabilities and in-memory report downloads."""

from __future__ import annotations

import importlib.util
import json
from enum import StrEnum
from typing import Any

from fastapi import APIRouter
from fastapi.responses import JSONResponse, Response

from agentscan.ui.state import state

router = APIRouter(tags=["features"])

_OPTIONAL_RUNTIME = (
    (
        "deep",
        "Neural probes",
        ("torch", "transformers"),
        "uv sync --frozen --no-dev --extra ui --extra deep",
    ),
    (
        "browser",
        "Browser connector",
        ("playwright",),
        "uv sync --frozen --no-dev --extra ui --extra browser",
    ),
    (
        "semantic",
        "Semantic matching",
        ("sentence_transformers",),
        "uv sync --frozen --no-dev --extra ui --extra semantic",
    ),
    ("pdf", "PDF rendering", ("weasyprint",), "uv sync --frozen --no-dev --extra ui --extra pdf"),
    (
        "semgrep",
        "External Semgrep",
        ("semgrep",),
        "uv sync --frozen --no-dev --extra ui --extra semgrep",
    ),
)


def _module_available(module: str) -> bool:
    """Check optional modules without importing them or loading model weights."""
    try:
        return importlib.util.find_spec(module) is not None
    except (ImportError, ValueError, OSError):
        return False


def feature_manifest() -> dict[str, Any]:
    """Describe available controls without inspecting credentials or making requests."""
    runtime = []
    for feature_id, label, modules, install_command in _OPTIONAL_RUNTIME:
        missing = [module for module in modules if not _module_available(module)]
        runtime.append(
            {
                "id": feature_id,
                "label": label,
                "installed": not missing,
                "missing_packages": missing,
                "setup_command": install_command,
                "verified": False,
                "note": "Package presence only; model files, browser binaries and native libraries may still need setup. Repeat every extra you intend to retain when syncing; restart the dashboard after installation.",
            }
        )
    return {
        "runtime": runtime,
        "analysis_policy": {
            "default_mode": "deterministic",
            "default_classification": "sensitive",
            "sensitive_modes": ["deterministic", "local"],
            "external_requires": ["non_sensitive", "explicit_selection", "local_provider_key"],
            "external_providers": ["openai", "anthropic", "gemini"],
            "local_note": "Local analysis requires an installed offline Ollama model and local daemon; availability is not probed here.",
            "target_note": "The target connector still sends scan payloads to your selected target. Analysis mode controls analysis-provider access.",
        },
        "report": {
            "available": state.report is not None,
            "formats": ["json", "sarif", "html"],
            "download_url": "/api/report/download",
            "note": "Downloads contain the current scan report and evidence. Review before sharing.",
        },
        "workflows": [
            {"id": "scan", "label": "Endpoint scan", "surface": "dashboard", "action": "scan"},
            {
                "id": "mcp_inventory",
                "label": "Approved target MCP catalog comparison",
                "surface": "dashboard",
                "action": "scan",
                "note": "Optional approved catalog JSON selects ATK-006 only: initialize and list tools without invoking them. Requires an exact MCP SSE endpoint, standard mode and deterministic analysis. Catalog deviations are separate from target findings and have no security score; observed catalogs are never approved automatically.",
            },
            {
                "id": "audit",
                "label": "Source and dependency audit",
                "surface": "dashboard",
                "action": "audit",
            },
            {
                "id": "attacks",
                "label": "Attack catalogue and availability",
                "surface": "dashboard",
                "action": "pipelines",
            },
            {
                "id": "identity",
                "label": "Identity and permissions",
                "surface": "dashboard",
                "action": "identity",
            },
            {
                "id": "guardrails",
                "label": "Guardrail configuration export",
                "surface": "dashboard",
                "action": "guardrails",
            },
            {
                "id": "compliance",
                "label": "Findings to compliance mapping",
                "surface": "dashboard",
                "action": "compliance",
            },
            {
                "id": "heal",
                "label": "Remediation preview and apply",
                "surface": "dashboard",
                "action": "heal",
            },
            {
                "id": "swarm",
                "label": "Coordinated evaluation",
                "surface": "dashboard",
                "action": "team",
            },
            {
                "id": "sentinel",
                "label": "Canary monitoring",
                "surface": "dashboard",
                "action": "sentinel",
            },
            {
                "id": "mcp",
                "label": "AgentScan MCP tools",
                "surface": "dashboard",
                "action": "mcp",
                "note": "This panel exposes AgentScan's own tools through /api/mcp. Use the endpoint scan's approved catalog field to compare a target MCP server's tool inventory.",
            },
            {
                "id": "aibom",
                "label": "AI bill of materials",
                "surface": "dashboard",
                "action": "aibom",
            },
            {
                "id": "dependency_graph",
                "label": "Dependency graph",
                "surface": "dashboard",
                "action": "dependency_graph",
            },
            {
                "id": "profiles",
                "label": "Captured request and target profiles",
                "surface": "terminal",
                "command": "agentscan scan --config target.yaml",
                "note": "Use a local profile for custom message/response paths and captured authentication.",
            },
            {
                "id": "browser_scan",
                "label": "Browser widget scan",
                "surface": "terminal",
                "command": "agentscan scan --browser-url https://your-agent.example/chat --input-selector '#message' --response-selector '.reply' --completion-selector '.done'",
                "note": "Choose selectors for your own application; browser package and binaries are required.",
            },
            {
                "id": "transcript",
                "label": "Scan transcript and trajectory logs",
                "surface": "terminal",
                "command": "agentscan scan http://127.0.0.1:8000/chat --transcript transcript.json --trajectory-log trajectory.json",
                "note": "Logs may contain sensitive evidence. Store locally with suitable access controls.",
            },
            {
                "id": "remediation_plan",
                "label": "Remediation plan and Git integration",
                "surface": "terminal",
                "command": "agentscan fix --help",
                "note": "The fix command previews a plan by default. File changes and Git integration require explicit options; interrupted edits require recovery-journal review.",
            },
        ],
    }


@router.get("/api/features")
def api_features() -> Any:
    return JSONResponse(feature_manifest())


class ReportFormat(StrEnum):
    JSON = "json"
    SARIF = "sarif"
    HTML = "html"


@router.get("/api/report/download")
def api_report_download(format: ReportFormat = ReportFormat.JSON) -> Any:
    """Download only the current report, without accepting a file path."""
    report = state.report
    if report is None:
        return JSONResponse(
            {
                "error": "Run a scan or load a JSON scan report before downloading.",
                "field_errors": {"report": "No scan report is available."},
            },
            status_code=404,
        )
    headers = {
        "Content-Disposition": f'attachment; filename="agentscan-report.{format.value}"',
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "no-store",
    }
    if format == ReportFormat.HTML:
        from agentscan.reporting.html_report import render_html_report

        headers["Content-Security-Policy"] = (
            "sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'"
        )
        return Response(render_html_report(report), media_type="text/html", headers=headers)
    if format == ReportFormat.SARIF:
        from agentscan.reporting.sarif_report import to_sarif

        data = to_sarif(report)
        data["runs"][0]["properties"] = {
            "agentscanAssessment": {
                "status": report.status,
                "scope": report.assessment_scope,
                "score": report.score,
                "tests_selected": report.tests_selected,
                "tests_run": report.tests_run,
                "module_errors": report.module_errors,
                "module_outcomes": report.module_outcomes,
            }
        }
        data["runs"][0]["invocations"] = [{"executionSuccessful": report.status == "COMPLETE"}]
    else:
        data = report.to_dict()
    return Response(
        json.dumps(data, ensure_ascii=False, indent=2),
        media_type="application/json",
        headers=headers,
    )
