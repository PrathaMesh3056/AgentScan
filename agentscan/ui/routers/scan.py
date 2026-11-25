# agentscan/ui/routers/scan.py
#
# Endpoints for initiating scans, monitoring status, cancelling, and discovering targets.

from __future__ import annotations

import asyncio
import json
import re
import uuid
from pathlib import Path
from typing import Any

import yaml
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from loguru import logger
from pydantic import ValidationError

from agentscan.core.ai_client import AIClientError
from agentscan.core.factuality import FactualityBaseline, unique_json_object
from agentscan.core.mcp_inventory import McpInventoryBaseline
from agentscan.core.models import Framework, ScanMode, Target
from agentscan.ui.state import SCAN_RUNNING, event_bus, state
from agentscan.ui.validation import Fields, model_field_errors, validation_error_response

router = APIRouter(tags=["scan"])


def _operation_failure(error: Exception, operation: str) -> dict[str, str]:
    """Return bounded known guidance and a reference without echoing exception data."""
    import httpx

    from agentscan.core.outcomes import ModuleUnavailableError, TargetRequestError

    reference = uuid.uuid4().hex[:12]
    code = "UNEXPECTED_FAILURE"
    message = "The operation failed unexpectedly. Review the terminal diagnostic reference before retrying."
    status = None
    if isinstance(error, httpx.HTTPStatusError):
        status = error.response.status_code
    elif isinstance(error, TargetRequestError):
        matched = re.fullmatch(r"Target returned HTTP ([1-5][0-9]{2})", str(error))
        if matched:
            status = int(matched.group(1))
        else:
            code = "TARGET_REQUEST_FAILED"
            message = "The target request could not be evaluated. Check the endpoint, target authentication and request format."
    if status is not None:
        code = f"HTTP_{status}"
        guidance = {
            401: "The target rejected authentication (HTTP 401). Check its target authentication header; an analysis-provider key does not authenticate a different target.",
            403: "The target denied access (HTTP 403). Check target permissions and whether this endpoint allows scan requests.",
            404: "The target route was not found (HTTP 404). Use the chat API endpoint rather than its dashboard or login page.",
            405: "The target rejected the request method (HTTP 405). Check its API contract and use a captured request profile when required.",
            422: "The target rejected the request body (HTTP 422). Check its message schema and use a captured request profile when required.",
            429: "The target rate limit was reached (HTTP 429). Allow it to recover and reduce request concurrency before retrying.",
        }
        message = guidance.get(
            status,
            f"The target returned HTTP {status}. Check target availability and its API contract before retrying.",
        )
    elif isinstance(error, httpx.TimeoutException):
        code = "REQUEST_TIMEOUT"
        message = "The request timed out. Check service availability and the target response deadline before retrying."
    elif isinstance(error, httpx.ConnectError):
        code = "CONNECTION_FAILED"
        message = "A connection could not be established. Check the endpoint, service availability and network configuration."
    elif isinstance(error, ModuleUnavailableError):
        code = "COMPONENT_UNAVAILABLE"
        message = "A required scan component is unavailable. Review installed runtime dependencies and local model configuration."
    elif isinstance(error, ModuleNotFoundError):
        code = "COMPONENT_UNAVAILABLE"
        message = "A required Python package is unavailable. Review the feature guide and install the required optional runtime."
        if error.name == "playwright":
            message = "Browser discovery requires Playwright and browser binaries. Run uv sync --frozen --no-dev --extra ui --extra browser while retaining any other installed extras, then python -m playwright install chromium. Restart the dashboard after setup."
    elif isinstance(error, AIClientError):
        code = "ANALYSIS_UNAVAILABLE"
        message = "Model analysis is unavailable. Check the selected analysis mode, locally configured credentials or installed offline model. Sensitive scans must stay deterministic or local."
    logger.error(
        "Dashboard {} failed [reference {}]: {}", operation, reference, type(error).__name__[:80]
    )
    return {"error": message, "error_id": reference, "error_code": code}


@router.post("/api/scan")
async def _api_start_scan_request(request: Request, payload: dict[str, Any]) -> Any:
    """Reject ambiguous JSON before approved-answer checks can start."""

    try:
        json.loads(await request.body(), object_pairs_hook=unique_json_object)
    except (ValueError, UnicodeDecodeError, RecursionError):
        field = "factuality_baseline" if "factuality_baseline" in payload else "target_url"
        return validation_error_response(
            {field: "Use valid JSON with unique object keys; duplicate keys are not accepted."}
        )
    return await api_start_scan(payload)


async def api_start_scan(payload: dict[str, Any]) -> Any:
    if state.scan_in_progress():
        return JSONResponse({"error": "A dashboard scan is already running"}, status_code=409)
    fields = Fields(payload)
    target_url = fields.url(
        "target_url",
        aliases=("target",),
        schemes=("http", "https", "ws", "wss", "mcp+sse", "mcp+sses"),
    )
    framework_val = fields.choice("framework", tuple(f.value for f in Framework), default="auto")
    concurrency = fields.integer("concurrency", 1, 100, default=4)
    mode = fields.choice("mode", ("FAST", "ACTIVE", "DEEP"), default="FAST")
    exploit = fields.boolean("exploit")
    deep = fields.boolean("deep")
    mutate = fields.boolean("mutate")
    indirect_adapter = fields.choice("indirect_adapter", ("none", "document_v1"), default="none")
    analysis = fields.analysis()
    optional_text = {
        key: fields.text(key)
        for key in (
            "system_prompt",
            "auth_header",
            "attacker_model",
            "attacker_goal",
            "judge_model",
        )
    }
    optional_text["auth_header"] = fields.header("auth_header")
    canary_token = fields.text("canary_token", max_length=128)
    if canary_token and not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", canary_token):
        fields.errors["canary_token"] = (
            "Use a synthetic reference of 16–128 letters, numbers, underscores or hyphens, "
            "already provisioned privately on the target. Leave empty if unavailable."
        )
    attacker_turns = fields.integer("attacker_turns", 1, 20)
    baseline = None
    factuality = None
    raw_factuality = fields.value("factuality_baseline")
    if "factuality_baseline" in payload and raw_factuality is not None:
        try:
            if (
                not isinstance(raw_factuality, dict)
                or len(
                    json.dumps(raw_factuality, ensure_ascii=False, allow_nan=False).encode("utf-8")
                )
                > 262144
            ):
                raise ValueError
            factuality = FactualityBaseline.model_validate(raw_factuality)
        except (ValidationError, ValueError, TypeError, RecursionError):
            fields.errors["factuality_baseline"] = (
                "Provide approved answer-check JSON of at most 256 KB with schema_version "
                "agentscan.factuality.v1, the exact HTTP(S) target_url, and 1–16 unique ASCII "
                "case IDs. Each case requires a question (1–2048 characters), expected_answer "
                "and a different false_answer (1–512 characters each). Extra keys are not accepted."
            )
        if factuality is not None and (
            target_url is None
            or target_url != factuality.target_url
            or not target_url.startswith(("http://", "https://"))
            or mode != "FAST"
            or exploit
            or deep
            or mutate
            or indirect_adapter != "none"
            or analysis["analysis_mode"] != "deterministic"
            or fields.value("mcp_inventory_baseline") is not None
            or any(optional_text[key] for key in ("attacker_model", "attacker_goal", "judge_model"))
            or attacker_turns is not None
            or any(payload.get(key) is not None for key in ("browser", "request_template"))
            or (
                payload.get("retry_state_changing_requests") is not None
                and payload.get("retry_state_changing_requests") is not False
            )
        ):
            fields.errors["factuality_baseline"] = (
                "Approved answer checks require the exact HTTP(S) endpoint, standard mode and "
                "deterministic analysis, without MCP catalog checks, active/deep probes, mutation, "
                "document adapters, browser/captured-request overrides, state-changing retries "
                "or attacker/judge settings."
            )
    raw_baseline = fields.value("mcp_inventory_baseline")
    if raw_baseline is not None:
        try:
            if (
                not isinstance(raw_baseline, dict)
                or len(
                    json.dumps(raw_baseline, ensure_ascii=False, allow_nan=False).encode("utf-8")
                )
                > 262144
            ):
                raise ValueError
            baseline = McpInventoryBaseline.model_validate(raw_baseline)
        except (ValidationError, ValueError, TypeError, RecursionError):
            fields.errors["mcp_inventory_baseline"] = (
                "Provide an approved catalog JSON object of at most 256 KB with an exact endpoint, "
                "at most 1000 exact ASCII tool names and lowercase SHA256 hashes."
            )
        if baseline is not None and (
            target_url is None
            or target_url != baseline.endpoint
            or not target_url.startswith(("mcp+sse://", "mcp+sses://"))
            or mode != "FAST"
            or exploit
            or deep
            or mutate
            or indirect_adapter != "none"
            or analysis["analysis_mode"] != "deterministic"
            or any(optional_text[key] for key in ("attacker_model", "attacker_goal", "judge_model"))
            or attacker_turns is not None
        ):
            fields.errors["mcp_inventory_baseline"] = (
                "Catalog-only checks require the exact MCP SSE endpoint, standard mode and "
                "deterministic analysis, without active/deep probes, mutation, document adapters "
                "or attacker/judge settings."
            )
    if error_response := fields.response():
        return error_response
    assert target_url is not None
    framework = Framework(framework_val)
    modes = [ScanMode.SCAN]
    if exploit or mode == "ACTIVE":
        modes.append(ScanMode.EXPLOIT)
    if deep or mode == "DEEP":
        modes.append(ScanMode.DEEP)

    try:
        target_obj = Target.model_validate(
            {
                "url": target_url,
                "framework": framework,
                **optional_text,
                "canary_token": canary_token,
                "indirect_adapter": None if indirect_adapter == "none" else indirect_adapter,
                "judge_model": optional_text["judge_model"] or optional_text["attacker_model"],
                "attacker_turns": attacker_turns,
                "mutate": mutate,
                "concurrency": concurrency,
                "mcp_inventory_baseline": baseline,
                "factuality_baseline": factuality,
                **analysis,
            }
        )
    except ValidationError as error:
        errors = model_field_errors(error)
        if factuality is not None:
            errors = {
                "factuality_baseline"
                if key == "analysis_mode" or key.startswith("factuality_baseline.")
                else key: message
                for key, message in errors.items()
            }
        if baseline is not None:
            errors = {
                "mcp_inventory_baseline"
                if key == "analysis_mode" or key.startswith("mcp_inventory_baseline.")
                else key: message
                for key, message in errors.items()
            }
        return validation_error_response(errors)
    except AIClientError:
        return validation_error_response({"analysis_mode": "Choose a compatible analysis model."})

    from agentscan.core.external_analysis import validate_analysis_selection

    try:
        validate_analysis_selection(
            target_obj.analysis_mode,
            target_obj.data_classification,
            target_obj.external_model
            if target_obj.analysis_mode == "external"
            else target_obj.local_model,
        )
        for selected in (target_obj.attacker_model, target_obj.judge_model):
            if selected:
                if target_obj.analysis_mode == "deterministic":
                    raise AIClientError("Model selection requires local or external analysis.")
                validate_analysis_selection(
                    target_obj.analysis_mode, target_obj.data_classification, selected
                )
    except AIClientError as error:
        return validation_error_response({"analysis_mode": str(error)})

    scan_id = str(uuid.uuid4())
    # Keep the previous report visible until this scan produces a new terminal report.
    state.scan_recorder = None
    state.begin_scan(scan_id, target_url, [m.value for m in modes])

    async def _run_in_background() -> None:
        try:
            from agentscan.core.runner import run_scan_multi

            report = await run_scan_multi(target_obj, modes)
            from agentscan.core.context import active_context

            context = active_context.get()
            state.scan_recorder = context.recorder if context else None
            report.scan_id = scan_id
            if str(state.scan_status.get("status", "")) != SCAN_RUNNING:
                # Cancellation won the race; keep the previous report instead of a cancelled run.
                return
            state.report = report
            result_status = {
                "COMPLETE": "completed",
                "INCONCLUSIVE": "inconclusive",
                "ERROR": "failed",
            }.get(report.status, "inconclusive")
            state.finish_scan(
                result_status,
                scan_id=scan_id,
                target=target_url,
                findings_count=len(report.findings),
                score=report.score,
                tests_run=report.tests_run,
                tests_selected=report.tests_selected,
                module_errors=report.module_errors,
                module_outcomes=report.module_outcomes,
                assessment_scope=report.assessment_scope,
            )
            await event_bus.publish(
                {
                    "type": "scan:complete"
                    if result_status == "completed"
                    else "scan:error"
                    if result_status == "failed"
                    else "scan:inconclusive",
                    "data": {
                        "status": result_status,
                        "scan_id": scan_id,
                        "score": report.score,
                        "findings_count": len(report.findings),
                        "tests_run": report.tests_run,
                        "tests_selected": report.tests_selected,
                        "module_errors": report.module_errors,
                        "module_outcomes": report.module_outcomes,
                        "assessment_scope": report.assessment_scope,
                    },
                }
            )
        except asyncio.CancelledError:
            state.finish_scan("cancelled")
            raise
        except Exception as ex:
            failure = _operation_failure(ex, "background scan")
            state.finish_scan(
                "failed",
                scan_id=scan_id,
                target=target_url,
                **failure,
                score=None,
            )
            await event_bus.publish(
                {
                    "type": "scan:error",
                    "data": {"status": "failed", "scan_id": scan_id, **failure},
                }
            )

    state.active_scan = asyncio.create_task(_run_in_background())
    snapshot = state.scan_snapshot()
    await event_bus.publish({"type": "scan:start", "data": snapshot})
    return JSONResponse({**snapshot, "started": True})


@router.get("/api/scan/status")
async def api_scan_status() -> Any:
    return JSONResponse(state.scan_snapshot())


@router.post("/api/scan/cancel")
async def api_scan_cancel() -> Any:
    snapshot, cancelled = state.cancel_scan()
    if cancelled:
        if state.active_scan is not None and not state.active_scan.done():
            state.active_scan.cancel()
        await event_bus.publish({"type": "scan:cancel", "data": snapshot})
    return JSONResponse({**snapshot, "cancelled": cancelled})


@router.post("/api/discovery")
async def api_discovery(payload: dict[str, Any]) -> Any:
    from agentscan.core.discovery import discover_http, discover_widget

    fields = Fields(payload)
    url = fields.url("url", aliases=("target", "target_url"))
    mode = fields.choice("mode", ("auto", "http", "browser"), default="auto")
    test_message = fields.text("test_message", default="Hello", required=True, max_length=4096)
    no_exploit = fields.boolean("no_exploit")
    if error_response := fields.response():
        return error_response

    assert url is not None and test_message is not None
    scan_settings = {
        "exploit": not no_exploit,
        "verbose": True,
        "transcript": "transcript.txt",
        "output": "report.html",
    }
    profile: dict[str, Any] | None = None
    attempts: list[dict[str, str]] = []

    if mode in ("auto", "http"):
        try:
            api = await discover_http(url, test_message=test_message)
            if api is not None:
                default_ok = api["message_path"] == "message" and api["response_path"].split(".")[
                    -1
                ] in (
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
                attempts.append(
                    {
                        "transport": "http",
                        "status": "success",
                        "code": "HTTP_DETECTED",
                        "message": "A compatible JSON chat API was detected.",
                    }
                )
            else:
                attempts.append(
                    {
                        "transport": "http",
                        "status": "failed",
                        "code": "HTTP_NOT_DETECTED",
                        "message": "No compatible JSON chat API was detected. Check the route, target authentication and custom message/response paths; discovery cannot confirm the exact rejection reason.",
                    }
                )
        except Exception as e:
            failure = _operation_failure(e, "HTTP discovery")
            attempts.append(
                {
                    "transport": "http",
                    "status": "failed",
                    "code": failure["error_code"],
                    "message": failure["error"],
                    "error_id": failure["error_id"],
                }
            )

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
                attempts.append(
                    {
                        "transport": "browser",
                        "status": "success",
                        "code": "BROWSER_DETECTED",
                        "message": "A browser chat widget was detected. Review its selectors and reply completion configuration before scanning.",
                    }
                )
            else:
                attempts.append(
                    {
                        "transport": "browser",
                        "status": "failed",
                        "code": "BROWSER_NOT_DETECTED",
                        "message": "No browser chat widget was detected. Check that the target page exposes a chat input and reply area, or configure its selectors in a local profile.",
                    }
                )
        except Exception as e:
            failure = _operation_failure(e, "browser discovery")
            attempts.append(
                {
                    "transport": "browser",
                    "status": "failed",
                    "code": failure["error_code"],
                    "message": failure["error"],
                    "error_id": failure["error_id"],
                }
            )

    yaml_content = yaml.safe_dump(profile, sort_keys=False) if profile else ""
    endpoints = [url] if profile else []
    if profile and "request_template" in profile:
        endpoints.append(profile["request_template"].get("url", url))

    errors = [attempt for attempt in attempts if attempt["status"] == "failed"]
    result = {
        "success": profile is not None,
        "profile": profile,
        "yaml": yaml_content,
        "endpoints": endpoints,
        "routes": endpoints,
        "attempts": attempts,
        "errors": errors,
        "message": "Discovery completed"
        if profile
        else "Could not auto-detect chat API or browser widget.",
    }
    if profile is None:
        result["error"] = (
            "Discovery did not find a compatible chat API or browser widget. Review the attempt details and use a local target profile when the API needs custom authentication or request fields."
        )
        result["error_code"] = "DISCOVERY_NOT_DETECTED"
        if reference := next(
            (attempt.get("error_id") for attempt in errors if attempt.get("error_id")), None
        ):
            result["error_id"] = reference
    return JSONResponse(result)


@router.post("/api/discovery/save")
async def api_discovery_save(request: Request, payload: dict[str, Any]) -> Any:
    from agentscan.guard.path import PathSecurityError
    from agentscan.remediation.paths import contained_path

    fields = Fields(payload)
    profile = fields.value("profile", aliases=("manifest",))
    if not isinstance(profile, dict) or not profile:
        fields.errors["profile"] = "Provide a discovered profile JSON object before saving."
    output_name = fields.text("output_path", default="target.yaml", required=True, max_length=1024)
    if error_response := fields.response():
        return error_response
    assert output_name is not None
    output_root: Path = request.app.state.profile_root
    try:
        contained_path(request.app.state.project_root, output_root)
        # The profile directory may not exist on a fresh dashboard installation.
        # Resolve both paths against the existing trusted project before mkdir.
        out_path = contained_path(request.app.state.project_root, output_root / output_name)
        out_path.relative_to(output_root)
    except (PathSecurityError, ValueError):
        return JSONResponse(
            {
                "error": "output path must be within the configured profile directory",
                "field_errors": {"output_path": "Choose a filename inside the profile directory."},
            },
            status_code=403,
        )
    if out_path.suffix not in (".json", ".yaml", ".yml"):
        return validation_error_response({"output_path": "Use a .json, .yaml or .yml filename."})
    content = (
        json.dumps(profile, indent=2)
        if str(out_path).endswith(".json")
        else yaml.safe_dump(profile, sort_keys=False)
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    contained_path(request.app.state.project_root, output_root)
    contained_path(output_root, out_path)
    try:
        with out_path.open("x", encoding="utf-8") as stream:
            stream.write(content)
    except FileExistsError:
        return validation_error_response(
            {"output_path": "This profile filename already exists; choose another filename."}, 409
        )
    return JSONResponse({"success": True, "saved_to": str(out_path)})
