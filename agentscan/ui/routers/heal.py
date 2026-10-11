# agentscan/ui/routers/heal.py
#
# Remediation planning, patch generation, applying fixes, and webhook simulation.

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from agentscan.guard.path import PathSecurityError
from agentscan.remediation.models import FixConflictError
from agentscan.ui.security import project_root
from agentscan.ui.state import event_bus, state
from agentscan.ui.validation import Fields, model_field_errors, validation_error_response

router = APIRouter(tags=["heal"])


@router.get("/api/heal")
async def api_heal(request: Request) -> Any:
    from agentscan.remediation.engine import RemediationEngine
    from agentscan.remediation.patch_generator import (
        generate_github_pr_payload,
        generate_unified_patch,
    )

    findings = state.report.findings if state.report else []
    root = project_root(request)
    engine = RemediationEngine(root)
    try:
        plan = engine.plan(findings)
    except PathSecurityError as error:
        raise HTTPException(status_code=403, detail=str(error)) from error
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


@router.post("/api/heal/apply")
async def api_heal_apply(request: Request, payload: dict[str, Any] | None = None) -> Any:
    from agentscan.remediation.engine import RemediationEngine

    fields = Fields(payload or {})
    root_value = fields.text("root_path", max_length=4096)
    fields.boolean("backup", default=True)
    kinds = fields.value("kinds")
    allowed = {"pin_bump", "ast_patch", "identity_shrink", "guardrails"}
    if kinds is not None and (
        not isinstance(kinds, list)
        or not kinds
        or any(not isinstance(k, str) or k not in allowed for k in kinds)
    ):
        fields.errors["kinds"] = "Select one or more supported remediation kinds."
    if error_response := fields.response():
        return error_response
    findings = state.report.findings if state.report else []
    root = project_root(request, root_value)
    engine = RemediationEngine(root)
    try:
        plan = engine.plan(findings, kinds=kinds)
        engine.apply(plan)
    except PathSecurityError as error:
        raise HTTPException(status_code=403, detail=str(error)) from error
    except FixConflictError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error

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


@router.get("/api/heal/server/status")
async def api_heal_server_status() -> Any:
    return JSONResponse(state.webhook_receiver_status)


@router.post("/api/heal/server/simulate")
async def api_heal_server_simulate(request: Request, payload: dict[str, Any]) -> Any:
    from agentscan.remediation.engine import RemediationEngine
    from agentscan.remediation.patch_generator import (
        generate_github_pr_payload,
        generate_unified_patch,
    )
    from agentscan.remediation.webhook_receiver import AlertPayload, _parse_findings

    fields = Fields(payload)
    fields.boolean("apply")
    if "file" in payload or "vulnerability_type" in payload or "evidence" in payload:
        file = fields.text("file", required=True, max_length=4096)
        vulnerability = fields.choice(
            "vulnerability_type",
            ("PROMPT_INJECTION", "SSRF_TOOL_LEAK", "SQL_INJECTION", "PRIVILEGE_ESCALATION"),
            default="PROMPT_INJECTION",
        )
        evidence = fields.text("evidence", required=True, max_length=65536)
        if error_response := fields.response():
            return error_response
        assert file is not None and evidence is not None
        from agentscan.ui.security import project_path

        try:
            file_path = project_path(request, file)
        except HTTPException as error:
            return validation_error_response(
                {"file": "Choose a file within the configured project."}, error.status_code
            )
        if not file_path.is_file():
            return validation_error_response({"file": "Choose an existing project file."})
        if payload.get("apply"):
            return validation_error_response(
                {
                    "apply": "Simulation generates a reviewable plan; apply reviewed fixes from the remediation action."
                }
            )
        attack_ids = {
            "PROMPT_INJECTION": ("ATK-001", "LLM01"),
            "SSRF_TOOL_LEAK": ("ATK-014", "LLM02"),
            "SQL_INJECTION": ("ATK-007", "LLM05"),
            "PRIVILEGE_ESCALATION": ("ATK-013", "LLM06"),
        }
        attack_id, owasp_id = attack_ids[vulnerability]
        payload = {
            "source": "dashboard_simulation",
            "findings": [
                {
                    "attack_id": attack_id,
                    "attack_name": vulnerability,
                    "owasp_id": owasp_id,
                    "description": "Operator-supplied simulated alert; this does not establish a verified vulnerability.",
                    "evidence": evidence,
                    "metadata": {"file": str(file_path), "simulation": True},
                }
            ],
            "apply": False,
        }
    else:
        fields.text("source", default="sentinel", required=True, max_length=128)
        fields.text("target_repo", default=".", required=True, max_length=4096)
        fields.text("branch_name", default="agentscan/auto-heal", required=True, max_length=256)
        fields.text("patch_out", max_length=4096)
        for key in ("findings", "finding_ids"):
            value = fields.value(key, [])
            if not isinstance(value, list) or any(
                not isinstance(item, dict if key == "findings" else str) or not item
                for item in value
            ):
                fields.errors[key] = (
                    "Provide a list of finding objects."
                    if key == "findings"
                    else "Provide a list of nonempty finding IDs."
                )
        if not payload.get("findings") and not payload.get("finding_ids"):
            fields.errors["findings"] = "Provide at least one finding or finding ID."
        raw_findings = fields.value("findings", [])
        if isinstance(raw_findings, list):
            for index, item in enumerate(raw_findings):
                if not isinstance(item, dict):
                    continue
                finding_fields = Fields(item)
                for key in (
                    "attack_id",
                    "id",
                    "attack_name",
                    "description",
                    "evidence",
                    "remediation",
                ):
                    finding_fields.text(key)
                finding_fields.choice(
                    "severity", ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"), default="HIGH"
                )
                finding_fields.object("metadata")
                fields.errors.update(
                    {
                        f"findings.{index}.{key}": message
                        for key, message in finding_fields.errors.items()
                    }
                )
        if error_response := fields.response():
            return error_response
    try:
        alert = AlertPayload.model_validate(payload)
    except ValidationError as error:
        return validation_error_response(model_field_errors(error))
    findings = _parse_findings(alert)
    root = project_root(request, alert.target_repo)
    engine = RemediationEngine(root)
    try:
        plan = engine.plan(findings)
    except PathSecurityError as error:
        raise HTTPException(status_code=403, detail=str(error)) from error
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
