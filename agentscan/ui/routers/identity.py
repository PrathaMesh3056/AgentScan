# agentscan/ui/routers/identity.py
#
# Identity manifest inspection, cryptographic report signing, and certificate verification.

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse
from loguru import logger

from agentscan.identity.manifest_loader import load_manifests
from agentscan.identity.permission_mapper import load_role_policies
from agentscan.ui.security import project_path
from agentscan.ui.state import state
from agentscan.ui.status_labels import assess_manifest_enforcement
from agentscan.ui.validation import Fields, validation_error_response

router = APIRouter(tags=["identity"])


@router.get("/api/identity")
async def api_identity(
    request: Request,
    path: str | None = Query(default=None, description="Directory of *.agent.json manifests"),
) -> Any:
    root = (
        str(project_path(request, path))
        if path
        else (str(state.identity_path) if state.identity_path else None)
    )
    if not root:
        return JSONResponse({"agents": [], "path": None, "count": 0})
    agents = load_manifests(root)
    role_policies = load_role_policies()
    payload = []
    for agent in agents:
        data = agent.model_dump(mode="json") if hasattr(agent, "model_dump") else agent
        if isinstance(data, dict):
            # Declared manifests are not proof of runtime RBAC enforcement.
            data["enforcement"] = assess_manifest_enforcement(agent, role_policies)
        payload.append(data)
    return JSONResponse({"path": root, "count": len(agents), "agents": payload})


@router.post("/api/certificate")
async def api_certificate_post(payload: dict[str, Any] | None = None) -> Any:
    fields = Fields(payload or {})
    secret_key = fields.text("secret_key", max_length=4096)
    if secret_key and (
        len(secret_key.encode("utf-8")) < 32 or secret_key == "agentscan-audit-verification-key"
    ):
        fields.errors["secret_key"] = (
            "Use a private signing key of at least 32 bytes, or leave this field empty to use the server key."
        )
    if error_response := fields.response():
        return error_response
    return _certificate_response(secret_key)


def _certificate_response(secret_key: str | None) -> Any:
    from agentscan.reporting.audit_verifier import sign_audit_report

    if state.report is None:
        return JSONResponse({"error": "no report loaded", "certificate": None}, status_code=200)
    if secret_key is not None and not isinstance(secret_key, str):
        return validation_error_response({"secret_key": "Enter a private signing key as text."})
    try:
        cert = sign_audit_report(state.report.to_dict(), secret_key=secret_key)
    except ValueError as error:
        return JSONResponse(
            {"error": str(error)}, status_code=400 if secret_key is not None else 503
        )
    return JSONResponse(cert)


@router.get("/api/certificate")
async def api_certificate(
    secret_key: str | None = Query(
        default=None,
        description="Optional HMAC key (deprecated: use POST /api/certificate with JSON body)",
    ),
) -> Any:
    if secret_key:
        logger.warning(
            "Passing secret_key via query parameter is deprecated for security. "
            "Use POST /api/certificate with a JSON body instead."
        )
    return _certificate_response(secret_key)


@router.post("/api/verify-certificate")
async def api_verify_certificate(payload: dict[str, Any]) -> Any:
    from agentscan.reporting.audit_verifier import verify_audit_certificate

    fields = Fields(payload)
    report_data = (
        fields.object("report")
        if "report" in payload
        else (state.report.to_dict() if state.report else {})
    )
    certificate_data = fields.object("certificate", required=True)
    secret_key = fields.text("secret_key", max_length=4096)
    if secret_key and (
        len(secret_key.encode("utf-8")) < 32 or secret_key == "agentscan-audit-verification-key"
    ):
        fields.errors["secret_key"] = (
            "Use a private signing key of at least 32 bytes, or leave this field empty to use the server key."
        )
    if error_response := fields.response():
        return error_response
    is_valid, reason = verify_audit_certificate(
        report_data, certificate_data, secret_key=secret_key
    )
    return JSONResponse({"valid": is_valid, "reason": reason})
