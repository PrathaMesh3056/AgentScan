# agentscan/remediation/webhook_receiver.py
#
# FastAPI webhook receiver for automated self-healing.
# Ingests security alerts from Sentinel, AI Gateways (LiteLLM, Cloudflare, AWS Bedrock),
# or external SIEMs, automatically generating unified git patches and remediation PR payloads.

from __future__ import annotations

import os
import re
import secrets
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, HTTPException
from loguru import logger
from pydantic import BaseModel, Field, ValidationError

from agentscan.core.models import Finding, Severity
from agentscan.guard.path import PathSecurityError
from agentscan.remediation.engine import RemediationEngine
from agentscan.remediation.models import FixConflictError
from agentscan.remediation.patch_generator import generate_github_pr_payload, generate_unified_patch
from agentscan.remediation.paths import contained_path

app = FastAPI(
    title="AgentScan Self-Healing Webhook Receiver",
    description="Ingests live security telemetry and triggers automated AST remediation and patch generation.",
    version="0.1.0",
)

_MAX_ALERT_FINDINGS = 100
_ATTACK_ID_RE = re.compile(r"^(ATK|SC|ID)-[A-Z0-9\-]+$")
_OWASP_ID_RE = re.compile(r"^(LLM\d{2}|UNMAPPED)$")


class FindingPayloadError(ValueError):
    """An alert finding is not a valid Finding or a well-formed alert item."""


class AlertPayload(BaseModel):
    """Incoming alert structure from Sentinel or Gateway webhook."""

    source: str = Field(
        default="sentinel", description="Source system (e.g. sentinel, litellm, cloudflare)"
    )
    target_repo: str = Field(default=".", description="Target repository path")
    finding_ids: list[str] = Field(default_factory=list, description="List of finding attack IDs")
    findings: list[dict[str, Any]] = Field(
        default_factory=list, description="Raw finding objects if provided"
    )
    branch_name: str = Field(
        default="agentscan/auto-heal", description="Git branch name for patch/PR"
    )
    apply: bool = Field(default=False, description="Whether to write fixes directly to disk")
    patch_out: str | None = Field(
        default=None, description="Optional filesystem path to save .patch file"
    )


def _alert_text(item: dict[str, Any], key: str, default: str, index: int) -> str:
    """Return an optional alert string without coercing arbitrary values."""
    value = item.get(key)
    if value is None:
        return default
    if not isinstance(value, str):
        raise FindingPayloadError(f"findings[{index}].{key} must be a string")
    return value


def _alert_finding(item: dict[str, Any], index: int) -> Finding:
    """Build a validated Finding from an alert-shaped dictionary."""
    attack_id = item.get("attack_id") or item.get("id")
    if not isinstance(attack_id, str) or not _ATTACK_ID_RE.fullmatch(attack_id):
        raise FindingPayloadError(f"findings[{index}].attack_id is missing or invalid")

    raw_severity = item.get("severity", Severity.HIGH.value)
    if not isinstance(raw_severity, str) or raw_severity.upper() not in Severity.__members__:
        raise FindingPayloadError(f"findings[{index}].severity is not a recognized severity")

    owasp_id = item.get("owasp_id") or "LLM05"
    if not isinstance(owasp_id, str) or not _OWASP_ID_RE.fullmatch(owasp_id):
        raise FindingPayloadError(f"findings[{index}].owasp_id is invalid")

    metadata = item.get("metadata")
    if metadata is None:
        metadata = {}
    if not isinstance(metadata, dict):
        raise FindingPayloadError(f"findings[{index}].metadata must be an object")

    try:
        return Finding(
            attack_id=attack_id,
            attack_name=_alert_text(item, "attack_name", "Security Alert", index),
            severity=Severity[raw_severity.upper()],
            owasp_id=owasp_id,
            description=_alert_text(item, "description", "Automated alert finding", index),
            evidence=_alert_text(item, "evidence", "", index),
            remediation=_alert_text(item, "remediation", "", index),
            metadata=metadata,
        )
    except ValidationError as error:
        location = ".".join(str(part) for part in error.errors()[0].get("loc", ())) or "finding"
        raise FindingPayloadError(f"findings[{index}] failed validation at {location}") from error


def _parse_findings(payload: AlertPayload) -> list[Finding]:
    """Extract validated Finding objects from alert payload."""
    if (
        len(payload.findings) > _MAX_ALERT_FINDINGS
        or len(payload.finding_ids) > _MAX_ALERT_FINDINGS
    ):
        raise FindingPayloadError(
            f"alert may contain at most {_MAX_ALERT_FINDINGS} findings or finding_ids"
        )

    parsed: list[Finding] = []
    for index, item in enumerate(payload.findings):
        try:
            parsed.append(Finding.model_validate(item))
        except ValidationError:
            parsed.append(_alert_finding(item, index))

    # If only finding_ids were supplied without full finding objects
    if not parsed:
        for index, finding_id in enumerate(payload.finding_ids):
            if not isinstance(finding_id, str) or not _ATTACK_ID_RE.fullmatch(finding_id):
                raise FindingPayloadError(f"finding_ids[{index}] is not a valid finding ID")
            parsed.append(
                Finding(
                    attack_id=finding_id,
                    attack_name=f"Alert for {finding_id}",
                    severity=Severity.HIGH,
                    owasp_id="LLM05",
                    description=f"Automated self-healing triggered for {finding_id}",
                    evidence="",
                    remediation="Apply automated fix.",
                    metadata={},
                )
            )

    return parsed


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "agentscan-self-healing"}


def _authorized_root(authorization: str | None = Header(default=None)) -> Path:
    """Require a deployment-owned credential and repository, independent of alert contents."""
    token = os.environ.get("AGENTSCAN_HEAL_TOKEN", "")
    configured_root = os.environ.get("AGENTSCAN_HEAL_ROOT", "")
    if not token or not configured_root:
        raise HTTPException(
            status_code=503, detail="Webhook token and project root are not configured"
        )
    supplied = authorization.removeprefix("Bearer ") if authorization else ""
    if (
        not authorization
        or not authorization.startswith("Bearer ")
        or not secrets.compare_digest(supplied, token)
    ):
        raise HTTPException(status_code=401, detail="Valid webhook bearer token required")
    root = Path(configured_root).resolve()
    if not root.is_dir():
        raise HTTPException(
            status_code=503, detail="Configured webhook project root is unavailable"
        )
    return root


@app.post("/webhook/alert")
def receive_alert(
    payload: AlertPayload, repo_path: Annotated[Path, Depends(_authorized_root)]
) -> dict[str, Any]:
    """Ingest security alert, plan remediation, and generate unified git patch."""
    try:
        findings = _parse_findings(payload)
    except FindingPayloadError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    if not findings:
        raise HTTPException(
            status_code=400, detail="No valid findings or finding_ids provided in alert."
        )

    requested_root = (
        repo_path if payload.target_repo == "." else Path(payload.target_repo).resolve()
    )
    if requested_root != repo_path:
        raise HTTPException(status_code=403, detail="Alert cannot select a different project root")
    if payload.apply and os.environ.get("AGENTSCAN_HEAL_ALLOW_APPLY") != "1":
        raise HTTPException(status_code=403, detail="Remote remediation application is disabled")
    try:
        out_file = contained_path(repo_path, payload.patch_out) if payload.patch_out else None
        if out_file is not None and out_file.suffix not in (".patch", ".diff"):
            raise HTTPException(status_code=400, detail="Patch output must use .patch or .diff")
        if out_file is not None and out_file.exists():
            raise HTTPException(status_code=409, detail="Patch output already exists")
    except PathSecurityError as error:
        raise HTTPException(status_code=403, detail=str(error)) from error

    engine = RemediationEngine(repo_path)
    try:
        plan = engine.plan(findings)
    except PathSecurityError as error:
        raise HTTPException(status_code=403, detail=str(error)) from error

    patch_content = generate_unified_patch(plan, base_dir=repo_path)
    pr_payload = generate_github_pr_payload(plan, branch_name=payload.branch_name)

    applied_count = 0
    if payload.apply:
        try:
            applied_count = engine.apply(plan).applied_count
        except FixConflictError as error:
            raise HTTPException(status_code=409, detail=str(error)) from error

    if out_file is not None and patch_content:
        out_file.parent.mkdir(parents=True, exist_ok=True)
        contained_path(repo_path, out_file)
        with out_file.open("x", encoding="utf-8") as stream:
            stream.write(patch_content)
        logger.info(f"Wrote self-healing patch to {out_file}")

    return {
        "status": "remediation_planned" if not payload.apply else "remediation_applied",
        "total_actions": plan.total_actions,
        "applied_count": applied_count,
        "paths_affected": plan.paths_affected,
        "patch": patch_content,
        "pr_payload": pr_payload,
    }


@app.post("/webhook/heal")
def trigger_heal(
    payload: AlertPayload, repo_path: Annotated[Path, Depends(_authorized_root)]
) -> dict[str, Any]:
    """Alias for /webhook/alert specifically for automated remediation workflows."""
    return receive_alert(payload, repo_path)


def run_heal_server(host: str = "127.0.0.1", port: int = 8766) -> None:
    """Run the self-healing webhook receiver via uvicorn."""
    import uvicorn

    logger.info(f"Starting AgentScan Self-Healing Webhook Receiver on {host}:{port}")
    uvicorn.run(app, host=host, port=port)
