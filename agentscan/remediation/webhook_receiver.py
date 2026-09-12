# agentscan/remediation/webhook_receiver.py
#
# FastAPI webhook receiver for automated self-healing.
# Ingests security alerts from Sentinel, AI Gateways (LiteLLM, Cloudflare, AWS Bedrock),
# or external SIEMs, automatically generating unified git patches and remediation PR payloads.

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from loguru import logger
from pydantic import BaseModel, Field

from agentscan.core.models import Finding, Severity
from agentscan.remediation.engine import RemediationEngine
from agentscan.remediation.patch_generator import generate_github_pr_payload, generate_unified_patch

app = FastAPI(
    title="AgentScan Self-Healing Webhook Receiver",
    description="Ingests live security telemetry and triggers automated AST remediation and patch generation.",
    version="0.1.0",
)


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


def _parse_findings(payload: AlertPayload) -> list[Finding]:
    """Extract or synthesize Finding objects from alert payload."""
    parsed: list[Finding] = []
    for item in payload.findings:
        try:
            finding = Finding.model_validate(item)
            parsed.append(finding)
        except Exception:
            # Construct minimal Finding from dictionary
            attack_id = str(item.get("attack_id") or item.get("id") or "SC-011")
            sev_str = str(item.get("severity") or "HIGH").upper()
            sev = getattr(Severity, sev_str, Severity.HIGH)
            parsed.append(
                Finding(
                    attack_id=attack_id,
                    attack_name=str(item.get("attack_name") or "Security Alert"),
                    severity=sev,
                    owasp_id=str(item.get("owasp_id") or "LLM05"),
                    description=str(item.get("description") or "Automated alert finding"),
                    evidence=str(item.get("evidence") or ""),
                    remediation=str(item.get("remediation") or ""),
                    metadata=item.get("metadata") or {},
                )
            )

    # If only finding_ids were supplied without full finding objects
    if not parsed and payload.finding_ids:
        for fid in payload.finding_ids:
            parsed.append(
                Finding(
                    attack_id=fid,
                    attack_name=f"Alert for {fid}",
                    severity=Severity.HIGH,
                    owasp_id="LLM05",
                    description=f"Automated self-healing triggered for {fid}",
                    evidence="",
                    remediation="Apply automated fix.",
                    metadata={},
                )
            )

    return parsed


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "agentscan-self-healing"}


@app.post("/webhook/alert")
def receive_alert(payload: AlertPayload) -> dict[str, Any]:
    """Ingest security alert, plan remediation, and generate unified git patch."""
    findings = _parse_findings(payload)
    if not findings:
        raise HTTPException(
            status_code=400, detail="No valid findings or finding_ids provided in alert."
        )

    repo_path = Path(payload.target_repo).resolve()
    if not repo_path.exists():
        raise HTTPException(status_code=404, detail=f"Target repo path not found: {repo_path}")

    engine = RemediationEngine(repo_path)
    plan = engine.plan(findings)

    patch_content = generate_unified_patch(plan, base_dir=repo_path)
    pr_payload = generate_github_pr_payload(plan, branch_name=payload.branch_name)

    applied_count = 0
    if payload.apply:
        applied_count = engine.apply(plan).applied_count

    if payload.patch_out and patch_content:
        out_file = Path(payload.patch_out)
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text(patch_content, encoding="utf-8")
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
def trigger_heal(payload: AlertPayload) -> dict[str, Any]:
    """Alias for /webhook/alert specifically for automated remediation workflows."""
    return receive_alert(payload)


def run_heal_server(host: str = "127.0.0.1", port: int = 8766) -> None:
    """Run the self-healing webhook receiver via uvicorn."""
    import uvicorn

    logger.info(f"Starting AgentScan Self-Healing Webhook Receiver on {host}:{port}")
    uvicorn.run(app, host=host, port=port)
