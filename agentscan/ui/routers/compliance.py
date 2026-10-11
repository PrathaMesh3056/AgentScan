# agentscan/ui/routers/compliance.py
#
# Compliance mapping endpoints (EU AI Act & NIST AI RMF).

from __future__ import annotations

from typing import Any

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from agentscan.ui.state import state

router = APIRouter(tags=["compliance"])


@router.get("/api/compliance")
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
