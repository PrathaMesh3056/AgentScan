# agentscan/ui/routers/telemetry.py
#
# Calibration and benchmarking telemetry endpoints.

from __future__ import annotations

from typing import Any

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from agentscan.ui.validation import Fields

router = APIRouter(tags=["telemetry"])


@router.post("/api/calibrate")
async def api_calibrate(payload: dict[str, Any] | None = None) -> Any:
    from agentscan.core.calibration import run_calibration

    if payload is None:
        payload = {}
    fields = Fields(payload)
    attacker_model = fields.text(
        "model",
        default="ollama/llama3.2",
        required=True,
        max_length=136,
        aliases=("attacker_model",),
    )
    attacker_goal = fields.text("attacker_goal")
    from agentscan.core.ai_client import AIClientError, local_model_name

    try:
        local_model_name(attacker_model or "")
    except AIClientError:
        fields.errors["model"] = "Enter an installed offline model as ollama/model-name."
    if error_response := fields.response():
        return error_response
    assert attacker_model is not None
    result = await run_calibration(attacker_model, attacker_goal=attacker_goal)
    return JSONResponse(
        {
            "passed": result.passed,
            "detail": result.detail,
            "baseline_latency_ms": getattr(result, "latency_ms", None),
            "model": attacker_model,
            "assessment_scope": "synthetic_local_model_smoke",
            "independent_calibration": False,
        }
    )


@router.get("/api/benchmark")
@router.post("/api/benchmark/run")
async def api_benchmark(payload: dict[str, Any] | None = None) -> Any:
    from agentscan.core.benchmark import BENCHMARK_SCOPE, discriminates, run_benchmark

    rows = await run_benchmark()
    is_discriminating = discriminates(rows)
    return JSONResponse(
        {
            "discriminates": is_discriminating,
            "assessment_scope": BENCHMARK_SCOPE,
            "independent_calibration": False,
            "suites": (
                sorted(set(getattr(r, "suite", "AGENT_BENCH_V1") for r in rows)) if rows else []
            ),
            "rows": [
                {
                    "name": r.name,
                    "expectation": r.expectation,
                    "findings": r.findings,
                    "score": r.score,
                    "assessment_status": r.assessment_status,
                    "tests_selected": r.tests_selected,
                    "tests_evaluated": r.tests_evaluated,
                    "reason": r.reason,
                }
                for r in rows
            ],
        }
    )
