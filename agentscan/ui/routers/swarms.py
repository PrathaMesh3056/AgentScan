# agentscan/ui/routers/swarms.py
#
# Multi-agent swarm orchestration, presets, and blackboard collaboration endpoints.

from __future__ import annotations

import asyncio
from typing import Any

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from agentscan.core.models import Target
from agentscan.swarm.blackboard import SwarmBlackboard
from agentscan.ui.state import event_bus, state
from agentscan.ui.validation import Fields, model_field_errors, validation_error_response

router = APIRouter(tags=["swarms"])


@router.get("/api/swarms")
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


@router.post("/api/swarms/run")
async def api_swarms_run(payload: dict[str, Any]) -> Any:
    from agentscan.swarm.coordinator import SwarmCoordinator
    from agentscan.swarm.presets import PRESETS, resolve_team

    fields = Fields(payload)
    target_url = fields.url("target_url", aliases=("target",))
    team_name = fields.text(
        "team", default="trio", required=True, max_length=64, aliases=("strategy",)
    )
    team_lower = (team_name or "").lower()
    aliases = {"collaborative": "agency", "adaptive": "stealth"}
    team_key = aliases.get(team_lower, team_lower)
    if team_key not in PRESETS:
        fields.errors["team"] = "Choose a supported swarm team: trio, agency or stealth."
    model = fields.text("model", max_length=140)
    rounds_val = fields.integer("rounds", 1, 10, aliases=("max_rounds",))
    legacy_offline = fields.boolean("offline", default=model is None)
    if "analysis_mode" not in payload:
        payload = {
            **payload,
            "analysis_mode": "deterministic"
            if legacy_offline
            else "local"
            if model and model.startswith("ollama/")
            else "external",
        }
        fields.payload = payload
    analysis = fields.analysis(model_alias=model)
    analysis_mode = analysis["analysis_mode"]
    if error_response := fields.response():
        return error_response
    assert target_url is not None
    offline = analysis_mode == "deterministic"

    team_cfg = resolve_team(team_key).model_copy(deep=True)
    if rounds_val is not None:
        team_cfg.max_rounds = rounds_val

    from agentscan.core.ai_client import AIClientError
    from agentscan.core.external_analysis import validate_analysis_selection

    try:
        target_obj = Target.model_validate({"url": target_url, **analysis})
        model = (
            analysis["external_model"] if analysis_mode == "external" else analysis["local_model"]
        )
        validate_analysis_selection(analysis_mode, target_obj.data_classification, model)
    except ValidationError as error:
        return validation_error_response(model_field_errors(error))
    except AIClientError as error:
        return validation_error_response({"analysis_mode": str(error)})
    coordinator = SwarmCoordinator(
        team_config=team_cfg,
        model_override=model,
        offline=offline,
    )
    # Each run has a fresh boundary. Earlier sensitive observations must never
    # become input to a later external analysis session.
    state.swarm_blackboard = SwarmBlackboard()
    coordinator.blackboard = state.swarm_blackboard

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

    from agentscan.core.outcomes import TargetRequestError

    try:
        report = await coordinator.run_swarm(target_obj, callback=_on_turn)
    except TargetRequestError as error:
        return JSONResponse({"status": "inconclusive", "error": str(error)}, status_code=502)
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


@router.post("/api/swarms/blackboard/add")
async def api_swarms_blackboard_add(payload: dict[str, Any]) -> Any:
    fields = Fields(payload)
    key = fields.text("key", required=True, max_length=256)
    value = payload.get("value")
    discovered_by = fields.text("discovered_by", default="Operator", required=True, max_length=128)
    confidence = payload.get("confidence", 1.0)
    if type(confidence) not in (int, float) or not 0 <= confidence <= 1:
        fields.errors["confidence"] = "Enter a finite number between 0 and 1."
    if value is None:
        fields.errors["value"] = "Provide an intel value."
    if error_response := fields.response():
        return error_response
    assert key is not None and discovered_by is not None
    item = state.swarm_blackboard.add_intel(
        key, value, discovered_by=discovered_by, confidence=confidence
    )
    await event_bus.publish({"type": "swarm:intel", "data": item.model_dump(mode="json")})
    return JSONResponse(item.model_dump(mode="json"))


@router.post("/api/swarms/blackboard/clear")
async def api_swarms_blackboard_clear() -> Any:
    state.swarm_blackboard = SwarmBlackboard()
    await event_bus.publish({"type": "swarm:intel_clear", "data": {}})
    return JSONResponse({"status": "cleared", "items": [], "cleared": True})
