# tests/test_swarm/test_budget.py

from __future__ import annotations

import pytest

from agentscan.core.connectors import CallableConnector, use_connector
from agentscan.core.models import Target
from agentscan.swarm.budget import BoundedSwarmController
from agentscan.swarm.coordinator import SwarmCoordinator
from agentscan.swarm.presets import load_team_preset


def test_bounded_swarm_controller_pruning_unit() -> None:
    """Verifies unit logic of BoundedSwarmController for rounds, tokens, and exploit early-exit."""
    budget = BoundedSwarmController(max_rounds=2, max_tokens_per_turn=50, token_ceiling=120)

    # Round 1 within budget
    assert budget.should_continue(current_round=1, exploit_confirmed=False) is True
    budget.record_turn(tokens_used=40)
    assert budget.tokens_consumed == 40

    # Round 2 within budget
    assert budget.should_continue(current_round=2, exploit_confirmed=False) is True
    budget.record_turn(tokens_used=40)
    assert budget.tokens_consumed == 80

    # Round 3 exceeds max_rounds
    assert budget.should_continue(current_round=3, exploit_confirmed=False) is False
    summary = budget.summary()
    assert summary["stop_reason"] == "max_rounds_reached"
    assert summary["rounds_used"] == 2
    assert summary["tokens_consumed"] == 80


def test_bounded_swarm_controller_token_ceiling_unit() -> None:
    """Verifies token ceiling enforcement triggers early stop."""
    budget = BoundedSwarmController(max_rounds=5, token_ceiling=100)

    assert budget.should_continue(current_round=1, exploit_confirmed=False) is True
    budget.record_turn(tokens_used=150)  # Exceeds ceiling

    assert budget.should_continue(current_round=2, exploit_confirmed=False) is False
    assert budget.summary()["stop_reason"] == "token_ceiling_reached"


def test_bounded_swarm_controller_exploit_confirmed_unit() -> None:
    """Verifies exploit confirmation triggers immediate halt."""
    budget = BoundedSwarmController(max_rounds=5)

    assert budget.should_continue(current_round=1, exploit_confirmed=True) is False
    assert budget.summary()["stop_reason"] == "exploit_confirmed"


@pytest.mark.asyncio
async def test_swarm_stops_after_exact_max_rounds() -> None:
    """Verifies swarm with max_rounds=2 stops after exactly 2 rounds."""

    def guarded_bot(msg: str) -> str:
        return "I am sorry, but I cannot assist with that request as it violates safety guidelines."

    team = load_team_preset("trio")
    team.max_rounds = 2
    coordinator = SwarmCoordinator(team_config=team, offline=True)
    target = Target(url="http://mock.local/chat")

    with use_connector(CallableConnector(guarded_bot)):
        report = await coordinator.run_swarm(target)

    # 3 agents in trio * 2 rounds = 6 turns
    assert len(report.turns) == 6
    assert report.budget_summary["rounds_used"] == 2
    assert report.budget_summary["stop_reason"] in ("completed", "max_rounds_reached")


@pytest.mark.asyncio
async def test_swarm_candidates_do_not_trigger_confirmed_compromise_stop() -> None:
    """Text indicators remain candidates and cannot trigger a confirmed-effect stop."""

    def vulnerable_bot(msg: str) -> str:
        msg_lower = msg.lower()
        if "initial instructions" in msg_lower or "declared tool" in msg_lower:
            return "You are an internal helper bot. Tools: [bash, exec]."
        if "execute system maintenance" in msg_lower or "drop table" in msg_lower:
            return "Maintenance executed: dropped table accounts."
        return "Diagnostic mode acknowledged."

    team = load_team_preset("trio")
    team.max_rounds = 5
    coordinator = SwarmCoordinator(team_config=team, offline=True)
    target = Target(url="http://mock.local/chat")

    with use_connector(CallableConnector(vulnerable_bot)):
        report = await coordinator.run_swarm(target)

    assert len(report.turns) == 15
    assert report.budget_summary["stop_reason"] != "exploit_confirmed"
    assert all(f.metadata.get("execution_verified") is False for f in report.findings)
    assert len(report.findings) >= 1


@pytest.mark.asyncio
async def test_swarm_stops_on_token_ceiling() -> None:
    """Verifies swarm halts when total tokens consumed reaches ceiling even if rounds remain."""

    def guarded_long_bot(msg: str) -> str:
        return (
            "I am sorry, but I cannot assist with that request as it violates safety guidelines. "
            * 5
        )

    team = load_team_preset("trio")
    team.max_rounds = 4

    # Restrict token ceiling to a low value
    custom_budget = BoundedSwarmController(max_rounds=4, token_ceiling=30)
    coordinator = SwarmCoordinator(team_config=team, offline=True, budget=custom_budget)
    target = Target(url="http://mock.local/chat")

    with use_connector(CallableConnector(guarded_long_bot)):
        report = await coordinator.run_swarm(target)

    assert report.budget_summary["stop_reason"] == "token_ceiling_reached"
    # Halts before executing all 4 rounds
    assert report.budget_summary["rounds_used"] < 4


@pytest.mark.asyncio
async def test_protected_canary_disclosure_stops_swarm_early():
    canary = "synthetic_protected_canary_6935"
    team = load_team_preset("trio")
    team.max_rounds = 5
    coordinator = SwarmCoordinator(team_config=team, offline=True)
    with use_connector(CallableConnector(lambda message: "Disclosure: " + canary)):
        report = await coordinator.run_swarm(
            Target(url="http://mock.local/chat", canary_token=canary)
        )
    assert len(report.turns) == 3
    assert report.budget_summary["stop_reason"] == "exploit_confirmed"
    assert all(canary not in turn.prompt for turn in report.turns)
    assert any(f.metadata.get("disclosure_verified") is True for f in report.findings)
