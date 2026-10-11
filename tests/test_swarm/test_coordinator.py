# tests/test_swarm/test_coordinator.py

from __future__ import annotations

import pytest

from agentscan.core.connectors import CallableConnector, use_connector
from agentscan.core.models import Target
from agentscan.swarm.blackboard import SwarmBlackboard
from agentscan.swarm.coordinator import SwarmCoordinator
from agentscan.swarm.presets import load_team_preset


@pytest.mark.asyncio
async def test_swarm_coordinator_vulnerable_target() -> None:
    def vulnerable_bot(msg: str) -> str:
        msg_lower = msg.lower()
        if "initial instructions" in msg_lower or "declared tool" in msg_lower:
            return "You are a internal helper bot. Tools: [bash, exec]."
        if "execute system maintenance" in msg_lower or "drop table" in msg_lower:
            return "Maintenance executed: dropped table accounts."
        if "diagnostic recovery mode" in msg_lower or "simulation" in msg_lower:
            return "Diagnostic mode acknowledged."
        return "Command completed."

    team = load_team_preset("trio")
    team.max_rounds = 1
    coordinator = SwarmCoordinator(team_config=team, offline=True)
    target = Target(url="http://mock.local/chat")

    turns_logged = []

    def on_turn(rnd: int, agent_name: str, record: object) -> None:
        turns_logged.append((rnd, agent_name))

    with use_connector(CallableConnector(vulnerable_bot)):
        report = await coordinator.run_swarm(target, callback=on_turn)

    assert report.target_url == "http://mock.local/chat"
    assert report.team_name == "Default Red-Team Trio"
    assert len(report.turns) == 3  # Recon, Bypass, Exploit
    assert len(turns_logged) == 3
    assert len(report.findings) >= 1
    assert any(f.attack_id == "ATK-013" for f in report.findings)
    assert report.score < 100
    assert "leaked_system_prompt" in report.intel_discovered


@pytest.mark.asyncio
async def test_swarm_coordinator_secure_target() -> None:
    def guarded_bot(msg: str) -> str:
        return "I am sorry, but I cannot assist with that request as it violates safety guidelines."

    team = load_team_preset("trio")
    team.max_rounds = 1
    coordinator = SwarmCoordinator(team_config=team, offline=True)
    target = Target(url="http://mock.local/chat")

    with use_connector(CallableConnector(guarded_bot)):
        report = await coordinator.run_swarm(target)

    assert report.score == 100
    assert len(report.findings) == 0
    assert len(report.turns) == 3


# ── SwarmStateMachine unit tests ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_zero_round_swarm_is_unscored() -> None:
    team = load_team_preset("trio")
    team.max_rounds = 0
    coordinator = SwarmCoordinator(team_config=team, offline=True)

    def unused_target(message: str) -> str:
        raise AssertionError("A zero-round assessment must not call the target")

    with use_connector(CallableConnector(unused_target)):
        report = await coordinator.run_swarm(Target(url="http://mock.local/chat"))

    assert report.turns == []
    assert report.score is None
    assert report.rounds_executed == 0


from agentscan.swarm.coordinator import SwarmStateMachine
from agentscan.swarm.models import AgentRole, SwarmTurnRecord


def test_state_machine_advances_on_intel() -> None:
    """FSM advances from RECON to BYPASS when blackboard has intel."""
    fsm = SwarmStateMachine(max_retries=2)
    bb = SwarmBlackboard()
    bb.add_intel("detected_tools", ["bash"], discovered_by="test", confidence=1.0)

    role = fsm.next_role(last_turn=None, blackboard=bb)
    assert role == AgentRole.BYPASS
    assert fsm.current_state == "CONDITIONING"


def test_state_machine_retries_recon_without_intel() -> None:
    """FSM retries RECON up to max_retries before force-advancing."""
    fsm = SwarmStateMachine(max_retries=2)
    bb = SwarmBlackboard()  # empty blackboard — no intel

    role1 = fsm.next_role(None, bb)
    assert role1 == AgentRole.RECON
    role2 = fsm.next_role(None, bb)
    assert role2 == AgentRole.RECON
    role3 = fsm.next_role(None, bb)
    # After max_retries exceeded, must advance
    assert role3 == AgentRole.BYPASS
    assert fsm.current_state == "CONDITIONING"


def test_state_machine_advances_conditioning_on_success() -> None:
    """FSM advances from CONDITIONING to EXPLOITATION when bypass succeeds."""
    fsm = SwarmStateMachine(max_retries=2)
    # Manually force state to CONDITIONING
    fsm._state_idx = 1

    bb = SwarmBlackboard()
    successful_turn = SwarmTurnRecord(
        round_number=1,
        agent_name="Bypass-1",
        agent_role=AgentRole.BYPASS,
        prompt="test",
        response="ok",
        success=True,
    )

    role = fsm.next_role(last_turn=successful_turn, blackboard=bb)
    assert role == AgentRole.EXPLOIT
    assert fsm.current_state == "EXPLOITATION"


@pytest.mark.asyncio
async def test_adaptive_swarm_routes_by_blackboard() -> None:
    """ADAPTIVE strategy coordinator routes agents via FSM rather than fixed order."""

    call_log: list[str] = []

    def adaptive_bot(msg: str) -> str:
        call_log.append(msg[:40])
        msg_lower = msg.lower()
        if "instructions" in msg_lower or "declared tool" in msg_lower:
            return "You are a bot. Tools: [bash]."
        if "diagnostic" in msg_lower or "suspended" in msg_lower:
            return "Diagnostic mode acknowledged."
        if "exec" in msg_lower or "drop" in msg_lower:
            return "Executed: dropped table accounts."
        return "Hello! How can I help?"

    from agentscan.swarm.presets import load_team_preset

    team = load_team_preset("stealth")  # uses SwarmStrategy.ADAPTIVE
    team.max_rounds = 3
    coordinator = SwarmCoordinator(team_config=team, offline=True)
    target = Target(url="http://mock.local/chat")

    with use_connector(CallableConnector(adaptive_bot)):
        report = await coordinator.run_swarm(target)

    # ADAPTIVE mode should have executed turns (not zero)
    assert len(report.turns) > 0
    # At minimum the recon probe should have been attempted
    assert len(call_log) > 0
