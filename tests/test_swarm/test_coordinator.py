# tests/test_swarm/test_coordinator.py

from __future__ import annotations

import pytest

from agentscan.core.connectors import CallableConnector, use_connector
from agentscan.core.models import Target
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
