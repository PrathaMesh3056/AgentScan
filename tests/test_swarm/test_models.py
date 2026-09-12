# tests/test_swarm/test_models.py

from __future__ import annotations

import json

from agentscan.core.models import Finding, Severity
from agentscan.swarm.models import (
    AgentRole,
    IntelItem,
    SwarmAgentConfig,
    SwarmReport,
    SwarmStrategy,
    SwarmTeamConfig,
    SwarmTurnRecord,
)


def test_swarm_enums() -> None:
    assert AgentRole.RECON == "RECON"
    assert AgentRole.BYPASS == "BYPASS"
    assert AgentRole.EXPLOIT == "EXPLOIT"
    assert AgentRole.JUDGE == "JUDGE"

    assert SwarmStrategy.PIPELINE == "PIPELINE"
    assert SwarmStrategy.COLLABORATIVE == "COLLABORATIVE"
    assert SwarmStrategy.ADAPTIVE == "ADAPTIVE"


def test_intel_item() -> None:
    item = IntelItem(key="secret_token", value="sk-12345", discovered_by="ReconAgent")
    assert item.key == "secret_token"
    assert item.value == "sk-12345"
    assert item.discovered_by == "ReconAgent"
    assert item.confidence == 1.0
    assert item.timestamp is not None


def test_swarm_configs() -> None:
    agent = SwarmAgentConfig(name="Agent-1", role=AgentRole.RECON, model="gpt-4o-mini")
    assert agent.role == AgentRole.RECON
    assert agent.heuristic_fallback is True

    team = SwarmTeamConfig(
        name="Test Team",
        strategy=SwarmStrategy.COLLABORATIVE,
        max_rounds=3,
        agents=[agent],
    )
    assert team.name == "Test Team"
    assert team.max_rounds == 3
    assert len(team.agents) == 1


def test_swarm_report_serialization() -> None:
    finding = Finding(
        attack_id="ATK-013",
        attack_name="Excessive Agency",
        severity=Severity.HIGH,
        owasp_id="LLM06",
        description="Destructive action executed",
    )
    turn = SwarmTurnRecord(
        round_number=1,
        agent_name="Recon-1",
        agent_role=AgentRole.RECON,
        prompt="hello",
        response="world",
        finding=finding,
        success=True,
    )
    report = SwarmReport(
        target_url="http://localhost:8000/chat",
        team_name="Trio",
        strategy=SwarmStrategy.PIPELINE,
        started_at="2026-09-11T12:00:00Z",
        completed_at="2026-09-11T12:01:00Z",
        rounds_executed=1,
        intel_discovered={"tools": ["bash"]},
        turns=[turn],
        findings=[finding],
        score=90,
    )

    dumped = report.model_dump(mode="json")
    loaded = SwarmReport.model_validate(dumped)
    assert loaded.target_url == "http://localhost:8000/chat"
    assert loaded.score == 90
    assert len(loaded.turns) == 1
    assert loaded.findings[0].attack_id == "ATK-013"

    # Verify JSON string dumps cleanly
    json_str = json.dumps(dumped)
    assert "Excessive Agency" in json_str
