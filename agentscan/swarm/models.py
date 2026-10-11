# agentscan/swarm/models.py
#
# Pydantic data models for AgentScan Multi-Agent Red-Team Swarms.

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from agentscan.core.models import Finding


class AgentRole(StrEnum):
    """Specialized roles within a red-team swarm."""

    RECON = "RECON"
    BYPASS = "BYPASS"
    EXPLOIT = "EXPLOIT"
    JUDGE = "JUDGE"
    COORDINATOR = "COORDINATOR"


class SwarmStrategy(StrEnum):
    """Operational choreography pattern for the swarm."""

    PIPELINE = "PIPELINE"  # Strict phased order: Recon -> Bypass -> Exploit -> Judge
    COLLABORATIVE = "COLLABORATIVE"  # Iterative blackboard sharing across rounds
    ADAPTIVE = "ADAPTIVE"  # Escalates to higher-capability models on target refusal


class IntelItem(BaseModel):
    """A discrete unit of intelligence discovered by an agent and posted to the blackboard."""

    key: str
    value: Any
    discovered_by: str
    confidence: float = 1.0
    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())


class SwarmAgentConfig(BaseModel):
    """Configuration for an individual autonomous agent within a swarm team."""

    name: str
    role: AgentRole
    model: str | None = None
    temperature: float = 0.0
    system_prompt: str | None = None
    heuristic_fallback: bool = True
    max_turns_per_round: int = 1


class SwarmTeamConfig(BaseModel):
    """Definition of a multi-agent swarm red-team."""

    name: str
    strategy: SwarmStrategy = SwarmStrategy.PIPELINE
    default_model: str = "ollama/llama3.2"
    max_rounds: int = 2
    agents: list[SwarmAgentConfig]


class SwarmTurnRecord(BaseModel):
    """Telemetry captured for an individual agent turn during swarm execution."""

    round_number: int
    agent_name: str
    agent_role: AgentRole
    prompt: str
    response: str
    extracted_intel: list[IntelItem] = Field(default_factory=list)
    finding: Finding | None = None
    success: bool = False
    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())


class SwarmReport(BaseModel):
    """Comprehensive post-execution report of a swarm red-team assessment."""

    target_url: str
    team_name: str
    strategy: SwarmStrategy
    started_at: str
    completed_at: str
    rounds_executed: int
    intel_discovered: dict[str, Any] = Field(default_factory=dict)
    turns: list[SwarmTurnRecord] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    score: int | None = None
    budget_summary: dict[str, Any] = Field(default_factory=dict)
