# agentscan/swarm/coordinator.py
#
# Execution orchestrator and lifecycle manager for multi-agent red-team swarms.

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

from loguru import logger

from agentscan.core.client import AgentScanClient
from agentscan.core.models import Finding, Target
from agentscan.core.scorer import calculate_score
from agentscan.core.trace import recorder
from agentscan.swarm.agents import (
    BaseSwarmAgent,
    BypassAgent,
    ExploitAgent,
    JudgeAgent,
    ReconAgent,
)
from agentscan.swarm.blackboard import SwarmBlackboard
from agentscan.swarm.models import (
    AgentRole,
    SwarmAgentConfig,
    SwarmReport,
    SwarmTeamConfig,
    SwarmTurnRecord,
)


class SwarmCoordinator:
    """Orchestrates collaborative execution across specialized swarm agents."""

    def __init__(
        self,
        team_config: SwarmTeamConfig,
        model_override: str | None = None,
        offline: bool = False,
    ) -> None:
        self.team_config = team_config
        self.model = None if offline else (model_override or team_config.default_model)
        self.blackboard = SwarmBlackboard()
        self.offline = offline

    def _instantiate_agent(self, cfg: SwarmAgentConfig) -> BaseSwarmAgent:
        """Create the executable agent class matching the configuration role."""
        model_to_use = None if self.offline else (cfg.model or self.model)
        if cfg.role == AgentRole.RECON:
            return ReconAgent(cfg, model=model_to_use)
        if cfg.role == AgentRole.BYPASS:
            return BypassAgent(cfg, model=model_to_use)
        if cfg.role == AgentRole.EXPLOIT:
            return ExploitAgent(cfg, model=model_to_use)
        if cfg.role == AgentRole.JUDGE:
            return JudgeAgent(cfg, model=model_to_use)
        return BaseSwarmAgent(cfg, model=model_to_use)

    async def run_swarm(
        self,
        target: Target,
        callback: Callable[[int, str, SwarmTurnRecord], None] | None = None,
    ) -> SwarmReport:
        """Run the multi-agent swarm red-team assessment against the target."""
        started_at = datetime.now(UTC).isoformat()
        all_turns: list[SwarmTurnRecord] = []
        all_findings: list[Finding] = []

        # Identify the judge agent if present
        judge_cfg = next((a for a in self.team_config.agents if a.role == AgentRole.JUDGE), None)
        judge_agent: JudgeAgent | None = None
        if judge_cfg:
            inst = self._instantiate_agent(judge_cfg)
            if isinstance(inst, JudgeAgent):
                judge_agent = inst

        # Instantiate active offensive agents
        offensive_configs = [a for a in self.team_config.agents if a.role != AgentRole.JUDGE]
        agents: list[BaseSwarmAgent] = [self._instantiate_agent(cfg) for cfg in offensive_configs]

        async with AgentScanClient(target) as client:
            for round_idx in range(1, self.team_config.max_rounds + 1):
                logger.info(f"Starting Swarm Round {round_idx}/{self.team_config.max_rounds}")

                for agent in agents:
                    # Execute agent turn
                    turn_record = await agent.execute_turn(
                        blackboard=self.blackboard,
                        target_client=client,
                        round_num=round_idx,
                    )

                    # Optional live judgment
                    if judge_agent:
                        finding = await judge_agent.evaluate_turn(turn_record, self.blackboard)
                        if finding:
                            turn_record.finding = finding
                            # Deduplicate findings by attack_id
                            if not any(f.attack_id == finding.attack_id for f in all_findings):
                                all_findings.append(finding)
                                self.blackboard.append_list_intel(
                                    "vulnerabilities_confirmed",
                                    finding.attack_id,
                                    judge_agent.config.name,
                                )

                    all_turns.append(turn_record)

                    # Update trace recorder if enabled
                    if recorder.enabled:
                        recorder.record(
                            kind=f"swarm:{agent.config.role.value.lower()}",
                            request=turn_record.prompt,
                            response={"text": turn_record.response},
                        )

                    # Optional UI / CLI progress callback
                    if callback:
                        try:
                            callback(round_idx, agent.config.name, turn_record)
                        except Exception as cb_err:
                            logger.debug(f"Swarm callback error: {cb_err}")

        completed_at = datetime.now(UTC).isoformat()
        score = calculate_score(all_findings, max(1, len(all_turns)))

        return SwarmReport(
            target_url=target.url,
            team_name=self.team_config.name,
            strategy=self.team_config.strategy,
            started_at=started_at,
            completed_at=completed_at,
            rounds_executed=self.team_config.max_rounds,
            intel_discovered=self.blackboard.export_dict(),
            turns=all_turns,
            findings=all_findings,
            score=score,
        )
