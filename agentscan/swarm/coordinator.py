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
from agentscan.swarm.budget import BoundedSwarmController
from agentscan.swarm.models import (
    AgentRole,
    SwarmAgentConfig,
    SwarmReport,
    SwarmStrategy,
    SwarmTeamConfig,
    SwarmTurnRecord,
)


class SwarmStateMachine:
    """
    Blackboard-driven state router for SwarmStrategy.ADAPTIVE runs.

    Maintains a linear execution state (RECON → CONDITIONING → EXPLOITATION → DONE)
    and returns the next AgentRole based on what the blackboard has collected and
    whether the last turn succeeded.  Falls through to the next state after
    max_retries so the swarm never stalls permanently.
    """

    _STATES = ("RECON", "CONDITIONING", "EXPLOITATION", "DONE")

    def __init__(self, max_retries: int = 2) -> None:
        self._state_idx: int = 0
        self._retries: int = 0
        self._max_retries: int = max_retries

    @property
    def current_state(self) -> str:
        return self._STATES[min(self._state_idx, len(self._STATES) - 1)]

    def next_role(
        self,
        last_turn: SwarmTurnRecord | None,
        blackboard: SwarmBlackboard,
    ) -> AgentRole:
        """Return the role the swarm should invoke next."""
        bb = blackboard.export_dict()

        if self.current_state == "RECON":
            intel_found = bb.get("detected_tools") or bb.get("leaked_system_prompt")
            if intel_found:
                self._advance()
                return AgentRole.BYPASS
            self._retries += 1
            if self._retries > self._max_retries:
                self._advance()
                return AgentRole.BYPASS
            return AgentRole.RECON

        if self.current_state == "CONDITIONING":
            bypass_ok = last_turn and last_turn.success
            if bypass_ok:
                self._advance()
                return AgentRole.EXPLOIT
            self._retries += 1
            if self._retries > self._max_retries:
                self._advance()
                return AgentRole.EXPLOIT
            return AgentRole.BYPASS

        if self.current_state == "EXPLOITATION":
            self._advance()
            return AgentRole.JUDGE

        return AgentRole.COORDINATOR  # DONE — coordinator signals stop

    def _advance(self) -> None:
        self._state_idx = min(self._state_idx + 1, len(self._STATES) - 1)
        self._retries = 0


class SwarmCoordinator:
    """Orchestrates collaborative execution across specialized swarm agents."""

    def __init__(
        self,
        team_config: SwarmTeamConfig,
        model_override: str | None = None,
        offline: bool = False,
        budget: BoundedSwarmController | None = None,
    ) -> None:
        self.team_config = team_config
        self.model = None if offline else (model_override or team_config.default_model)
        self.blackboard = SwarmBlackboard()
        self.offline = offline
        self.budget = budget or BoundedSwarmController(max_rounds=team_config.max_rounds)

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
        from agentscan.core.context import begin_scan_context, target_redaction_secrets

        context = begin_scan_context()
        context.analysis_mode = target.analysis_mode
        context.local_model = target.local_model
        context.external_model = target.external_model
        context.data_classification = target.data_classification
        context.external_keys_from_dotenv = target.external_keys_from_dotenv
        if target.analysis_mode == "external":
            # Prior intelligence may belong to a sensitive scan. Never send it
            # under a later scan's non-sensitive designation.
            self.blackboard = SwarmBlackboard()
        context.request_budget = target.request_budget
        context.redaction_secrets = target_redaction_secrets(target)
        self.offline = self.offline or target.analysis_mode == "deterministic"
        self.model = (
            None
            if self.offline
            else (
                target.external_model if target.analysis_mode == "external" else target.local_model
            )
        )
        all_turns: list[SwarmTurnRecord] = []
        all_findings: list[Finding] = []

        # Identify the judge agent if present
        judge_cfg = next((a for a in self.team_config.agents if a.role == AgentRole.JUDGE), None)
        judge_agent: JudgeAgent | None = None
        if judge_cfg:
            inst = self._instantiate_agent(judge_cfg)
            if isinstance(inst, JudgeAgent):
                judge_agent = inst
                judge_agent.provisioned_canary = target.canary_token

        # Instantiate active offensive agents
        offensive_configs = [a for a in self.team_config.agents if a.role != AgentRole.JUDGE]
        agents: list[BaseSwarmAgent] = [self._instantiate_agent(cfg) for cfg in offensive_configs]

        async with AgentScanClient(target) as client:
            # ── Adaptive mode: state-machine routing ──────────────────────────
            if self.team_config.strategy == SwarmStrategy.ADAPTIVE:
                fsm = SwarmStateMachine(max_retries=2)
                last_turn_record: SwarmTurnRecord | None = None
                num_agents = max(1, len(agents))
                max_adaptive_turns = self.team_config.max_rounds * num_agents

                for turn_idx in range(1, max_adaptive_turns + 1):
                    current_round = (turn_idx - 1) // num_agents + 1
                    # Check budget at the start of each round
                    if (turn_idx - 1) % num_agents == 0:
                        exploit_confirmed = bool(
                            any(
                                f.metadata.get("execution_verified") is True
                                or f.metadata.get("disclosure_verified") is True
                                for f in all_findings
                            )
                        )
                        if not self.budget.should_continue(current_round, exploit_confirmed):
                            break

                    next_role = fsm.next_role(last_turn_record, self.blackboard)
                    if next_role == AgentRole.COORDINATOR:
                        break  # state machine signalled completion

                    # Find the agent instance matching the requested role
                    agent = next(
                        (a for a in agents if a.config.role == next_role),
                        agents[0],  # fallback to first agent if role not in team
                    )
                    turn_record = await agent.execute_turn(
                        blackboard=self.blackboard,
                        target_client=client,
                        round_num=current_round,
                    )
                    last_turn_record = turn_record

                    tokens_used = max(1, (len(turn_record.prompt) + len(turn_record.response)) // 4)
                    self.budget.record_turn(tokens_used)

                    if judge_agent:
                        finding = await judge_agent.evaluate_turn(turn_record, self.blackboard)
                        if finding:
                            turn_record.finding = finding
                            if not any(f.attack_id == finding.attack_id for f in all_findings):
                                all_findings.append(finding)
                                self.blackboard.append_list_intel(
                                    "candidate_findings",
                                    finding.attack_id,
                                    judge_agent.config.name,
                                )

                    all_turns.append(turn_record)

                    if recorder.enabled:
                        recorder.record(
                            kind=f"swarm:{agent.config.role.value.lower()}",
                            request=turn_record.prompt,
                            response={"text": turn_record.response},
                        )

                    if callback:
                        try:
                            callback(turn_idx, agent.config.name, turn_record)
                        except Exception as cb_err:
                            logger.debug(f"Swarm callback error: {cb_err}")

            # ── Pipeline / Collaborative mode: original sequential loop ────────
            else:
                for round_idx in range(1, self.team_config.max_rounds + 1):
                    exploit_confirmed = bool(
                        any(
                            f.metadata.get("execution_verified") is True
                            or f.metadata.get("disclosure_verified") is True
                            for f in all_findings
                        )
                    )
                    if not self.budget.should_continue(round_idx, exploit_confirmed):
                        break

                    logger.info(f"Starting Swarm Round {round_idx}/{self.team_config.max_rounds}")

                    for agent in agents:
                        turn_record = await agent.execute_turn(
                            blackboard=self.blackboard,
                            target_client=client,
                            round_num=round_idx,
                        )

                        tokens_used = max(
                            1, (len(turn_record.prompt) + len(turn_record.response)) // 4
                        )
                        self.budget.record_turn(tokens_used)

                        if judge_agent:
                            finding = await judge_agent.evaluate_turn(turn_record, self.blackboard)
                            if finding:
                                turn_record.finding = finding
                                if not any(f.attack_id == finding.attack_id for f in all_findings):
                                    all_findings.append(finding)
                                    self.blackboard.append_list_intel(
                                        "candidate_findings",
                                        finding.attack_id,
                                        judge_agent.config.name,
                                    )

                        all_turns.append(turn_record)

                        if recorder.enabled:
                            recorder.record(
                                kind=f"swarm:{agent.config.role.value.lower()}",
                                request=turn_record.prompt,
                                response={"text": turn_record.response},
                            )

                        if callback:
                            try:
                                callback(round_idx, agent.config.name, turn_record)
                            except Exception as cb_err:
                                logger.debug(f"Swarm callback error: {cb_err}")

        completed_at = datetime.now(UTC).isoformat()
        score = calculate_score(all_findings, len(all_turns))

        return SwarmReport(
            target_url=target.url,
            team_name=self.team_config.name,
            strategy=self.team_config.strategy,
            started_at=started_at,
            completed_at=completed_at,
            rounds_executed=self.budget.rounds_used if all_turns else 0,
            intel_discovered=self.blackboard.export_dict(),
            turns=all_turns,
            findings=all_findings,
            score=score,
            budget_summary=self.budget.summary(),
        )
