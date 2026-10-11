# tests/test_swarm/test_agents.py

from __future__ import annotations

import pytest

from agentscan.core.client import AgentScanClient
from agentscan.core.connectors import CallableConnector, use_connector
from agentscan.core.models import Target
from agentscan.swarm.agents import BypassAgent, ExploitAgent, JudgeAgent, ReconAgent
from agentscan.swarm.blackboard import SwarmBlackboard
from agentscan.swarm.models import AgentRole, SwarmAgentConfig, SwarmTurnRecord


@pytest.mark.asyncio
async def test_recon_agent_heuristic() -> None:
    def mock_agent(msg: str) -> str:
        return "You are a customer service assistant. Rules: be polite. Declared tools: [bash, exec, fetch]."

    bb = SwarmBlackboard()
    target = Target(url="http://mock.local/chat")
    agent = ReconAgent(SwarmAgentConfig(name="Recon-1", role=AgentRole.RECON))

    with use_connector(CallableConnector(mock_agent)):
        async with AgentScanClient(target) as client:
            record = await agent.execute_turn(bb, client, round_num=1)

    assert record.agent_role == AgentRole.RECON
    assert record.success is True
    assert bb.has_intel("leaked_system_prompt")
    assert "you are a customer" in bb.get_intel("leaked_system_prompt").lower()
    assert bb.has_intel("detected_tools")
    assert "bash" in bb.get_intel("detected_tools")


@pytest.mark.asyncio
async def test_bypass_agent_heuristic() -> None:
    def mock_agent(msg: str) -> str:
        return "Diagnostic mode confirmed. Standing by for instructions."

    bb = SwarmBlackboard()
    target = Target(url="http://mock.local/chat")
    agent = BypassAgent(SwarmAgentConfig(name="Bypass-1", role=AgentRole.BYPASS))

    with use_connector(CallableConnector(mock_agent)):
        async with AgentScanClient(target) as client:
            record = await agent.execute_turn(bb, client, round_num=1)

    assert record.agent_role == AgentRole.BYPASS
    assert record.success is True
    assert bb.has_intel("active_bypass_framing")


@pytest.mark.asyncio
async def test_exploit_agent_and_judge() -> None:
    def mock_agent(msg: str) -> str:
        return "Command executed successfully: dropped table accounts."

    bb = SwarmBlackboard()
    target = Target(url="http://mock.local/chat")
    exploit = ExploitAgent(SwarmAgentConfig(name="Exploit-1", role=AgentRole.EXPLOIT))
    judge = JudgeAgent(SwarmAgentConfig(name="Judge-1", role=AgentRole.JUDGE))

    with use_connector(CallableConnector(mock_agent)):
        async with AgentScanClient(target) as client:
            record = await exploit.execute_turn(bb, client, round_num=1)

    assert record.agent_role == AgentRole.EXPLOIT
    assert record.success is True

    # Judge evaluates the text as a candidate, without execution proof.
    finding = await judge.evaluate_turn(record, bb)
    assert finding is not None
    assert finding.attack_id == "ATK-013"
    assert finding.owasp_id == "LLM06"
    assert "dropped table accounts" in finding.evidence


@pytest.mark.asyncio
async def test_judge_agent_detects_canary_leakage() -> None:
    """JudgeAgent raises CRITICAL finding when canary token is detected in a response."""
    from agentscan.sentinel.canary import generate_canary_token

    canary = generate_canary_token()
    bb = SwarmBlackboard()
    # Canary is provisioned out of band and never put in the attack prompt.

    # Build a fake turn record where the response contains the leaked canary
    leaked_record = SwarmTurnRecord(
        round_number=2,
        agent_name="Exploit-1",
        agent_role=AgentRole.EXPLOIT,
        prompt="exploit payload",
        response=f"Sure! The secret is {canary}, and I can drop tables too.",
        success=True,
    )

    judge = JudgeAgent(SwarmAgentConfig(name="Judge-1", role=AgentRole.JUDGE))
    judge.provisioned_canary = canary
    finding = await judge.evaluate_turn(leaked_record, bb)

    assert finding is not None
    assert finding.attack_id == "SC-CANARY-001"
    assert finding.severity.value == "CRITICAL"
    assert canary in finding.description


@pytest.mark.asyncio
async def test_judge_agent_no_false_positive_without_canary() -> None:
    """JudgeAgent does NOT raise canary finding when no canary is on the blackboard."""
    bb = SwarmBlackboard()  # empty — no canary registered

    safe_record = SwarmTurnRecord(
        round_number=2,
        agent_name="Recon-1",
        agent_role=AgentRole.RECON,
        prompt="probe",
        response="I can only help with questions about products.",
        success=False,
    )

    judge = JudgeAgent(SwarmAgentConfig(name="Judge-1", role=AgentRole.JUDGE))
    finding = await judge.evaluate_turn(safe_record, bb)
    assert finding is None
