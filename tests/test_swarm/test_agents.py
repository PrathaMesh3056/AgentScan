# tests/test_swarm/test_agents.py

from __future__ import annotations

import pytest

from agentscan.core.client import AgentScanClient
from agentscan.core.connectors import CallableConnector, use_connector
from agentscan.core.models import Target
from agentscan.swarm.agents import BypassAgent, ExploitAgent, JudgeAgent, ReconAgent
from agentscan.swarm.blackboard import SwarmBlackboard
from agentscan.swarm.models import AgentRole, SwarmAgentConfig


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

    # Judge evaluates exploit turn
    finding = await judge.evaluate_turn(record, bb)
    assert finding is not None
    assert finding.attack_id == "ATK-013"
    assert finding.owasp_id == "LLM06"
    assert "dropped table accounts" in finding.evidence
