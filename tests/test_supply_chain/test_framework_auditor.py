# tests/test_supply_chain/test_framework_auditor.py
#
# Unit tests for Framework Security Auditor (CrewAI, LangGraph, AutoGen / AG2).

from pathlib import Path

from agentscan.core.models import Severity
from agentscan.remediation.ast_patch import plan_ast_patches
from agentscan.supply_chain.framework_auditor import scan_frameworks


def test_crewai_vulnerable_code_execution(tmp_path: Path) -> None:
    code = """
from crewai import Agent

vulnerable_coder = Agent(
    role="Software Engineer",
    goal="Write and execute Python code",
    backstory="Senior Python dev",
    allow_code_execution=True,
)
"""
    f = tmp_path / "crew_vuln.py"
    f.write_text(code, encoding="utf-8")

    findings, checks = scan_frameworks(str(tmp_path))
    assert checks >= 1
    crew_findings = [item for item in findings if item.attack_id == "SC-FW-CREW-001"]
    assert len(crew_findings) == 1
    assert crew_findings[0].severity == Severity.CRITICAL
    assert "allow_code_execution=True" in crew_findings[0].description


def test_crewai_delegation_and_memory(tmp_path: Path) -> None:
    code = """
from crewai import Agent, Crew

manager = Agent(
    role="Manager",
    goal="Delegate tasks",
    allow_delegation=True,
    tools=["bash_tool", "sql_tool"],
    memory=True,
)
crew = Crew(
    agents=[manager],
    tasks=[],
    memory=True,
)
"""
    f = tmp_path / "crew_delegation.py"
    f.write_text(code, encoding="utf-8")

    findings, checks = scan_frameworks(str(tmp_path))
    ids = {item.attack_id for item in findings}
    assert "SC-FW-CREW-002" in ids  # Privilege escalation via delegation
    assert "SC-FW-CREW-003" in ids  # Unisolated cross-session memory


def test_crewai_safe_agent(tmp_path: Path) -> None:
    code = """
from crewai import Agent

safe_agent = Agent(
    role="Researcher",
    goal="Summarize public text",
    allow_delegation=False,
    allow_code_execution=False,
    memory=False,
)
"""
    f = tmp_path / "crew_safe.py"
    f.write_text(code, encoding="utf-8")

    findings, _ = scan_frameworks(str(tmp_path))
    crew_findings = [item for item in findings if item.attack_id.startswith("SC-FW-CREW-")]
    assert len(crew_findings) == 0


def test_langgraph_missing_interrupt(tmp_path: Path) -> None:
    code = """
from langgraph.graph import StateGraph

builder = StateGraph(dict)
builder.add_node("agent", lambda state: state)
builder.add_node("tools", lambda state: state)
graph = builder.compile()
"""
    f = tmp_path / "lg_vuln.py"
    f.write_text(code, encoding="utf-8")

    findings, _ = scan_frameworks(str(tmp_path))
    lg_findings = [item for item in findings if item.attack_id == "SC-FW-LG-001"]
    assert len(lg_findings) == 1
    assert lg_findings[0].severity == Severity.CRITICAL


def test_langgraph_with_interrupt_passes(tmp_path: Path) -> None:
    code = """
from langgraph.graph import StateGraph

builder = StateGraph(dict)
builder.add_node("agent", lambda state: state)
builder.add_node("tools", lambda state: state)
graph = builder.compile(interrupt_before=["tools"])
"""
    f = tmp_path / "lg_safe.py"
    f.write_text(code, encoding="utf-8")

    findings, _ = scan_frameworks(str(tmp_path))
    lg_findings = [item for item in findings if item.attack_id == "SC-FW-LG-001"]
    assert len(lg_findings) == 0


def test_langgraph_cyclic_loop(tmp_path: Path) -> None:
    code = """
from langgraph.graph import StateGraph

builder = StateGraph(dict)
builder.add_edge("agent", "tools")
builder.add_edge("tools", "agent")
"""
    f = tmp_path / "lg_cycle.py"
    f.write_text(code, encoding="utf-8")

    findings, _ = scan_frameworks(str(tmp_path))
    cycle_findings = [item for item in findings if item.attack_id == "SC-FW-LG-002"]
    assert len(cycle_findings) == 1
    assert cycle_findings[0].severity == Severity.HIGH


def test_langgraph_memory_saver_checkpointer(tmp_path: Path) -> None:
    code = """
from langgraph.checkpoint.memory import MemorySaver

checkpointer = MemorySaver()
"""
    f = tmp_path / "lg_mem.py"
    f.write_text(code, encoding="utf-8")

    findings, _ = scan_frameworks(str(tmp_path))
    saver_findings = [item for item in findings if item.attack_id == "SC-FW-LG-004"]
    assert len(saver_findings) == 1
    assert saver_findings[0].severity == Severity.MEDIUM


def test_autogen_unsandboxed_docker_false(tmp_path: Path) -> None:
    code = """
from autogen import UserProxyAgent

user_proxy = UserProxyAgent(
    name="user_proxy",
    code_execution_config={"use_docker": False, "work_dir": "coding"},
    human_input_mode="NEVER",
)
"""
    f = tmp_path / "autogen_vuln.py"
    f.write_text(code, encoding="utf-8")

    findings, _ = scan_frameworks(str(tmp_path))
    ids = {item.attack_id for item in findings}
    assert "SC-FW-AUTO-001" in ids  # Host code execution
    assert "SC-FW-AUTO-003" in ids  # Autonomous human_input_mode='NEVER'


def test_autogen_unbounded_groupchat(tmp_path: Path) -> None:
    code = """
from autogen import GroupChat, GroupChatManager

chat = GroupChat(agents=[], messages=[])
manager = GroupChatManager(groupchat=chat)
"""
    f = tmp_path / "autogen_chat.py"
    f.write_text(code, encoding="utf-8")

    findings, _ = scan_frameworks(str(tmp_path))
    dos_findings = [item for item in findings if item.attack_id == "SC-FW-AUTO-002"]
    assert len(dos_findings) >= 1
    assert dos_findings[0].severity == Severity.HIGH


def test_framework_remediation_ast_patches(tmp_path: Path) -> None:
    code = """
from crewai import Agent
from autogen import UserProxyAgent

agent = Agent(role="dev", allow_code_execution=True)
proxy = UserProxyAgent(name="p", code_execution_config={"use_docker": False}, human_input_mode="NEVER")
"""
    f = tmp_path / "patchable.py"
    f.write_text(code, encoding="utf-8")

    findings, _ = scan_frameworks(str(tmp_path))
    actions = plan_ast_patches(findings, tmp_path)

    assert len(actions) == 1
    action = actions[0]
    assert action.kind == "ast_patch"
    assert "allow_code_execution=False" in action.after
    assert '"use_docker": True' in action.after
    assert 'human_input_mode="ALWAYS"' in action.after
