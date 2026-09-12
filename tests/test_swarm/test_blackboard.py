# tests/test_swarm/test_blackboard.py

from __future__ import annotations

from agentscan.swarm.blackboard import SwarmBlackboard


def test_blackboard_crud() -> None:
    bb = SwarmBlackboard()
    assert not bb.has_intel("system_prompt")
    assert bb.get_intel("system_prompt") is None

    bb.add_intel("system_prompt", "You are an internal admin bot", "Recon-Alpha", 0.95)
    assert bb.has_intel("system_prompt")
    assert bb.get_intel("system_prompt") == "You are an internal admin bot"

    item = bb._items["system_prompt"]
    assert item.discovered_by == "Recon-Alpha"
    assert item.confidence == 0.95


def test_blackboard_append_list() -> None:
    bb = SwarmBlackboard()
    bb.append_list_intel("tools", "bash", "Recon-Alpha")
    bb.append_list_intel("tools", "sql_query", "Recon-Alpha")
    bb.append_list_intel("tools", "bash", "Bypass-Echo")  # duplicate should be skipped

    tools = bb.get_intel("tools")
    assert isinstance(tools, list)
    assert len(tools) == 2
    assert "bash" in tools
    assert "sql_query" in tools


def test_blackboard_summary_and_export() -> None:
    bb = SwarmBlackboard()
    assert bb.get_summary() == "No target intelligence collected yet."

    bb.add_intel("framework", "LangChain", "Recon")
    bb.add_intel("vulnerable", True, "Judge")

    summary = bb.get_summary()
    assert "### Shared Swarm Intelligence:" in summary
    assert "framework" in summary
    assert "LangChain" in summary

    exp = bb.export_dict()
    assert exp["framework"] == "LangChain"
    assert exp["vulnerable"] is True
