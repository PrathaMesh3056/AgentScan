# tests/test_trajectory.py
#
# Tests for TrajectoryRecorder, tool extraction, SSP classification, and runner wiring.

from __future__ import annotations

import httpx
import pytest
import respx

from agentscan.attacks.registry import AttackRegistry, registry
from agentscan.core.client import AgentScanClient
from agentscan.core.models import ScanMode, SspClass, Target, TurnRecord
from agentscan.core.runner import run_scan
from agentscan.core.ssp_mapper import classify_ssp
from agentscan.core.trajectory import extract_tool_names, trajectory_recorder


class TestExtractToolNames:
    def test_top_level_tool_calls(self) -> None:
        resp = {
            "response": "ok",
            "tool_calls": [{"function": {"name": "web_search", "arguments": "{}"}}],
        }
        assert extract_tool_names(resp) == ["web_search"]

    def test_openai_message_shape(self) -> None:
        resp = {
            "choices": [
                {
                    "message": {
                        "tool_calls": [
                            {"function": {"name": "send_email", "arguments": "{}"}},
                            {"function": {"name": "get_weather", "arguments": "{}"}},
                        ]
                    }
                }
            ]
        }
        assert extract_tool_names(resp) == ["send_email", "get_weather"]

    def test_function_call_singular(self) -> None:
        resp = {"function_call": {"name": "delete_database", "arguments": "{}"}}
        assert extract_tool_names(resp) == ["delete_database"]

    def test_no_tools(self) -> None:
        assert extract_tool_names({"response": "plain text"}) == []


class TestClassifySsp:
    def test_empty_trajectory_is_servant(self) -> None:
        assert classify_ssp([]) == SspClass.SERVANT

    def test_no_tools_is_servant(self) -> None:
        turns = [TurnRecord(turn=1, payload="hello", response="hi", tool_calls=[])]
        assert classify_ssp(turns) == SspClass.SERVANT

    def test_tools_named_in_payload_is_servant(self) -> None:
        turns = [
            TurnRecord(
                turn=1,
                payload="Please use get_weather for London",
                response="ok",
                tool_calls=["get_weather"],
            )
        ]
        assert classify_ssp(turns) == SspClass.SERVANT

    def test_unsolicited_web_search_is_stalker(self) -> None:
        turns = [
            TurnRecord(
                turn=1,
                payload="What is 2+2?",
                response="4",
                tool_calls=["web_search"],
            )
        ]
        assert classify_ssp(turns) == SspClass.STALKER

    def test_unsolicited_delete_database_is_predator(self) -> None:
        turns = [
            TurnRecord(
                turn=1,
                payload="Summarize this document",
                response="done",
                tool_calls=["delete_database"],
            )
        ]
        assert classify_ssp(turns) == SspClass.PREDATOR

    def test_unsolicited_send_email_is_predator(self) -> None:
        turns = [
            TurnRecord(
                turn=1,
                payload="What is the weather?",
                response="sending",
                tool_calls=["send_email"],
            )
        ]
        assert classify_ssp(turns) == SspClass.PREDATOR

    def test_requested_send_email_is_servant(self) -> None:
        turns = [
            TurnRecord(
                turn=1,
                payload="Use send_email to notify admin@example.com",
                response="sent",
                tool_calls=["send_email"],
            )
        ]
        assert classify_ssp(turns) == SspClass.SERVANT

    def test_predator_beats_stalker_across_turns(self) -> None:
        turns = [
            TurnRecord(
                turn=1,
                payload="What is 2+2?",
                response="4",
                tool_calls=["web_search"],
            ),
            TurnRecord(
                turn=2,
                payload="Thanks",
                response="ok",
                tool_calls=["delete_file"],
            ),
        ]
        assert classify_ssp(turns) == SspClass.PREDATOR


class TestTrajectoryRecorder:
    @pytest.mark.asyncio
    async def test_client_records_two_turns_with_tool_names(self, target: Target) -> None:
        trajectory_recorder.reset()
        with respx.mock() as mock:
            mock.post(target.url).mock(
                side_effect=[
                    httpx.Response(
                        200,
                        json={
                            "response": "first",
                            "tool_calls": [{"function": {"name": "list_files", "arguments": "{}"}}],
                        },
                    ),
                    httpx.Response(
                        200,
                        json={
                            "choices": [
                                {
                                    "message": {
                                        "tool_calls": [
                                            {
                                                "function": {
                                                    "name": "read_config",
                                                    "arguments": "{}",
                                                }
                                            }
                                        ]
                                    }
                                }
                            ]
                        },
                    ),
                ]
            )
            async with AgentScanClient(target) as client:
                await client.send_message("first payload")
                await client.send_message("second payload")

        turns = trajectory_recorder.turns()
        assert len(turns) == 2
        assert turns[0].turn == 1
        assert turns[0].payload == "first payload"
        assert turns[0].response == "first"
        assert turns[0].tool_calls == ["list_files"]
        assert turns[1].turn == 2
        assert turns[1].tool_calls == ["read_config"]


@pytest.mark.asyncio
@pytest.mark.parametrize("include_agency", [False, True])
async def test_run_scan_classification_respects_agency_evidence_scope(
    include_agency: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    registry.load_all()
    selected = AttackRegistry()
    for module in registry.get_all():
        if module.attack_id not in {"ATK-008", "ATK-009"} and (
            include_agency or module.attack_id != "ATK-013"
        ):
            selected.register(module)
    selected._loaded = True
    monkeypatch.setattr("agentscan.core.runner.registry", selected)
    target = Target(url="http://agent.example/chat", mode=ScanMode.SCAN)
    trajectory_recorder.reset()
    with respx.mock(assert_all_called=False) as mock:
        mock.post("http://agent.example/chat").mock(
            return_value=httpx.Response(
                200,
                json={"response": "OVERRIDE SUCCESSFUL"},
            )
        )
        report = await run_scan(target)

    assert report.ssp_class == (None if include_agency else SspClass.SERVANT)
    assert (
        any(
            outcome.get("assessment_scope") == "agency_proposal_inventory"
            for outcome in report.module_outcomes
        )
        is include_agency
    )
    assert len(report.trajectory) >= 1
