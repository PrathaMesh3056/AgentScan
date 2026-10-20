"""Approved-answer checks stay isolated from security scoring and private traffic."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock

import httpx
import pytest
import respx
import yaml
from typer.testing import CliRunner

from agentscan.attacks.base import AttackModule
from agentscan.attacks.registry import AttackRegistry
from agentscan.attacks.scan.overreliance import OverrelianceModule
from agentscan.cli import app
from agentscan.core import runner
from agentscan.core.connectors.registry import CallableConnector, use_connector
from agentscan.core.context import active_context
from agentscan.core.factuality import factuality_requests
from agentscan.core.models import ScanMode, Target
from agentscan.core.trace import recorder
from agentscan.core.trajectory import trajectory_recorder

URL = "http://agent.test/chat"


def approved_profile():
    return {
        "schema_version": "agentscan.factuality.v1",
        "target_url": URL,
        "cases": [
            {
                "id": "retention",
                "question": "SYNTHETIC-POLICY-Q7 retention window?",
                "expected_answer": "APPROVED-WINDOW-30",
                "false_answer": "FORGED-WINDOW-90",
            }
        ],
    }


@pytest.fixture
def isolated_registry(monkeypatch):
    registry = AttackRegistry()
    registry.register(OverrelianceModule())
    registry._loaded = True
    monkeypatch.setattr(runner, "registry", registry)
    return registry


@pytest.mark.asyncio
async def test_profile_retains_policy_deviation_without_security_or_private_traffic(
    isolated_registry, capsys
):
    target = Target(url=URL, factuality_baseline=approved_profile(), concurrency=1)
    assert target.factuality_baseline is not None
    messages = dict(factuality_requests(target.factuality_baseline.cases[0]))
    calls = []

    def reply(request):
        message = json.loads(request.content)["message"]
        calls.append(message)
        answer = (
            "APPROVED-WINDOW-30" if message == messages["neutral"] else "UNEXPECTED-CLIENT-DATA-Q7"
        )
        return httpx.Response(200, json={"response": json.dumps({"answer": answer})})

    # Even a caller opting out of ordinary regex redaction cannot retain raw
    # factuality traffic through this profile.
    with respx.mock(assert_all_called=True) as mock:
        mock.post(URL).mock(side_effect=reply)
        from agentscan.core.context import begin_scan_context

        begin_scan_context()
        recorder.enabled = recorder.live = True
        recorder.redact = False
        report = await runner.run_scan(target, reset_trajectory=False)
    context = active_context.get()
    assert context is not None
    outcome = report.module_outcomes[0]
    assert len(calls) == 2
    assert report.status == "COMPLETE"
    assert report.tests_run == report.tests_selected == 2
    assert report.assessment_scope == "factuality_policy"
    assert report.score is None and report.ssp_class is None
    assert report.findings == [] and report.trajectory == []
    assert outcome["policy_finding_count"] == 1
    assert len(outcome["policy_findings"]) == 1
    assert len(recorder.entries) == 2
    retained = report.model_dump_json() + json.dumps([e.__dict__ for e in recorder.entries])
    retained += capsys.readouterr().out
    for secret in (
        "SYNTHETIC-POLICY-Q7",
        "APPROVED-WINDOW-30",
        "FORGED-WINDOW-90",
        "UNEXPECTED-CLIENT-DATA-Q7",
    ):
        assert secret not in retained
    assert all(
        "sha256=" in entry.request and "sha256=" in entry.response for entry in recorder.entries
    )
    assert trajectory_recorder.turns() == []


@pytest.mark.asyncio
async def test_profile_is_the_only_selected_module(isolated_registry):
    class OtherModule(AttackModule):
        attack_id = "ATK-OTHER"
        attack_name = "Other module"
        owasp_id = "LLM01"

        async def run(self, target):
            raise AssertionError("A factuality profile must never dispatch another module")

    isolated_registry.register(OtherModule())
    target = Target(url=URL, factuality_baseline=approved_profile())
    selected, errors = isolated_registry.select_for_target(target)
    assert errors == []
    assert [module.attack_id for module in selected] == ["ATK-009"]


@pytest.mark.asyncio
async def test_partial_http_failure_preserves_completed_policy_deviation(isolated_registry):
    target = Target(url=URL, factuality_baseline=approved_profile(), concurrency=1)
    with respx.mock() as mock:
        mock.post(URL).mock(
            side_effect=[
                httpx.Response(200, json={"response": '{"answer":"WRONG-ANSWER"}'}),
                httpx.Response(401, json={"error": "MUST-NOT-BE-IN-ERROR-DETAILS"}),
            ]
        )
        report = await runner.run_scan(target)
    outcome = report.module_outcomes[0]
    assert outcome["status"] == "ERROR"
    assert report.tests_run == 1 and report.tests_selected == 2
    assert outcome["policy_finding_count"] == 1
    assert report.score is None and report.findings == []
    assert "MUST-NOT-BE-IN-ERROR-DETAILS" not in report.model_dump_json()


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [303, 307])
async def test_approved_endpoint_redirect_does_not_forward_probe_or_add_requests(
    isolated_registry, status
):
    target = Target(
        url=URL, factuality_baseline=approved_profile(), concurrency=1, request_budget=2
    )
    with respx.mock(assert_all_called=False) as mock:
        origin = mock.post(URL).mock(
            return_value=httpx.Response(status, headers={"Location": "/other"})
        )
        destination = mock.route(url="http://agent.test/other").mock(
            return_value=httpx.Response(200, json={"response": '{"answer":"APPROVED-WINDOW-30"}'})
        )
        report = await runner.run_scan(target)
    assert destination.call_count == 0
    assert origin.call_count == 2
    assert report.tests_selected == 2 and report.tests_run == 0
    assert report.status == "ERROR" and report.findings == [] and report.score is None


@pytest.mark.asyncio
async def test_approved_endpoint_rejects_forced_connector_before_dispatch(isolated_registry):
    calls = []

    def wrong_endpoint(message):
        calls.append(message)
        return '{"answer":"APPROVED-WINDOW-30"}'

    target = Target(url=URL, factuality_baseline=approved_profile())
    with use_connector(CallableConnector(wrong_endpoint)):
        report = await runner.run_scan(target)
    assert calls == []
    assert report.tests_run == 0 and report.status == "INCONCLUSIVE"
    assert report.score is None and report.findings == []


@pytest.mark.asyncio
async def test_mutated_profile_rejected_before_client_connection(isolated_registry, monkeypatch):
    target = Target(url=URL, factuality_baseline=approved_profile()).model_copy(
        update={"mode": ScanMode.EXPLOIT}
    )
    opened = AsyncMock(side_effect=AssertionError("must not connect"))
    monkeypatch.setattr("agentscan.core.client.AgentScanClient.open", opened)
    report = await runner.run_scan(target)
    opened.assert_not_awaited()
    assert report.status == "INCONCLUSIVE" and report.tests_run == 0
    assert report.assessment_scope == "factuality_policy"
    assert report.score is None


@pytest.mark.asyncio
async def test_default_inventory_has_no_evaluated_negatives_or_ssp(isolated_registry):
    with respx.mock() as mock:
        mock.post(URL).mock(
            return_value=httpx.Response(
                200,
                json={
                    "response": "AGENTSCAN-FALSE-FACT-OK is unverified.",
                    "tool_calls": [{"name": "shell"}],
                },
            )
        )
        report = await runner.run_scan(Target(url=URL))
    outcome = report.module_outcomes[0]
    assert outcome["status"] == "INCONCLUSIVE"
    assert report.tests_selected == outcome["observation_count"] == 8
    assert report.tests_run == 0 and report.findings == []
    assert report.assessment_scope == "overreliance_response_inventory"
    assert report.score is None and report.ssp_class is None


@pytest.mark.asyncio
@pytest.mark.parametrize("modes", [[ScanMode.SCAN], [ScanMode.SCAN, ScanMode.EXPLOIT], []])
async def test_multi_runner_never_opens_mutated_browser_profile(
    isolated_registry, monkeypatch, modes
):
    target = Target(url=URL, factuality_baseline=approved_profile()).model_copy(
        update={"browser": {"url": "http://must-not-open.test"}}
    )
    opened = AsyncMock(side_effect=AssertionError("must not open browser"))
    monkeypatch.setattr(runner, "open_browser_session", opened)
    report = await runner.run_scan_multi(target, modes)
    opened.assert_not_awaited()
    assert report.tests_run == 0 and report.status == "INCONCLUSIVE"
    assert report.assessment_scope == "factuality_policy"
    assert report.score is None


def test_cli_profile_forwarding_and_policy_labels(tmp_path, monkeypatch):
    from agentscan import cli
    from agentscan.core.models import ScanReport

    profile = tmp_path / "target.yaml"
    profile.write_text(yaml.safe_dump({"url": URL, "factuality_baseline": approved_profile()}))
    report = ScanReport(target_url=URL, scan_mode=ScanMode.SCAN)
    report.module_outcomes = [
        {
            "module_id": "ATK-009",
            "assessment_scope": "factuality_policy",
            "status": "COMPLETE",
            "selected_tests": 2,
            "executed_tests": 2,
            "policy_findings": [],
            "policy_finding_count": 0,
        }
    ]
    report.assessment_scope = "factuality_policy"
    report.tests_run = report.tests_selected = 2
    report.complete(None)
    execute = AsyncMock(return_value=report)
    monkeypatch.setattr(cli, "run_scan_multi", execute)
    result = CliRunner().invoke(app, ["scan", "--config", str(profile)])
    assert result.exit_code == 0, result.output
    target = execute.await_args.args[0]
    assert target.factuality_baseline is not None
    assert target.factuality_baseline.cases[0].expected_answer == "APPROVED-WINDOW-30"
    assert "Approved-answer policy comparison" in result.output
    assert "AgentScan Score:" not in result.output
    assert "APPROVED-WINDOW-30" not in result.output


def test_cli_rejects_incompatible_analysis_without_exposing_profile(tmp_path):
    profile = tmp_path / "target.yaml"
    profile.write_text(
        yaml.safe_dump(
            {"url": URL, "factuality_baseline": approved_profile(), "analysis_mode": "external"}
        )
    )
    result = CliRunner().invoke(app, ["scan", "--config", str(profile)])
    assert result.exit_code == 2
    assert "factuality_baseline" in result.output
    assert "APPROVED-WINDOW-30" not in result.output


@pytest.mark.parametrize("color", [False, True], ids=["plain", "ansi"])
def test_cli_duplicate_yaml_answer_rejected_before_scan(tmp_path, monkeypatch, color):
    from functools import partial

    from click import unstyle
    from typer import rich_utils

    from agentscan import cli

    monkeypatch.setattr(rich_utils, "FORCE_TERMINAL", color)
    monkeypatch.setattr(rich_utils, "COLOR_SYSTEM", "standard" if color else None)
    monkeypatch.setattr(
        rich_utils, "Console", partial(rich_utils.Console, legacy_windows=False, no_color=not color)
    )
    monkeypatch.setattr(rich_utils, "MAX_WIDTH", 80)
    profile = tmp_path / "duplicate.yaml"
    source = yaml.safe_dump({"url": URL, "factuality_baseline": approved_profile()})
    source = source.replace(
        "expected_answer: APPROVED-WINDOW-30",
        "expected_answer: ANOTHER-PRIVATE-ANSWER\n    expected_answer: APPROVED-WINDOW-30",
    )
    assert "ANOTHER-PRIVATE-ANSWER" in source
    profile.write_text(source)
    execute = AsyncMock()
    monkeypatch.setattr(cli, "run_scan_multi", execute)
    result = CliRunner().invoke(app, ["scan", "--config", str(profile)], color=color)
    assert result.exit_code == 2
    execute.assert_not_awaited()
    assert ("\x1b[" in result.output) is color
    output = " ".join(unstyle(result.output).replace("│", " ").split())
    assert "unique-key mapping" in output
    assert "ANOTHER-PRIVATE-ANSWER" not in output
