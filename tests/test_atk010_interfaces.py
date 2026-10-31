"""ATK-010 coverage and privacy survive the actual runner and report interfaces."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock

import pytest
import respx
import yaml
from typer.testing import CliRunner

from agentscan.attacks.exploit.crescendo import CrescendoModule
from agentscan.attacks.registry import AttackRegistry
from agentscan.core import runner
from agentscan.core.client import AgentScanClient
from agentscan.core.context import ScanContext, active_context
from agentscan.core.models import ScanMode, ScanReport, Target, TurnRecord
from agentscan.core.outcomes import TargetRequestError
from agentscan.core.trace import TrafficRecorder
from agentscan.core.trajectory import TrajectoryRecorder
from agentscan.reporting.html_report import render_html_report
from agentscan.reporting.sarif_report import to_sarif

URL = "http://synthetic.invalid/atk010-interfaces"
PRIVATE = "SYNTHETIC_ATK010_PRIVATE_7qK9"
SCOPE = "crescendo_complete_known_reference"


@pytest.fixture(autouse=True)
def isolated_context():
    token = active_context.set(None)
    try:
        yield
    finally:
        active_context.reset(token)


@pytest.fixture
def selected(monkeypatch):
    registry = AttackRegistry()
    registry.register(CrescendoModule())
    registry._loaded = True
    monkeypatch.setattr(runner, "registry", registry)


@pytest.mark.asyncio
@pytest.mark.parametrize("error", [False, True])
async def test_conversation_recording_opt_out_protects_raw_response_and_still_validates(error):
    traffic = TrafficRecorder(redact=False)
    traffic.enabled = True
    trajectory = TrajectoryRecorder()
    active_context.set(ScanContext(recorder=traffic, trajectory=trajectory))
    client = AgentScanClient(Target(url=URL), record_exchange=False)
    body = {"response": PRIVATE, "tool_calls": [{"name": "delete_records"}]}
    if error:
        body.update({"error": PRIVATE, "status_code": 401})
    client._connector.send_conversation = AsyncMock(return_value=body)
    if error:
        with pytest.raises(TargetRequestError, match="HTTP 401"):
            await client.send_conversation([{"role": "user", "content": "public request"}])
    else:
        assert await client.send_conversation([]) == body
    assert traffic.entries == []
    assert trajectory.turns() == []


@pytest.mark.asyncio
@pytest.mark.parametrize("case", ["disclosure", "negative", "incomplete", "missing", "budget"])
async def test_runner_exports_and_dashboard_api_preserve_scope_and_unknowns(
    selected, case, tmp_path
):
    from fastapi.testclient import TestClient

    from agentscan.ui.app import create_app

    body = {"response": PRIVATE, "tool_calls": [{"name": "delete_all"}]}
    if case == "negative":
        body = {"response": "Public discussion only; no private reference disclosed."}
    elif case == "incomplete":
        body["done"] = False
    target = Target(
        url=URL,
        mode=ScanMode.EXPLOIT,
        canary_token=None if case == "missing" else PRIVATE,
        request_budget=1 if case == "budget" else None,
    )
    with respx.mock(assert_all_called=False) as mock:
        route = mock.post(URL).respond(200, json=body)
        report = await runner.run_scan(target)
    complete = case in {"disclosure", "negative"}
    expected_evaluated = 6 if complete else 1 if case == "budget" else 0
    expected_findings = 6 if case == "disclosure" else 1 if case == "budget" else 0
    assert report.tests_selected == 6
    assert report.tests_run == expected_evaluated
    assert len(report.findings) == expected_findings
    assert report.status == ("COMPLETE" if complete else "INCONCLUSIVE")
    assert report.ssp_class is None and report.trajectory == []
    if not complete:
        assert report.score is None
    if case == "missing":
        assert route.call_count == 0
    if case == "budget":
        assert route.call_count == 1
    outcome = report.module_outcomes[0]
    assert outcome["assessment_scope"] == SCOPE
    assert outcome["executed_tests"] == expected_evaluated
    assert len(outcome["observations"]) == 6
    assert (
        sum(row["status"] == "DISCLOSURE" for row in outcome["observations"]) == expected_findings
    )

    saved = report.model_dump_json()
    html = render_html_report(report)
    sarif = to_sarif(report)
    assessment = sarif["runs"][0]["properties"]["agentscanAssessment"]
    assert assessment["tests_run"] == expected_evaluated
    assert assessment["module_outcomes"] == report.module_outcomes
    assert sarif["runs"][0]["invocations"][0]["executionSuccessful"] is complete
    assert SCOPE in html and "Crescendo Multi-Turn Reference Disclosure" in html
    for value in (saved, html, json.dumps(sarif)):
        assert PRIVATE not in value

    path = tmp_path / "report.json"
    path.write_text(saved, encoding="utf-8")
    with TestClient(create_app(report_path=path)) as client:
        client.get("/")
        received = client.get("/api/report").json()
        assert received["module_outcomes"] == report.model_dump(mode="json")["module_outcomes"]
        assert received["tests_run"] == expected_evaluated
        assert received["ssp_class"] is None
        trajectory = client.get("/api/trajectory").json()
        assert trajectory == {"ssp_class": None, "turns": []}
        assert PRIVATE not in json.dumps(received)


@pytest.mark.asyncio
async def test_mixed_report_dashboard_does_not_reclassify_unassessed_conversation(
    selected, monkeypatch
):
    from agentscan.ui.routers.reports import api_trajectory
    from agentscan.ui.state import state

    with respx.mock() as mock:
        mock.post(URL).respond(200, json={"response": PRIVATE})
        report = await runner.run_scan(Target(url=URL, mode=ScanMode.EXPLOIT, canary_token=PRIVATE))
    # Another module can contribute trajectory turns in a mixed assessment.
    # A null SSP from the runner must stay null at the dashboard API boundary.
    report.trajectory = [
        TurnRecord(turn=1, payload="public request", response="public reply", tool_calls=["shell"])
    ]
    report.module_outcomes.append(
        {"module_id": "ATK-OTHER", "assessment_scope": "target", "status": "COMPLETE"}
    )
    runner._attach_trajectory(report)
    assert report.ssp_class is None
    report.trajectory = [
        TurnRecord(turn=1, payload="public request", response="public reply", tool_calls=["shell"])
    ]
    monkeypatch.setattr(state, "report", report)
    response = await api_trajectory()
    assert json.loads(response.body)["ssp_class"] is None


def test_cli_profile_and_json_keep_missing_reference_inconclusive(selected, tmp_path, monkeypatch):
    from agentscan import cli

    report = ScanReport(target_url=URL, scan_mode=ScanMode.EXPLOIT)
    report.tests_selected = 6
    report.module_outcomes = [
        {
            "module_id": "ATK-010",
            "assessment_scope": SCOPE,
            "status": "INCONCLUSIVE",
            "selected_tests": 6,
            "executed_tests": 0,
            "reason": "Private canary is unavailable.",
        }
    ]
    report.complete(None, status="INCONCLUSIVE")
    execute = AsyncMock(return_value=report)
    monkeypatch.setattr(cli, "run_scan_multi", execute)
    profile = tmp_path / "target.yaml"
    profile.write_text(yaml.safe_dump({"url": URL, "canary_token": PRIVATE}), encoding="utf-8")
    output = tmp_path / "out.json"
    result = CliRunner().invoke(
        cli.app, ["scan", "--config", str(profile), "--output", str(output)]
    )
    assert result.exit_code == 3, result.output
    assert execute.await_args.args[0].canary_token == PRIVATE
    result_json = json.loads(output.read_text(encoding="utf-8"))
    assert result_json["score"] is None and result_json["tests_run"] == 0
    assert result_json["module_outcomes"][0]["assessment_scope"] == SCOPE
    assert PRIVATE not in result.output and PRIVATE not in json.dumps(result_json)
