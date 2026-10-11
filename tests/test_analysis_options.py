"""Entry-point privacy boundaries; runners and providers never perform real IO."""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from typer.testing import CliRunner

from agentscan.cli import app
from agentscan.core.ai_client import AIClientError
from agentscan.core.models import ScanMode, ScanReport
from agentscan.ui.routers.scan import api_start_scan
from agentscan.ui.routers.swarms import api_swarms_run
from agentscan.ui.state import event_bus, state


@pytest.fixture(autouse=True)
def isolated_model_options(monkeypatch):
    monkeypatch.setattr(state, "active_scan", None)
    monkeypatch.setattr(state, "report", None)
    monkeypatch.setattr(state, "scan_status", {"status": "idle"})
    monkeypatch.setattr(event_bus, "publish", AsyncMock())
    # Never read the operator's .env or real provider keys in these entry-point tests.
    monkeypatch.setattr(
        "agentscan.core.external_analysis.provider_key", lambda provider: "synthetic-test-key"
    )


@pytest.mark.parametrize("classification", [None, "sensitive"])
async def test_dashboard_external_requires_non_sensitive_designation(monkeypatch, classification):
    run = AsyncMock()
    monkeypatch.setattr("agentscan.core.runner.run_scan_multi", run)
    payload = {
        "target_url": "https://owned.invalid/chat",
        "analysis_mode": "external",
        "external_model": "gemini/synthetic-model",
    }
    if classification:
        payload["data_classification"] = classification
    response = await api_start_scan(payload)
    assert response.status_code == 400
    assert state.active_scan is None
    run.assert_not_called()


@pytest.mark.parametrize("provider", ["openai", "anthropic", "gemini"])
async def test_dashboard_explicit_external_non_sensitive_scan(monkeypatch, provider):
    report = ScanReport(target_url="https://owned.invalid/chat", scan_mode=ScanMode.SCAN)
    run = AsyncMock(return_value=report)
    monkeypatch.setattr("agentscan.core.runner.run_scan_multi", run)
    response = await api_start_scan(
        {
            "target_url": report.target_url,
            "analysis_mode": "external",
            "external_model": f"{provider}/synthetic-model",
            "data_classification": "non_sensitive",
        }
    )
    assert response.status_code == 200
    await state.active_scan
    target, _ = run.call_args.args
    assert target.data_classification == "non_sensitive"
    assert target.analysis_mode == "external"
    assert target.external_model == f"{provider}/synthetic-model"


async def test_dashboard_missing_external_key_rejected_before_task(monkeypatch):
    def missing_key(provider):
        raise AIClientError("Configure the provider key locally.")

    monkeypatch.setattr("agentscan.core.external_analysis.provider_key", missing_key)
    response = await api_start_scan(
        {
            "target_url": "https://owned.invalid/chat",
            "analysis_mode": "external",
            "external_model": "openai/synthetic-model",
            "data_classification": "non_sensitive",
        }
    )
    assert response.status_code == 400
    assert state.active_scan is None
    assert "key locally" in json.loads(response.body)["field_errors"]["analysis_mode"]


async def test_dashboard_sensitive_default_and_role_model_bypass_rejected(monkeypatch):
    run = AsyncMock()
    monkeypatch.setattr("agentscan.core.runner.run_scan_multi", run)
    response = await api_start_scan(
        {"target_url": "https://owned.invalid/chat", "attacker_model": "openai/synthetic"}
    )
    assert response.status_code == 400
    run.assert_not_called()


@pytest.mark.parametrize("model", ["openai", "gpt-4", "gemini/", "https://evil.invalid/model"])
async def test_dashboard_invalid_external_model_rejected_without_task(model):
    response = await api_start_scan(
        {
            "target_url": "https://owned.invalid/chat",
            "analysis_mode": "external",
            "external_model": model,
            "data_classification": "non_sensitive",
        }
    )
    assert response.status_code == 400
    assert state.active_scan is None


@pytest.mark.parametrize("classification", [None, "sensitive"])
async def test_dashboard_swarm_external_denied_without_designation(monkeypatch, classification):
    run = AsyncMock()
    monkeypatch.setattr("agentscan.swarm.coordinator.SwarmCoordinator.run_swarm", run)
    payload = {
        "target_url": "https://owned.invalid/chat",
        "analysis_mode": "external",
        "external_model": "anthropic/synthetic-model",
    }
    if classification:
        payload["data_classification"] = classification
    response = await api_swarms_run(payload)
    assert response.status_code == 400
    run.assert_not_called()


async def test_dashboard_external_swarm_discards_prior_sensitive_blackboard(monkeypatch):
    from agentscan.swarm.blackboard import SwarmBlackboard

    old = SwarmBlackboard()
    old.add_intel("private-observation", "private fixture", "Previous sensitive scan")
    monkeypatch.setattr(state, "swarm_blackboard", old)
    report = SimpleNamespace(
        score=None, findings=[], turns=[], model_dump=lambda **kwargs: {"score": None}
    )
    run = AsyncMock(return_value=report)
    monkeypatch.setattr("agentscan.swarm.coordinator.SwarmCoordinator.run_swarm", run)
    response = await api_swarms_run(
        {
            "target_url": "https://owned.invalid/chat",
            "analysis_mode": "external",
            "external_model": "gemini/synthetic-model",
            "data_classification": "non_sensitive",
        }
    )
    assert response.status_code == 200
    assert state.swarm_blackboard is not old
    assert state.swarm_blackboard.get_all_items() == []
    target = run.call_args.args[0]
    assert target.data_classification == "non_sensitive" and target.analysis_mode == "external"


@pytest.mark.parametrize("classification", [None, "sensitive"])
def test_cli_external_denied_without_designation(classification):
    args = [
        "scan",
        "https://owned.invalid/chat",
        "--analysis",
        "external",
        "--external-model",
        "openai/synthetic-model",
    ]
    if classification:
        args += ["--data-classification", classification]
    with patch("agentscan.cli.run_scan_multi", new_callable=AsyncMock) as run:
        response = CliRunner().invoke(app, args)
    assert response.exit_code != 0
    assert "non-sensitive" in response.output
    run.assert_not_called()


def test_cli_designated_external_scan_and_role_models():
    report = ScanReport(target_url="https://owned.invalid/chat", scan_mode=ScanMode.SCAN)
    with patch("agentscan.cli.run_scan_multi", new_callable=AsyncMock, return_value=report) as run:
        response = CliRunner().invoke(
            app,
            [
                "scan",
                report.target_url,
                "--analysis",
                "external",
                "--external-model",
                "gemini/synthetic-model",
                "--data-classification",
                "non_sensitive",
                "--attacker-model",
                "gemini/synthetic-model",
                "--judge-model",
                "gemini/synthetic-judge",
            ],
        )
    assert response.exit_code == 0, response.output
    target, modes = run.call_args.args
    assert target.analysis_mode == "external" and target.data_classification == "non_sensitive"
    assert target.external_model == "gemini/synthetic-model"
    assert target.judge_model == "gemini/synthetic-judge"
    assert ScanMode.EXPLOIT in modes


def test_cli_external_role_model_does_not_bypass_sensitive_default():
    with patch("agentscan.cli.run_scan_multi", new_callable=AsyncMock) as run:
        response = CliRunner().invoke(
            app, ["scan", "https://owned.invalid/chat", "--attacker-model", "openai/synthetic"]
        )
    assert response.exit_code != 0
    assert "require --analysis external" in response.output
    run.assert_not_called()


def test_cli_explicit_deterministic_mode_cannot_be_overridden_by_role_model():
    with patch("agentscan.cli.run_scan_multi", new_callable=AsyncMock) as run:
        response = CliRunner().invoke(
            app,
            [
                "scan",
                "https://owned.invalid/chat",
                "--analysis",
                "deterministic",
                "--attacker-model",
                "ollama/llama3.2",
            ],
        )
    assert response.exit_code != 0
    run.assert_not_called()


def test_cli_external_calibration_rejected_before_any_model_call():
    with (
        patch("agentscan.cli.run_scan_multi", new_callable=AsyncMock) as scan,
        patch("agentscan.core.calibration.run_calibration", new_callable=AsyncMock) as calibration,
    ):
        response = CliRunner().invoke(
            app,
            [
                "scan",
                "https://owned.invalid/chat",
                "--analysis",
                "external",
                "--external-model",
                "gemini/synthetic-model",
                "--data-classification",
                "non_sensitive",
                "--calibrate",
            ],
        )
    assert response.exit_code != 0
    assert "offline local model smoke check" in response.output
    scan.assert_not_called()
    calibration.assert_not_called()


def test_cli_swarm_external_requires_designation():
    with patch(
        "agentscan.swarm.coordinator.SwarmCoordinator.run_swarm", new_callable=AsyncMock
    ) as run:
        response = CliRunner().invoke(
            app, ["swarm", "https://owned.invalid/chat", "--model", "gemini/synthetic-model"]
        )
    assert response.exit_code != 0
    run.assert_not_called()


def test_cli_swarm_designated_external_mode():
    report = SimpleNamespace(
        score=None, findings=[], turns=[], model_dump=lambda **kwargs: {"score": None}
    )
    with patch(
        "agentscan.swarm.coordinator.SwarmCoordinator.run_swarm",
        new_callable=AsyncMock,
        return_value=report,
    ) as run:
        response = CliRunner().invoke(
            app,
            [
                "swarm",
                "https://owned.invalid/chat",
                "--model",
                "anthropic/synthetic-model",
                "--data-classification",
                "non_sensitive",
                "--quiet",
            ],
        )
    assert response.exit_code == 0, response.output
    target = run.call_args.args[0]
    assert target.analysis_mode == "external"
    assert target.data_classification == "non_sensitive"
