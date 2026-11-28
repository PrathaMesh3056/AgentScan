"""Regression tests for QA-037 applied to ``agentscan swarm``."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from typer.testing import CliRunner

from agentscan.cli import app
from agentscan.core.connectors import CallableConnector, use_connector

TARGET = "http://test.local/chat"
CONSENT_ENV = "AGENTSCAN_EXPLOIT_CONSENT"


@pytest.fixture(autouse=True)
def _clear_consent_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(CONSENT_ENV, raising=False)


def test_non_tty_swarm_without_consent_refuses_before_dispatch() -> None:
    with patch(
        "agentscan.swarm.coordinator.SwarmCoordinator.run_swarm", new_callable=AsyncMock
    ) as run:
        result = CliRunner().invoke(app, ["swarm", TARGET, "--offline"])

    assert result.exit_code == 2, result.output
    assert "EXPLOIT / DEEP MODE REFUSED" in " ".join(result.output.split())
    run.assert_not_called()


def test_non_tty_swarm_with_authorized_proceeds() -> None:
    with use_connector(CallableConnector(lambda msg: "Acknowledged.")):
        result = CliRunner().invoke(
            app, ["swarm", TARGET, "--offline", "--rounds", "1", "--authorized"]
        )

    assert result.exit_code == 0, result.output
    assert "AgentScan Swarm" in result.output
    assert "Swarm Execution Complete" in result.output


def test_non_tty_swarm_with_env_consent_proceeds() -> None:
    with use_connector(CallableConnector(lambda msg: "Acknowledged.")):
        result = CliRunner().invoke(
            app,
            ["swarm", TARGET, "--offline", "--rounds", "1"],
            env={CONSENT_ENV: "1"},
        )

    assert result.exit_code == 0, result.output
    assert "AgentScan Swarm" in result.output


def test_non_tty_swarm_ambiguous_consent_env_fails_closed() -> None:
    with patch(
        "agentscan.swarm.coordinator.SwarmCoordinator.run_swarm", new_callable=AsyncMock
    ) as run:
        result = CliRunner().invoke(app, ["swarm", TARGET, "--offline"], env={CONSENT_ENV: "yes"})

    assert result.exit_code == 2, result.output
    assert f"{CONSENT_ENV} must be exactly '1'" in " ".join(result.output.split())
    run.assert_not_called()


def test_tty_swarm_prompt_is_preserved_and_decline_cancels(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("agentscan._cli._shared._stdin_is_interactive", lambda: True)
    monkeypatch.setattr("rich.prompt.Confirm.ask", lambda *args, **kwargs: False)
    with patch(
        "agentscan.swarm.coordinator.SwarmCoordinator.run_swarm", new_callable=AsyncMock
    ) as run:
        result = CliRunner().invoke(app, ["swarm", TARGET, "--offline"])

    assert result.exit_code == 0, result.output
    assert "Scan cancelled." in " ".join(result.output.split())
    run.assert_not_called()


def test_tty_swarm_prompt_accepts_and_runs(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("agentscan._cli._shared._stdin_is_interactive", lambda: True)
    monkeypatch.setattr("rich.prompt.Confirm.ask", lambda *args, **kwargs: True)
    with use_connector(CallableConnector(lambda msg: "Acknowledged.")):
        result = CliRunner().invoke(app, ["swarm", TARGET, "--offline", "--rounds", "1"])

    assert result.exit_code == 0, result.output
    assert "AgentScan Swarm" in result.output


def test_tty_swarm_explicit_consent_skips_prompt(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("agentscan._cli._shared._stdin_is_interactive", lambda: True)

    def unexpected_prompt(*args: object, **kwargs: object) -> bool:
        raise AssertionError("interactive prompt should be skipped with explicit consent")

    monkeypatch.setattr("rich.prompt.Confirm.ask", unexpected_prompt)
    with use_connector(CallableConnector(lambda msg: "Acknowledged.")):
        result = CliRunner().invoke(
            app, ["swarm", TARGET, "--offline", "--rounds", "1", "--authorized"]
        )

    assert result.exit_code == 0, result.output
    assert "AgentScan Swarm" in result.output
