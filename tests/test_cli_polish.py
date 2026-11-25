"""Regression coverage for issue #46 CLI polish."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from agentscan.cli import app

ROOT = Path(__file__).resolve().parents[1]
runner = CliRunner()


def test_mistyped_command_suggests_once() -> None:
    result = runner.invoke(app, ["audt"])

    assert result.exit_code != 0
    assert "Did you mean 'audit'?" in result.output
    assert result.output.count("Did you mean") == 1


def test_default_logging_is_not_debug() -> None:
    env = os.environ.copy()
    env.pop("AGENTSCAN_LOG_LEVEL", None)
    env["PYTHONDONTWRITEBYTECODE"] = "1"

    result = subprocess.run(
        [sys.executable, "-m", "agentscan.cli", "list-attacks"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "DEBUG" not in result.stderr


def test_help_does_not_truncate_long_option_names() -> None:
    result = runner.invoke(app, ["scan", "--help"])

    assert result.exit_code == 0
    assert "--allow-unverified-completion" in result.output
    assert "completi\u2026" not in result.output
    assert "completi..." not in result.output


@pytest.mark.parametrize(
    "args",
    [
        ["-h"],
        ["scan", "-h"],
        ["heal-server", "-h"],
        ["api", "serve", "-h"],
    ],
)
def test_dash_h_is_help_everywhere(args: list[str]) -> None:
    result = runner.invoke(app, args)

    assert result.exit_code == 0, result.output
    assert "Usage:" in result.output
