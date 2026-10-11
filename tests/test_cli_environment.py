"""CLI imports and help must not eagerly import local .env secrets into services."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def test_cli_help_keeps_dotenv_out_of_service_environment(tmp_path):
    (tmp_path / ".env").write_text(
        "GEMINI_API_KEY=synthetic-local-key\nAGENTSCAN_UI_TOKEN=synthetic-local-ui-token\n",
        encoding="utf-8",
    )
    environment = dict(os.environ)
    for name in ("GEMINI_API_KEY", "GOOGLE_API_KEY", "AGENTSCAN_UI_TOKEN"):
        environment.pop(name, None)
    environment["PYTHONPATH"] = str(Path(__file__).resolve().parents[1])
    code = """
import os
from unittest.mock import patch
from typer.testing import CliRunner
with patch('dotenv.load_dotenv', side_effect=AssertionError('Unexpected eager dotenv read')):
    from agentscan.cli import app
    result = CliRunner().invoke(app, ['--help'])
    assert result.exit_code == 0
assert 'GEMINI_API_KEY' not in os.environ
assert 'AGENTSCAN_UI_TOKEN' not in os.environ
from agentscan.core.external_analysis import provider_key
from agentscan.core.ai_client import AIClientError
try:
    provider_key('gemini', allow_dotenv=False)
except AIClientError:
    pass
else:
    raise AssertionError('Service analysis accepted a local dotenv credential')
assert provider_key('gemini') == 'synthetic-local-key'
assert 'GEMINI_API_KEY' not in os.environ
"""
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        timeout=25,
    )
    assert result.returncode == 0, result.stderr
