"""Regression tests for QA-037: non-TTY exploit/deep consent.

The CLI must refuse ``--exploit`` / ``--deep`` in a non-interactive process
unless the operator supplies ``--authorized`` or ``AGENTSCAN_EXPLOIT_CONSENT=1``.
Selecting ``--attacker-model`` alone must not enable EXPLOIT mode.
"""

from __future__ import annotations

import http.server
import json
import os
import subprocess
import sys
import threading
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from typer.testing import CliRunner

from agentscan._cli._shared import _confirm_exploit_mode
from agentscan.cli import app
from agentscan.core.models import Framework, ScanMode, ScanReport

REPO_ROOT = Path(__file__).resolve().parents[1]
TARGET = "http://127.0.0.1:9/chat"
CONSENT_ENV = "AGENTSCAN_EXPLOIT_CONSENT"


def _completed_report() -> ScanReport:
    report = ScanReport(target_url=TARGET, scan_mode=ScanMode.SCAN, framework=Framework.AUTO)
    report.complete(100)
    return report


def _invoke(args: list[str], env: dict[str, str] | None = None):
    return CliRunner().invoke(app, ["scan", TARGET, *args], env=env)


def _flat(output: str) -> str:
    return " ".join(output.split())


@pytest.fixture(autouse=True)
def _clear_consent_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(CONSENT_ENV, raising=False)


@pytest.mark.parametrize("flag", ["--exploit", "--deep"])
def test_non_tty_exploit_without_consent_refuses_before_dispatch(flag: str) -> None:
    with patch("agentscan.cli.run_scan_multi", new_callable=AsyncMock) as run:
        result = _invoke([flag])

    output = _flat(result.output)
    assert result.exit_code == 2, result.output
    assert "EXPLOIT / DEEP MODE REFUSED" in output
    assert "--authorized" in output
    assert f"{CONSENT_ENV}=1" in output
    assert "Refusing before any request is sent to the target" in output
    run.assert_not_called()


@pytest.mark.parametrize("setting", ["exploit: true", "deep: true"])
def test_non_tty_profile_enabled_active_mode_refuses_without_consent(
    tmp_path: Path, setting: str
) -> None:
    profile = tmp_path / "target.yaml"
    profile.write_text(f"url: {TARGET}\n{setting}\n", encoding="utf-8")
    with patch("agentscan.cli.run_scan_multi", new_callable=AsyncMock) as run:
        result = CliRunner().invoke(app, ["scan", "--config", str(profile)])

    assert result.exit_code == 2, result.output
    assert "EXPLOIT / DEEP MODE REFUSED" in _flat(result.output)
    run.assert_not_called()


def test_non_tty_attacker_model_with_exploit_still_requires_consent() -> None:
    with patch("agentscan.cli.run_scan_multi", new_callable=AsyncMock) as run:
        result = _invoke(["--attacker-model", "ollama/llama3.2", "--exploit"])

    assert result.exit_code == 2, result.output
    assert "EXPLOIT / DEEP MODE REFUSED" in _flat(result.output)
    run.assert_not_called()


def test_non_tty_exploit_with_authorized_flag_proceeds() -> None:
    report = _completed_report()
    with patch("agentscan.cli.run_scan_multi", new_callable=AsyncMock, return_value=report) as run:
        result = _invoke(["--exploit", "--authorized"])

    assert result.exit_code == 0, result.output
    run.assert_called_once()
    _, modes = run.call_args.args
    assert modes == [ScanMode.SCAN, ScanMode.EXPLOIT]
    assert "consent acknowledged via --authorized" in _flat(result.output)


def test_non_tty_exploit_with_env_consent_proceeds() -> None:
    report = _completed_report()
    with patch("agentscan.cli.run_scan_multi", new_callable=AsyncMock, return_value=report) as run:
        result = _invoke(["--exploit"], env={CONSENT_ENV: "1"})

    assert result.exit_code == 0, result.output
    run.assert_called_once()
    _, modes = run.call_args.args
    assert modes == [ScanMode.SCAN, ScanMode.EXPLOIT]
    assert f"consent acknowledged via {CONSENT_ENV}" in _flat(result.output)


def test_non_tty_deep_with_authorized_flag_proceeds() -> None:
    report = _completed_report()
    with patch("agentscan.cli.run_scan_multi", new_callable=AsyncMock, return_value=report) as run:
        result = _invoke(["--deep", "--authorized"])

    assert result.exit_code == 0, result.output
    run.assert_called_once()
    _, modes = run.call_args.args
    assert modes == [ScanMode.SCAN, ScanMode.DEEP]


@pytest.mark.parametrize("value", ["true", "yes", "2", "enabled"])
def test_ambiguous_consent_env_fails_closed(value: str) -> None:
    with patch("agentscan.cli.run_scan_multi", new_callable=AsyncMock) as run:
        result = _invoke(["--exploit"], env={CONSENT_ENV: value})

    assert result.exit_code == 2, result.output
    assert f"{CONSENT_ENV} must be exactly '1'" in _flat(result.output)
    run.assert_not_called()


@pytest.mark.parametrize("value", ["0", "false", "no", "off", ""])
def test_explicit_negative_consent_env_is_not_consent(value: str) -> None:
    with patch("agentscan.cli.run_scan_multi", new_callable=AsyncMock) as run:
        result = _invoke(["--exploit"], env={CONSENT_ENV: value})

    assert result.exit_code == 2, result.output
    assert "EXPLOIT / DEEP MODE REFUSED" in _flat(result.output)
    run.assert_not_called()


def test_attacker_model_alone_does_not_enable_exploit() -> None:
    report = _completed_report()
    with patch("agentscan.cli.run_scan_multi", new_callable=AsyncMock, return_value=report) as run:
        result = _invoke(["--attacker-model", "ollama/llama3.2"])

    assert result.exit_code == 0, result.output
    run.assert_called_once()
    target_obj, modes = run.call_args.args
    assert modes == [ScanMode.SCAN]
    assert target_obj.attacker_model == "ollama/llama3.2"
    assert "require an explicit --exploit" in _flat(result.output)


class _TTYStdin:
    def isatty(self) -> bool:
        return True


def test_tty_prompt_is_still_the_default_and_decline_cancels(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "stdin", _TTYStdin())
    prompts: list[dict[str, object]] = []

    def decline(*args: object, **kwargs: object) -> bool:
        prompts.append(dict(kwargs))
        return False

    monkeypatch.setattr("rich.prompt.Confirm.ask", decline)

    with pytest.raises(SystemExit) as exc:
        _confirm_exploit_mode(require_non_tty_consent=True)

    assert exc.value.code == 0
    assert prompts == [{"default": False}]


def test_tty_prompt_accepts(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "stdin", _TTYStdin())
    monkeypatch.setattr("rich.prompt.Confirm.ask", lambda *args, **kwargs: True)

    assert _confirm_exploit_mode(require_non_tty_consent=True) is True


def test_tty_explicit_consent_skips_prompt(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "stdin", _TTYStdin())

    def unexpected_prompt(*args: object, **kwargs: object) -> bool:
        raise AssertionError("interactive prompt should be skipped with explicit consent")

    monkeypatch.setattr("rich.prompt.Confirm.ask", unexpected_prompt)

    assert _confirm_exploit_mode(authorized=True, require_non_tty_consent=True) is True


def test_tty_scan_prompts_and_proceeds_on_accept(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("agentscan._cli._shared._stdin_is_interactive", lambda: True)
    prompts: list[dict[str, object]] = []

    def accept(*args: object, **kwargs: object) -> bool:
        prompts.append(dict(kwargs))
        return True

    monkeypatch.setattr("rich.prompt.Confirm.ask", accept)
    report = _completed_report()
    with patch("agentscan.cli.run_scan_multi", new_callable=AsyncMock, return_value=report) as run:
        result = _invoke(["--exploit"])

    assert result.exit_code == 0, result.output
    run.assert_called_once()
    _, modes = run.call_args.args
    assert modes == [ScanMode.SCAN, ScanMode.EXPLOIT]
    assert prompts == [{"default": False}]


def test_tty_scan_decline_does_not_dispatch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("agentscan._cli._shared._stdin_is_interactive", lambda: True)
    monkeypatch.setattr("rich.prompt.Confirm.ask", lambda *args, **kwargs: False)
    with patch("agentscan.cli.run_scan_multi", new_callable=AsyncMock) as run:
        result = _invoke(["--exploit"])

    assert result.exit_code == 0, result.output
    assert "Scan cancelled." in _flat(result.output)
    run.assert_not_called()


def test_scan_report_records_consent_metadata_for_normal_scan() -> None:
    report = _completed_report()
    with patch("agentscan.cli.run_scan_multi", new_callable=AsyncMock, return_value=report) as run:
        result = _invoke([])

    assert result.exit_code == 0, result.output
    run.assert_called_once()
    assert report.exploit_consent == {
        "exploit": False,
        "deep": False,
        "consent_required": False,
        "consent_granted": None,
        "consent_source": None,
    }


def test_scan_report_records_consent_metadata_for_exploit_authorized() -> None:
    report = _completed_report()
    with patch("agentscan.cli.run_scan_multi", new_callable=AsyncMock, return_value=report) as run:
        result = _invoke(["--exploit", "--authorized"])

    assert result.exit_code == 0, result.output
    run.assert_called_once()
    assert report.exploit_consent == {
        "exploit": True,
        "deep": False,
        "consent_required": True,
        "consent_granted": True,
        "consent_source": "--authorized",
    }


def test_scan_report_records_consent_metadata_for_exploit_env() -> None:
    report = _completed_report()
    with patch("agentscan.cli.run_scan_multi", new_callable=AsyncMock, return_value=report) as run:
        result = _invoke(["--exploit"], env={CONSENT_ENV: "1"})

    assert result.exit_code == 0, result.output
    run.assert_called_once()
    assert report.exploit_consent == {
        "exploit": True,
        "deep": False,
        "consent_required": True,
        "consent_granted": True,
        "consent_source": "environment",
    }


def test_scan_report_records_consent_metadata_for_deep_authorized() -> None:
    report = _completed_report()
    with patch("agentscan.cli.run_scan_multi", new_callable=AsyncMock, return_value=report) as run:
        result = _invoke(["--deep", "--authorized"])

    assert result.exit_code == 0, result.output
    run.assert_called_once()
    assert report.exploit_consent == {
        "exploit": False,
        "deep": True,
        "consent_required": True,
        "consent_granted": True,
        "consent_source": "--authorized",
    }


def test_scan_report_records_consent_metadata_for_tty_accept(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("agentscan._cli._shared._stdin_is_interactive", lambda: True)
    monkeypatch.setattr("rich.prompt.Confirm.ask", lambda *args, **kwargs: True)
    report = _completed_report()
    with patch("agentscan.cli.run_scan_multi", new_callable=AsyncMock, return_value=report) as run:
        result = _invoke(["--exploit"])

    assert result.exit_code == 0, result.output
    run.assert_called_once()
    assert report.exploit_consent == {
        "exploit": True,
        "deep": False,
        "consent_required": True,
        "consent_granted": True,
        "consent_source": "interactive",
    }


def test_json_report_includes_exploit_consent_metadata(tmp_path: Path) -> None:
    report = _completed_report()
    out = tmp_path / "report.json"
    with patch("agentscan.cli.run_scan_multi", new_callable=AsyncMock, return_value=report):
        result = _invoke(["--exploit", "--authorized", "--output", str(out)])

    assert result.exit_code == 0, result.output
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["exploit_consent"] == {
        "exploit": True,
        "deep": False,
        "consent_required": True,
        "consent_granted": True,
        "consent_source": "--authorized",
    }


def test_html_report_contains_consent_line(tmp_path: Path) -> None:
    report = _completed_report()
    out = tmp_path / "report.html"
    with patch("agentscan.cli.run_scan_multi", new_callable=AsyncMock, return_value=report):
        result = _invoke(["--exploit", "--authorized", "--output", str(out)])

    assert result.exit_code == 0, result.output
    html = out.read_text(encoding="utf-8")
    assert "Consent" in html
    assert "source=--authorized" in html
    assert "exploit=True" in html


def test_sarif_report_contains_exploit_consent_metadata(tmp_path: Path) -> None:
    report = _completed_report()
    out = tmp_path / "report.sarif"
    with patch("agentscan.cli.run_scan_multi", new_callable=AsyncMock, return_value=report):
        result = _invoke(["--exploit", "--authorized", "--output", str(out)])

    assert result.exit_code == 0, result.output
    data = json.loads(out.read_text(encoding="utf-8"))
    assessment = data["runs"][0]["properties"]["agentscanAssessment"]
    assert assessment["exploit_consent"] == {
        "exploit": True,
        "deep": False,
        "consent_required": True,
        "consent_granted": True,
        "consent_source": "--authorized",
    }


def test_non_tty_subprocess_refuses_without_sending_any_request(tmp_path: Path) -> None:
    class CountingHandler(http.server.BaseHTTPRequestHandler):
        requests = 0

        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            type(self).requests += 1
            self._reply()

        def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            type(self).requests += 1
            self._reply()

        def _reply(self) -> None:
            body = b'{"response": "synthetic refusal"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: object) -> None:
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), CountingHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        env = dict(os.environ)
        env.pop(CONSENT_ENV, None)
        env["PYTHONPATH"] = str(REPO_ROOT)
        env["NO_COLOR"] = "1"
        env["TERM"] = "dumb"
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "agentscan.cli",
                "scan",
                f"http://127.0.0.1:{port}/chat",
                "--exploit",
            ],
            cwd=tmp_path,
            env=env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=60,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    output = _flat(proc.stdout + proc.stderr)
    assert proc.returncode == 2, output
    assert "EXPLOIT / DEEP MODE REFUSED" in output
    assert CountingHandler.requests == 0
