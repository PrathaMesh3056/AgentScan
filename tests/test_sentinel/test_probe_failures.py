# tests/test_sentinel/test_probe_failures.py
#
# QA-072 regression: probe failures must never be reported as a clean cycle.
# HTTP 500, non-JSON, empty JSON, timeout, and connection refusal each produce
# an INCONCLUSIVE/ERROR result and a nonzero CLI exit. All targets are loopback
# HTTP servers or an unbound loopback port.

from __future__ import annotations

import json
import socket
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from typer.testing import CliRunner

from agentscan.cli import app
from agentscan.core.client import AgentScanClient
from agentscan.core.models import Target
from agentscan.sentinel.watcher import ContinuousWatcher, SentinelStatus

CANARY = "CANARY-PROD-9988"
Responder = Callable[[int, bytes], tuple[int, str, bytes]]


class _LoopbackServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, responder: Responder) -> None:
        super().__init__(("127.0.0.1", 0), _Handler)
        self.responder = responder
        self.requests: list[bytes] = []


class _Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        server = self.server
        assert isinstance(server, _LoopbackServer)
        length = int(self.headers.get("content-length", "0"))
        body = self.rfile.read(length)
        server.requests.append(body)
        status, content_type, payload = server.responder(len(server.requests), body)
        try:
            self.send_response(status)
            self.send_header("content-type", content_type)
            self.send_header("content-length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
            pass

    def log_message(self, *args: object) -> None:
        return


@contextmanager
def _loopback(responder: Responder) -> Iterator[tuple[_LoopbackServer, str]]:
    server = _LoopbackServer(responder)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, f"http://127.0.0.1:{server.server_port}/chat"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _responder(mode: str) -> Responder:
    def respond(_count: int, _body: bytes) -> tuple[int, str, bytes]:
        if mode == "http500":
            return 500, "application/json", b'{"error": "synthetic failure"}'
        if mode == "non_json":
            return 200, "text/plain", b"this is not json"
        if mode == "empty":
            return 200, "application/json", b"{}"
        if mode == "timeout":
            time.sleep(1.5)
            return 200, "application/json", b'{"response": "late"}'
        return 200, "application/json", json.dumps({"response": "safe refusal"}).encode()

    return respond


def _disable_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    monkeypatch.setenv("no_proxy", "127.0.0.1")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("mode", "expected_status"),
    [
        ("http500", SentinelStatus.ERROR),
        ("non_json", SentinelStatus.INCONCLUSIVE),
        ("empty", SentinelStatus.INCONCLUSIVE),
        ("timeout", SentinelStatus.ERROR),
    ],
)
async def test_probe_failure_result_is_not_clean(
    mode: str, expected_status: SentinelStatus, monkeypatch: pytest.MonkeyPatch
) -> None:
    _disable_proxy(monkeypatch)

    with _loopback(_responder(mode)) as (server, url):
        target = Target(url=url, timeout=1)
        watcher = ContinuousWatcher(target, canary_token=CANARY)
        async with AgentScanClient(target) as client:
            result = await watcher.run_iteration_result(client)

    assert result.status is expected_status
    assert result.clean is False
    assert result.complete is False
    assert result.findings == []
    assert result.error
    assert result.error_id
    assert result.probes_attempted == 1
    assert result.probes_completed == 0
    assert len(server.requests) == 1


@pytest.mark.asyncio
async def test_connection_refused_result_is_not_clean(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _disable_proxy(monkeypatch)
    target = Target(url=f"http://127.0.0.1:{_free_port()}/chat", timeout=1)
    watcher = ContinuousWatcher(target, canary_token=CANARY)

    async with AgentScanClient(target) as client:
        result = await watcher.run_iteration_result(client)

    assert result.status is SentinelStatus.ERROR
    assert result.clean is False
    assert result.complete is False
    assert result.findings == []
    assert result.error


@pytest.mark.asyncio
async def test_failed_cycle_makes_the_run_incomplete(monkeypatch: pytest.MonkeyPatch) -> None:
    _disable_proxy(monkeypatch)

    with _loopback(_responder("http500")) as (_server, url):
        target = Target(url=url, timeout=1)
        watcher = ContinuousWatcher(target, max_iterations=3, canary_token=CANARY)
        async with AgentScanClient(target) as client:
            result = await watcher.run_loop_result(client)

    assert result.status is SentinelStatus.ERROR
    assert result.clean is False
    assert result.complete is False
    assert result.failed_cycle is not None
    assert result.error_message
    assert len(result.cycles) == 1


@pytest.mark.parametrize("mode", ["http500", "non_json", "empty", "refused"])
def test_watch_cli_probe_failure_exits_nonzero_without_pass(
    mode: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    _disable_proxy(monkeypatch)
    if mode == "refused":
        result = CliRunner().invoke(
            app,
            [
                "watch",
                f"http://127.0.0.1:{_free_port()}/chat",
                "--iterations",
                "1",
                "--canary",
                CANARY,
            ],
        )
    else:
        with _loopback(_responder(mode)) as (_server, url):
            result = CliRunner().invoke(
                app, ["watch", url, "--iterations", "1", "--canary", CANARY]
            )

    assert result.exit_code != 0
    assert "PASS" not in result.output
    assert "completed cleanly" not in result.output
    assert "Sentinel evaluation failed" in result.output
    assert ("ERROR" in result.output) or ("INCONCLUSIVE" in result.output)


def test_watch_cli_timeout_exits_nonzero_without_pass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _disable_proxy(monkeypatch)
    real_target = Target
    monkeypatch.setattr("agentscan.core.models.Target", lambda url: real_target(url=url, timeout=1))

    with _loopback(_responder("timeout")) as (server, url):
        result = CliRunner().invoke(app, ["watch", url, "--iterations", "1", "--canary", CANARY])

    assert result.exit_code != 0
    assert len(server.requests) == 1
    assert "PASS" not in result.output
    assert "completed cleanly" not in result.output
    assert "Sentinel evaluation failed (ERROR)" in result.output


def test_watch_cli_clean_cycle_still_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _disable_proxy(monkeypatch)

    with _loopback(_responder("clean")) as (server, url):
        result = CliRunner().invoke(app, ["watch", url, "--iterations", "1", "--canary", CANARY])

    assert result.exit_code == 0, result.output
    assert len(server.requests) == 3
    assert "Cycle 1: PASS - Canary secure, 0 findings." in result.output
    assert "Sentinel completed cleanly with 0 regressions." in result.output
