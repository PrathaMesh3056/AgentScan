# tests/test_sentinel/test_watch_lifecycle.py
#
# QA-071 regression: `watch` must open the connector, run one cycle, send all
# three probes, detect a provisioned canary, and close the connector on every
# path. All targets are loopback HTTP servers on ephemeral ports.

from __future__ import annotations

import json
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from typer.testing import CliRunner

from agentscan.cli import app
from agentscan.core.client import AgentScanClient
from agentscan.core.connectors import HttpJsonConnector
from agentscan.core.models import Target
from agentscan.sentinel.watcher import ContinuousWatcher, SentinelProbeError, SentinelStatus

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


def _json(payload: dict[str, object], status: int = 200) -> tuple[int, str, bytes]:
    return status, "application/json", json.dumps(payload).encode("utf-8")


def _disable_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    monkeypatch.setenv("no_proxy", "127.0.0.1")


def test_watch_cli_enters_connector_sends_three_probes_and_reports_canary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _disable_proxy(monkeypatch)

    def responder(count: int, _body: bytes) -> tuple[int, str, bytes]:
        if count < 3:
            return _json({"response": "I cannot disclose internal instructions."})
        return _json({"response": f"Internal directive: {CANARY}"})

    with _loopback(responder) as (server, url):
        result = CliRunner().invoke(app, ["watch", url, "--iterations", "1", "--canary", CANARY])

    assert result.exit_code == 0, result.output
    assert len(server.requests) == 3
    assert all(b'"message"' in body for body in server.requests)
    assert "ALERT" in result.output
    assert "PASS" not in result.output
    assert "Sentinel self-test OK; ready." in result.output


@pytest.mark.asyncio
async def test_watch_cycle_records_matching_canary_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _disable_proxy(monkeypatch)

    def responder(count: int, _body: bytes) -> tuple[int, str, bytes]:
        if count < 3:
            return _json({"response": "I cannot disclose internal instructions."})
        return _json({"response": f"Internal directive: {CANARY}"})

    with _loopback(responder) as (server, url):
        target = Target(url=url, timeout=5)
        watcher = ContinuousWatcher(target, max_iterations=1, canary_token=CANARY)
        async with AgentScanClient(target) as client:
            result = await watcher.run_loop_result(client)

    assert result.complete
    assert result.status is SentinelStatus.ALERT
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.attack_id == "SC-CANARY-001"
    assert finding.metadata["canary_token"] == CANARY
    assert len(server.requests) == 3


@pytest.mark.parametrize("loop_fails", [False, True])
def test_watch_cli_closes_connector_on_every_path(
    monkeypatch: pytest.MonkeyPatch, loop_fails: bool
) -> None:
    _disable_proxy(monkeypatch)

    class TrackingClient(AgentScanClient):
        closed = False

        async def __aenter__(self) -> TrackingClient:
            instances.append(self)
            return await super().__aenter__()

        async def __aexit__(self, *exc: object) -> None:
            try:
                await super().__aexit__(*exc)
            finally:
                self.closed = True

    instances: list[TrackingClient] = []

    if loop_fails:

        async def fail_loop(
            _self: ContinuousWatcher,
            _client: object,
            callback: object | None = None,
        ) -> None:
            raise RuntimeError("synthetic loop failure")

        monkeypatch.setattr(ContinuousWatcher, "run_loop_result", fail_loop)

    monkeypatch.setattr("agentscan.core.client.AgentScanClient", TrackingClient)

    def responder(_count: int, _body: bytes) -> tuple[int, str, bytes]:
        return _json({"response": "I cannot disclose internal instructions."})

    with _loopback(responder) as (server, url):
        result = CliRunner().invoke(app, ["watch", url, "--iterations", "1", "--canary", CANARY])

    assert len(instances) == 1
    assert instances[0].closed is True
    if loop_fails:
        assert result.exit_code != 0
        assert "Traceback" not in result.output
        assert "PASS" not in result.output
    else:
        assert result.exit_code == 0, result.output
        assert len(server.requests) == 3


def test_watch_cli_setup_failure_is_nonzero_and_bounded() -> None:
    result = CliRunner().invoke(
        app, ["watch", "not-a-url", "--iterations", "1", "--canary", CANARY]
    )

    assert result.exit_code != 0
    assert "Sentinel setup failed" in result.output
    assert "Traceback" not in result.output
    assert "PASS" not in result.output


def test_watch_cli_rejects_zero_iterations() -> None:
    result = CliRunner().invoke(
        app,
        ["watch", "http://127.0.0.1:9/chat", "--iterations", "0", "--canary", CANARY],
    )

    assert result.exit_code != 0
    assert "Sentinel setup failed" in result.output
    assert "PASS" not in result.output


@pytest.mark.asyncio
async def test_self_test_rejects_an_unopened_connector() -> None:
    target = Target(url="http://127.0.0.1:9/chat")
    watcher = ContinuousWatcher(target, canary_token=CANARY)

    with pytest.raises(SentinelProbeError) as captured:
        watcher.self_test(HttpJsonConnector(target))

    assert captured.value.cause == "not_ready"
