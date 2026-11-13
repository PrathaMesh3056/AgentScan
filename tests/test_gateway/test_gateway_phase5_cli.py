"""Phase 5 CLI dispatch tests without network or real credentials."""

from __future__ import annotations

import sys
from contextlib import asynccontextmanager
from types import SimpleNamespace
from typing import Any

import pytest

from agentscan.gateway import cli
from agentscan.gateway.recovery import ReconciliationStatus


def test_main_without_command_returns(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", ["agentscan-gateway"])
    cli.main()


def test_main_dispatches_serve(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(cli, "serve", lambda path: calls.append(path))
    monkeypatch.setattr(sys, "argv", ["agentscan-gateway", "serve", "--config", "gateway.toml"])
    cli.main()
    assert calls == ["gateway.toml"]


def test_main_rejects_unavailable_verify(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", ["agentscan-gateway", "verify"])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 2


def test_serve_runs_injected_server(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    served: list[bool] = []

    class FakeServer:
        async def serve(self) -> None:
            served.append(True)

    @asynccontextmanager
    async def fake_service(_path: Any):
        yield SimpleNamespace()

    monkeypatch.setattr(cli, "open_gateway_service", fake_service)
    cli.serve(tmp_path / "gateway.toml", server_factory=lambda _service: FakeServer())
    assert served == [True]


def test_main_reconcile_prints_bounded_status(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    class FakeResult:
        status = ReconciliationStatus.NO_EFFECT_RECORDED
        appended = None

    async def fake_reconcile(*_args: Any, **_kwargs: Any) -> FakeResult:
        return FakeResult()

    monkeypatch.setattr(cli, "reconcile_gateway", fake_reconcile)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "agentscan-gateway",
            "reconcile",
            "--config",
            "gateway.toml",
            "--idempotency-key",
            "raw-key",
        ],
    )
    cli.main()
    assert capsys.readouterr().out.strip() == "reconciliation=NO_EFFECT_RECORDED receipt=none"


def test_reconcile_rejects_malformed_request_hash() -> None:
    async def run() -> None:
        await cli.reconcile_gateway(
            "gateway.toml", idempotency_key="raw-key", request_hash="not-a-hash"
        )

    with pytest.raises(cli.GatewayCliError, match="request hash"):
        import asyncio

        asyncio.run(run())
