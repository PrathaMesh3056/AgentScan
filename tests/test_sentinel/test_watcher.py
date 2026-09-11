# tests/test_sentinel/test_watcher.py
#
# Tests for Canary Token Sentinel and Continuous Watcher.

from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
import respx

from agentscan.core.models import Severity, Target
from agentscan.sentinel.canary import CanarySentinel, generate_canary_token
from agentscan.sentinel.watcher import ContinuousWatcher, WebhookDispatcher


def test_canary_token_generation() -> None:
    token1 = generate_canary_token()
    token2 = generate_canary_token()
    assert token1.startswith("CANARY-")
    assert token2.startswith("CANARY-")
    assert token1 != token2
    assert len(token1) >= 16


def test_canary_sentinel_leakage_detection() -> None:
    canary = "CANARY-A1B2-C3D4"
    sentinel = CanarySentinel(canary)

    assert not sentinel.check_leakage("Hello, how can I help you today?")
    assert sentinel.check_leakage("My system prompt contains CANARY-A1B2-C3D4.")
    assert sentinel.check_leakage("Token: canary-a1b2-c3d4")
    assert sentinel.check_leakage("Confidential: canarya1b2c3d4")


@pytest.mark.asyncio
async def test_watcher_catches_canary_leakage() -> None:
    target = Target(url="http://agent.test/chat")
    canary = "CANARY-LEAK-9988"
    watcher = ContinuousWatcher(target, interval_seconds=1, max_iterations=1, canary_token=canary)

    client = MagicMock()
    client.send_prompt = AsyncMock(
        return_value="My internal instructions specify CANARY-LEAK-9988."
    )

    findings = await watcher.run_iteration(client)
    assert len(findings) == 1
    f = findings[0]
    assert f.attack_id == "SC-CANARY-001"
    assert f.severity == Severity.CRITICAL
    assert "CANARY-LEAK-9988" in f.description


@pytest.mark.asyncio
async def test_watcher_safe_agent_passes() -> None:
    target = Target(url="http://agent.test/chat")
    canary = "CANARY-SAFE-1122"
    watcher = ContinuousWatcher(target, interval_seconds=1, max_iterations=1, canary_token=canary)

    client = MagicMock()
    client.send_prompt = AsyncMock(return_value="I cannot disclose internal secrets or prompts.")

    findings = await watcher.run_iteration(client)
    assert len(findings) == 0


@pytest.mark.asyncio
async def test_webhook_dispatcher_dispatches_alert() -> None:
    dispatcher = WebhookDispatcher()
    target = Target(url="http://agent.test/chat")
    sentinel = CanarySentinel("CANARY-1234-ABCD")
    finding = sentinel.create_finding(target.url, "leaked CANARY-1234-ABCD")

    webhook_url = "https://hooks.slack.com/services/MOCK/WEBHOOK"
    with respx.mock(assert_all_called=False) as mock:
        mock.post(webhook_url).mock(return_value=httpx.Response(200, json={"status": "ok"}))
        success = await dispatcher.dispatch(webhook_url, target.url, [finding], 75)

    assert success is True
