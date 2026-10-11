"""Echoed target credentials must not reach optional external analysis providers."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from agentscan.attacks.registry import AttackRegistry
from agentscan.core.ai_client import AIClient
from agentscan.core.context import active_context
from agentscan.core.models import RequestTemplate, Target
from agentscan.core.runner import run_scan


@pytest.mark.parametrize(
    "credentials",
    [
        {"auth_header": "Bearer short-fixture-token"},
        {"auth_header": "X-Api-Key: short-fixture-token"},
        {"extra_headers": {"Authorization": "Bearer short-fixture-token"}},
        {"extra_headers": {"Cookie": "session=short-fixture-token; other=another-fixture-value"}},
        {
            "request_template": RequestTemplate(
                url="https://owned.invalid/chat",
                message_path="message",
                headers={"Authorization": "Basic short-fixture-token"},
            )
        },
    ],
)
async def test_bare_echoed_credential_removed_from_analysis(monkeypatch, credentials):
    target = Target(
        url="https://owned.invalid/chat",
        analysis_mode="external",
        data_classification="non_sensitive",
        external_model="gemini/synthetic-model",
        **credentials,
    )
    registry = AttackRegistry()
    registry._loaded = True
    monkeypatch.setattr("agentscan.core.runner.registry", registry)
    monkeypatch.setattr(
        "agentscan.core.external_analysis.provider_key", lambda *args, **kwargs: "synthetic-key"
    )
    wire = AsyncMock(return_value="Synthetic analysis complete.")
    monkeypatch.setattr("agentscan.core.external_analysis.external_chat", wire)
    previous = active_context.get()
    try:
        await run_scan(target)
        await AIClient("gemini/synthetic-model").complete(
            "Target replied: short-fixture-token; other=another-fixture-value"
        )
        sent = str(wire.call_args.args[1])
        assert "short-fixture-token" not in sent
        assert "REDACTED" in sent
        if "Cookie" in credentials.get("extra_headers", {}):
            assert "another-fixture-value" not in sent
    finally:
        active_context.set(previous)
