from __future__ import annotations

import json

import httpx
import pytest
from pydantic import ValidationError

from agentscan.core.ai_client import AIClient, AIClientError
from agentscan.core.context import active_context, begin_scan_context
from agentscan.core.external_analysis import provider_key
from agentscan.core.models import Target


@pytest.fixture(autouse=True)
def isolated_context(monkeypatch, tmp_path):
    token = active_context.set(None)
    monkeypatch.chdir(tmp_path)
    for variable in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY"):
        monkeypatch.delenv(variable, raising=False)
    yield
    active_context.reset(token)


@pytest.mark.parametrize("mode", ["deterministic", "local", "external"])
async def test_sensitive_classification_blocks_cloud_before_io(monkeypatch, mode):
    context = begin_scan_context()
    context.analysis_mode = mode
    context.external_model = "gemini/synthetic-model"
    transport_calls = []
    monkeypatch.setattr(
        "agentscan.core.egress.PinnedHTTPTransport", lambda t: transport_calls.append(t)
    )
    if mode == "local":
        context.local_model = "gemini/synthetic-model"
    with pytest.raises(AIClientError):
        await AIClient("gemini/synthetic-model").complete("sensitive synthetic fixture")
    assert transport_calls == []
    with pytest.raises(ValidationError):
        Target(
            url="https://target.invalid",
            analysis_mode="external",
            external_model="gemini/synthetic-model",
        )


@pytest.mark.parametrize(
    "provider,variable,payload",
    [
        (
            "gemini",
            "GEMINI_API_KEY",
            {
                "candidates": [
                    {"finishReason": "STOP", "content": {"parts": [{"text": "synthetic result"}]}}
                ]
            },
        ),
        (
            "openai",
            "OPENAI_API_KEY",
            {"choices": [{"finish_reason": "stop", "message": {"content": "synthetic result"}}]},
        ),
        (
            "anthropic",
            "ANTHROPIC_API_KEY",
            {"stop_reason": "end_turn", "content": [{"type": "text", "text": "synthetic result"}]},
        ),
    ],
)
async def test_designated_external_adapters_use_fixed_origin_and_header_keys(
    monkeypatch, provider, variable, payload
):
    monkeypatch.setenv(variable, "synthetic-provider-key")
    context = begin_scan_context()
    context.analysis_mode = "external"
    context.data_classification = "non_sensitive"
    context.external_model = f"{provider}/synthetic-model"
    context.redaction_secrets = ("synthetic-target-token",)
    observed = []

    def respond(request):
        observed.append(request)
        return httpx.Response(200, json=payload)

    monkeypatch.setattr(
        "agentscan.core.egress.PinnedHTTPTransport", lambda target: httpx.MockTransport(respond)
    )
    assert AIClient(context.external_model).validate_environment() == (True, [])
    result = await AIClient(context.external_model).complete(
        "synthetic-target-token synthetic-provider-key public fixture",
        system="synthetic instructions",
    )
    assert result == "synthetic result"
    assert len(observed) == 1 and observed[0].url.scheme == "https"
    assert "synthetic-provider-key" not in str(observed[0].url)
    assert "synthetic-provider-key" not in observed[0].content.decode()
    assert "synthetic-target-token" not in observed[0].content.decode()
    if provider == "openai":
        assert json.loads(observed[0].content)["store"] is False
    assert context.analysis_requests == 1


async def test_external_failure_does_not_retry_or_leak_provider_error_body(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "synthetic-key")
    context = begin_scan_context()
    context.analysis_mode = "external"
    context.data_classification = "non_sensitive"
    context.external_model = "gemini/synthetic-model"
    calls = []

    def fail(request):
        calls.append(request)
        return httpx.Response(401, text="synthetic key and private provider diagnostic")

    monkeypatch.setattr(
        "agentscan.core.egress.PinnedHTTPTransport", lambda target: httpx.MockTransport(fail)
    )
    with pytest.raises(AIClientError) as error:
        await AIClient(context.external_model).complete("non-sensitive fixture")
    assert len(calls) == 1 and "private provider diagnostic" not in str(error.value)


def test_service_keys_do_not_fall_back_to_local_dotenv(tmp_path):
    (tmp_path / ".env").write_text("GEMINI_API_KEY=synthetic-dotenv-key\n")
    assert provider_key("gemini") == "synthetic-dotenv-key"
    with pytest.raises(AIClientError):
        provider_key("gemini", allow_dotenv=False)


async def test_external_budget_and_missing_keys_fail_before_transport(monkeypatch):
    context = begin_scan_context()
    context.analysis_mode = "external"
    context.data_classification = "non_sensitive"
    context.external_model = "gemini/synthetic-model"

    def forbidden(target):
        pytest.fail("No transport should be opened")

    monkeypatch.setattr("agentscan.core.egress.PinnedHTTPTransport", forbidden)
    with pytest.raises(AIClientError, match="Configure"):
        await AIClient(context.external_model).complete("public fixture")
    context.analysis_requests = 128
    with pytest.raises(AIClientError, match="budget"):
        await AIClient(context.external_model).complete("public fixture")
