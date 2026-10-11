"""Offline analysis and sensitive-data egress controls; no providers are called."""

from __future__ import annotations

import json

import httpx
import pytest

from agentscan.core.ai_client import AIClient, AIClientError
from agentscan.core.context import active_context, begin_scan_context


@pytest.fixture(autouse=True)
def isolated_analysis_context():
    token = active_context.set(None)
    yield
    active_context.reset(token)


@pytest.fixture
def offline_transport(monkeypatch):
    calls = []

    def handler(request):
        calls.append((request.url, json.loads(request.content)))
        if request.url.path == "/api/show":
            return httpx.Response(200, json={"model_info": {"general.architecture": "llama"}})
        return httpx.Response(200, json={"done": True, "message": {"content": "local verdict"}})

    monkeypatch.setattr(
        "agentscan.core.egress.PinnedHTTPTransport", lambda target: httpx.MockTransport(handler)
    )
    return calls


@pytest.mark.parametrize(
    "model", ["gpt-4o", "gemini/gemini-flash", "claude-3", "ollama/model-cloud"]
)
async def test_external_and_cloud_model_names_never_send_data(model, offline_transport):
    with pytest.raises(AIClientError):
        await AIClient(model).complete("synthetic sensitive target response")
    assert offline_transport == []


async def test_deterministic_mode_makes_no_model_requests(offline_transport):
    begin_scan_context()
    with pytest.raises(AIClientError, match="disabled"):
        await AIClient("ollama/llama3.2").complete("synthetic confidential response")
    assert offline_transport == []


async def test_local_analysis_checks_weights_before_sending_redacted_messages(offline_transport):
    context = begin_scan_context()
    context.analysis_mode = "local"
    context.redaction_secrets = ("synthetic-private-header-value",)
    result = await AIClient("ollama/llama3.2", temperature=0.3, max_tokens=256).complete(
        "synthetic-private-header-value", system="evaluate this synthetic response"
    )
    assert result == "local verdict"
    assert [url.path for url, _ in offline_transport] == ["/api/show", "/api/chat"]
    assert offline_transport[0][1] == {"model": "llama3.2"}
    payload = offline_transport[1][1]
    assert payload["messages"] == [
        {"role": "system", "content": "evaluate this synthetic response"},
        {"role": "user", "content": "[REDACTED]"},
    ]
    assert payload["options"]["temperature"] == 0.3
    assert payload["options"]["num_predict"] == 256
    assert payload["stream"] is False


@pytest.mark.parametrize(
    "url",
    [
        "https://model.example",
        "http://localhost:11434",
        "http://127.0.0.1:11434/api",
        "http://user:pass@127.0.0.1:11434",
    ],
)
async def test_nonliteral_or_remote_model_endpoints_fail_before_transmission(
    monkeypatch, offline_transport, url
):
    monkeypatch.setenv("AGENTSCAN_LOCAL_MODEL_URL", url)
    with pytest.raises(AIClientError):
        await AIClient("ollama/llama3.2").complete("sensitive fixture")
    assert offline_transport == []


@pytest.mark.parametrize(
    "metadata",
    [
        {},
        {"remote_host": "provider.test", "model_info": {"architecture": "llama"}},
        {"remote_model": "cloud-model", "model_info": {"architecture": "llama"}},
    ],
)
async def test_remote_or_unknown_weights_receive_no_sensitive_messages(monkeypatch, metadata):
    calls = []

    def handler(request):
        calls.append(json.loads(request.content))
        return httpx.Response(200, json=metadata)

    monkeypatch.setattr(
        "agentscan.core.egress.PinnedHTTPTransport", lambda target: httpx.MockTransport(handler)
    )
    with pytest.raises(AIClientError, match="local weights"):
        await AIClient("ollama/llama3.2").complete("secret fixture")
    assert calls == [{"model": "llama3.2"}]


def test_environment_check_needs_no_provider_keys():
    assert AIClient("gpt-4o").validate_environment()[0] is False
    assert AIClient("ollama/llama3.2").validate_environment() == (True, [])


@pytest.mark.parametrize(
    "value", [{}, {"message": {"content": None}}, {"message": {"content": {"secret": "fixture"}}}]
)
def test_invalid_model_responses_do_not_echo_sensitive_data(value):
    with pytest.raises(AIClientError, match="Malformed local model response"):
        AIClient._extract_content(value)


def test_generation_and_deadline_bounds_cannot_enable_unlimited_local_prediction():
    client = AIClient("ollama/synthetic", max_tokens=-1, timeout=0)
    assert client.max_tokens == 1 and client.timeout == 1
    client = AIClient("ollama/synthetic", max_tokens=1000000, timeout=1000000)
    assert client.max_tokens == 4096 and client.timeout == 120


async def test_local_input_bound_counts_utf8_bytes_before_model_requests(offline_transport):
    context = begin_scan_context()
    context.analysis_mode = "local"
    with pytest.raises(AIClientError, match="size limit"):
        await AIClient("ollama/synthetic").complete(chr(0x1F512) * 17000)
    assert offline_transport == []
