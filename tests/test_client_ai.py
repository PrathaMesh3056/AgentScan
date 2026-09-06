# tests/test_client_ai.py
#
# Unit tests for AIClient. litellm is mocked — no network, no API key needed.

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from agentscan.core.ai_client import AIClient, AIClientError


def _fake_response(content: str | None) -> SimpleNamespace:
    """Build a minimal litellm-shaped response object."""
    message = SimpleNamespace(content=content)
    choice = SimpleNamespace(message=message)
    return SimpleNamespace(choices=[choice])


@pytest.mark.asyncio
async def test_complete_builds_system_and_user_messages() -> None:
    client = AIClient(model="gpt-4o", temperature=0.3, max_tokens=256)
    mock = AsyncMock(return_value=_fake_response("hello"))

    with patch("litellm.acompletion", mock):
        out = await client.complete("do the thing", system="be terse")

    assert out == "hello"
    _, kwargs = mock.call_args
    assert kwargs["model"] == "gpt-4o"
    assert kwargs["messages"] == [
        {"role": "system", "content": "be terse"},
        {"role": "user", "content": "do the thing"},
    ]
    assert kwargs["temperature"] == 0.3
    assert kwargs["max_tokens"] == 256


@pytest.mark.asyncio
async def test_complete_without_system_omits_system_message() -> None:
    client = AIClient(model="claude-3-5-sonnet-latest")
    mock = AsyncMock(return_value=_fake_response("ok"))

    with patch("litellm.acompletion", mock):
        await client.complete("hi")

    _, kwargs = mock.call_args
    assert kwargs["messages"] == [{"role": "user", "content": "hi"}]


@pytest.mark.asyncio
async def test_chat_returns_content() -> None:
    client = AIClient(model="gpt-4o")
    mock = AsyncMock(return_value=_fake_response("multi-turn reply"))

    with patch("litellm.acompletion", mock):
        out = await client.chat([{"role": "user", "content": "hey"}])

    assert out == "multi-turn reply"


@pytest.mark.asyncio
async def test_empty_content_becomes_empty_string() -> None:
    client = AIClient(model="gpt-4o")
    mock = AsyncMock(return_value=_fake_response(None))

    with patch("litellm.acompletion", mock):
        out = await client.complete("hi")

    assert out == ""


@pytest.mark.asyncio
async def test_provider_error_is_wrapped() -> None:
    client = AIClient(model="gpt-4o")
    mock = AsyncMock(side_effect=RuntimeError("429 rate limited"))

    with patch("litellm.acompletion", mock), pytest.raises(AIClientError) as exc:
        await client.complete("hi")

    assert "gpt-4o" in str(exc.value)


@pytest.mark.asyncio
async def test_malformed_response_raises() -> None:
    client = AIClient(model="gpt-4o")
    mock = AsyncMock(return_value=SimpleNamespace(choices=[]))  # no choices

    with patch("litellm.acompletion", mock), pytest.raises(AIClientError):
        await client.complete("hi")


def test_validate_environment_reports_missing_keys() -> None:
    client = AIClient(model="gpt-4o")
    info = {"keys_in_environment": False, "missing_keys": ["OPENAI_API_KEY"]}

    with patch("litellm.validate_environment", return_value=info):
        present, missing = client.validate_environment()

    assert present is False
    assert missing == ["OPENAI_API_KEY"]
