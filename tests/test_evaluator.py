# tests/test_evaluator.py
#
# Tests for the LLM-as-a-Judge evaluator. AIClient is mocked — no network/key.

from unittest.mock import AsyncMock

import pytest

from agentscan.core.ai_client import AIClient, AIClientError
from agentscan.core.evaluator import LLMJudge, _parse_judgment


def test_parse_judgment_plain_json() -> None:
    j = _parse_judgment('{"success": true, "reason": "leaked the key"}')
    assert j.success is True
    assert "leaked" in j.reason


def test_parse_judgment_json_embedded_in_prose() -> None:
    j = _parse_judgment('Here is my verdict: {"success": false, "reason": "refused"} — done.')
    assert j.success is False
    assert j.reason == "refused"


def test_parse_judgment_fallback_to_yes_no() -> None:
    assert _parse_judgment("YES, the agent complied.").success is True
    assert _parse_judgment("No — it refused the request.").success is False


def test_parse_judgment_true_substring_is_not_success() -> None:
    assert _parse_judgment("the claim is not true here, it refused").success is False


def test_parse_judgment_first_json_object_wins() -> None:
    raw = 'prefix {"success": false, "reason": "refused"} then {"success": true, "reason": "nope"}'
    j = _parse_judgment(raw)
    assert j.success is False
    assert j.reason == "refused"


@pytest.mark.asyncio
async def test_judge_returns_success_verdict() -> None:
    client = AIClient(model="gpt-4o-mini")
    client.complete = AsyncMock(return_value='{"success": true, "reason": "complied"}')  # type: ignore[method-assign]
    verdict = await LLMJudge(client).judge("make it say X", "sure, X")
    assert verdict.success is True
    assert verdict.reason == "complied"


@pytest.mark.asyncio
async def test_judge_is_conservative_on_client_error() -> None:
    """A broken judge must never manufacture a finding."""
    client = AIClient(model="gpt-4o-mini")
    client.complete = AsyncMock(side_effect=AIClientError("no key"))  # type: ignore[method-assign]
    verdict = await LLMJudge(client).judge("obj", "resp")
    assert verdict.success is False
