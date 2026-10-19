"""Strict baseline and independent response-schema boundary tests."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from agentscan.core.factuality import (
    FactualityBaseline,
    FactualityCase,
    evaluate_factuality_response,
    factuality_baseline_digest,
    factuality_requests,
)
from agentscan.core.models import BrowserConfig, RequestTemplate, ScanMode, Target

URL = "https://agent.example/chat"


def case(**updates):
    return {
        "id": "FACT-01",
        "question": "Synthetic question?",
        "expected_answer": "blue",
        "false_answer": "red",
        **updates,
    }


def baseline(**updates):
    return {
        "schema_version": "agentscan.factuality.v1",
        "target_url": URL,
        "cases": [case()],
        **updates,
    }


@pytest.mark.parametrize(
    "updates",
    [
        {"id": "bad id"},
        {"id": "é"},
        {"id": "a" * 65},
        {"id": ""},
        {"question": " "},
        {"question": 2},
        {"question": "a" * 2049},
        {"expected_answer": ""},
        {"expected_answer": "a" * 513},
        {"false_answer": "blue"},
        {"false_answer": None},
        {"extra": "wrong"},
        {"question": "\ud800"},
    ],
)
def test_case_rejects_invalid_approved_values(updates):
    with pytest.raises(ValidationError):
        FactualityCase.model_validate(case(**updates))


@pytest.mark.parametrize(
    "updates",
    [
        {"cases": []},
        {"cases": [case()] * 2},
        {"cases": [case(id=str(i)) for i in range(17)]},
        {"cases": "wrong"},
        {"schema_version": "unknown"},
        {"source": "target-output"},
        {"target_url": "mcp://stdio"},
        {"target_url": "https://user:secret@agent.example/chat"},
        {"target_url": "https://agent.example/chat#private"},
        {"target_url": "https://agent.example:0/chat"},
        {"target_url": "https://agent.example:99999/chat"},
        {"target_url": " https://agent.example/chat"},
        {"target_url": "https://agent.example\\other/chat"},
    ],
)
def test_baseline_rejects_unbound_or_unbounded_configuration(updates):
    with pytest.raises(ValidationError):
        FactualityBaseline.model_validate(baseline(**updates))


def test_baseline_digest_is_stable_and_binds_all_configuration():
    original = FactualityBaseline.model_validate(baseline())
    assert factuality_baseline_digest(original) == factuality_baseline_digest(
        FactualityBaseline.model_validate(baseline())
    )
    changed = FactualityBaseline.model_validate(baseline(cases=[case(expected_answer="green")]))
    assert factuality_baseline_digest(original) != factuality_baseline_digest(changed)
    requests = factuality_requests(original.cases[0])
    assert len(requests) == 2
    assert all("blue" not in message for _, message in requests)


@pytest.mark.parametrize(
    "updates",
    [
        {"url": "https://other.example/chat"},
        {"mode": ScanMode.EXPLOIT},
        {"mode": ScanMode.DEEP},
        {"analysis_mode": "local"},
        {"mutate": True},
        {"retry_state_changing_requests": True},
        {"judge_model": "ollama/fake"},
        {"attacker_model": "ollama/fake"},
        {"escalation_model": "ollama/fake"},
        {"indirect_adapter": "document_v1"},
        {"request_template": RequestTemplate(url=URL, message_path="message")},
        {"browser": BrowserConfig(url=URL, input_selector="#in", response_selector="#out")},
    ],
)
def test_target_rejects_profile_conflicts(updates):
    with pytest.raises(ValidationError):
        Target(**{"url": URL, "factuality_baseline": baseline(), **updates})


@pytest.mark.parametrize(
    "text",
    [
        "I refuse",
        "",
        '{"answer":"blue"',
        '{"answer":"red","answer":"blue"}',
        '{"answer":"blue","extra":0}',
        '{"answer":4}',
        '{"answer":null}',
        '{"answer":" "}',
        '[{"answer":"blue"}]',
        '```json\n{"answer":"blue"}\n```',
        'prefix {"answer":"blue"}',
        '{"answer":"blue"} trailing',
        json.dumps({"answer": "a" * 513}),
        '{"answer":"\\ud800"}',
    ],
)
def test_response_contract_rejects_ambiguous_or_unreadable_answers(text):
    verdict = evaluate_factuality_response({"response": text})
    assert verdict.status == "inconclusive" and verdict.answer is None
    assert text not in verdict.reason or text == ""


@pytest.mark.parametrize(
    "updates",
    [
        {"truncated": True},
        {"truncated": "yes"},
        {"incomplete": True},
        {"complete": False},
        {"done": 1},
        {"finish_reason": "length"},
        {"status_code": 401},
        {"status_code": 200.0},
        {"error": "private"},
        {"raw": 'data: {"response":"partial"}'},
    ],
)
def test_response_contract_rejects_incomplete_delivery(updates):
    assert (
        evaluate_factuality_response({"response": '{"answer":"blue"}', **updates}).status
        == "inconclusive"
    )


def test_complete_exact_answer_is_literal_and_bounded():
    verdict = evaluate_factuality_response({"response": ' {"answer":"Blue"} ', "done": True})
    assert verdict.status == "complete" and verdict.answer == "Blue"
    assert verdict.response_bytes and len(verdict.response_sha256) == 64
    assert (
        evaluate_factuality_response({"response": '{"answer":"blue"}'}, max_bytes=1).status
        == "inconclusive"
    )
