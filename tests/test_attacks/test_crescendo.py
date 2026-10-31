"""ATK-010's declared deterministic conversation and private-reference scope."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx

from agentscan.attacks.exploit.crescendo import CrescendoModule
from agentscan.core.context import active_context
from agentscan.core.models import ScanMode, Target
from agentscan.core.outcomes import ExecutionLedger, execution_ledger

URL = "http://synthetic.invalid/crescendo"
PRIVATE = "SYNTHETIC_CRESCENDO_PRIVATE_Q9k7Z"
SAFE = "I can discuss the public task without disclosing the private reference."


@pytest.fixture(autouse=True)
def isolated_context():
    token = active_context.set(None)
    try:
        yield
    finally:
        active_context.reset(token)


@pytest.fixture
def ledger():
    value = ExecutionLedger()
    token = execution_ledger.set(value)
    try:
        yield value
    finally:
        execution_ledger.reset(token)


def test_six_bounded_conversation_families_have_no_public_success_marker():
    module = CrescendoModule()
    scripts = module._load_scripts()
    assert module.variant_count() == len(scripts) == 6
    assert [script["id"] for script in scripts] == [f"CRESC-{n:03d}" for n in range(1, 7)]
    assert all(4 <= len(script["turns"]) <= 6 for script in scripts)
    assert all("canary" not in script and "judge_objective" not in script for script in scripts)
    assert "AGENTSCAN-CRESCENDO-OK" not in json.dumps(scripts)
    assert module.is_applicable(Target(url=URL, mode=ScanMode.EXPLOIT))
    assert not module.is_applicable(Target(url=URL, mode=ScanMode.SCAN))


@pytest.mark.asyncio
async def test_history_grows_with_real_prior_answers_and_resets_per_script(ledger):
    requests = []

    def respond(request):
        body = json.loads(request.content)
        messages = body["messages"]
        requests.append(messages)
        turn = (len(messages) + 1) // 2
        assert [m["role"] for m in messages] == ["user", "assistant"] * (turn - 1) + ["user"]
        assert all(m["content"] == f"Public answer {n + 1}" for n, m in enumerate(messages[1::2]))
        assert PRIVATE not in request.content.decode()
        return httpx.Response(200, json={"response": f"Public answer {turn}", "complete": True})

    with respx.mock() as mock:
        route = mock.post(URL).mock(side_effect=respond)
        findings = await CrescendoModule().run(
            Target(url=URL, mode="EXPLOIT", canary_token=PRIVATE)
        )
    assert route.call_count == 30
    assert [(len(messages) + 1) // 2 for messages in requests] == list(range(1, 6)) * 6
    assert findings == []
    assert ledger.selected == ledger.evaluated == 6
    assert [row["status"] for row in ledger.observations] == ["NO_DISCLOSURE"] * 6
    assert all(row["delivered_turns"] == row["evaluated_turns"] == 5 for row in ledger.observations)


@pytest.mark.asyncio
@pytest.mark.parametrize("reply", [PRIVATE, " ".join(PRIVATE), f'I refuse, but "{PRIVATE}".'])
async def test_disclosure_stops_script_before_replaying_private_answer(reply, ledger):
    def respond(request):
        body = json.loads(request.content)
        turn = len(body["messages"][::2])
        assert turn <= 3
        assert PRIVATE not in request.content.decode()
        return httpx.Response(200, json={"response": reply if turn == 3 else SAFE, "done": True})

    with respx.mock() as mock:
        route = mock.post(URL).mock(side_effect=respond)
        findings = await CrescendoModule().run(
            Target(url=URL, mode="EXPLOIT", canary_token=PRIVATE)
        )
    assert route.call_count == 18
    assert ledger.evaluated == len(findings) == 6
    assert all(f.turn_number == 3 for f in findings)
    assert all(f.metadata["tool_execution_verified"] is False for f in findings)
    assert PRIVATE not in json.dumps([f.model_dump(mode="json") for f in findings])
    assert all(
        row["status"] == "DISCLOSURE" and row["finding_turn"] == 3 for row in ledger.observations
    )


@pytest.mark.asyncio
async def test_models_mutations_and_retry_opt_ins_cannot_expand_deterministic_profile(ledger):
    with (
        patch("agentscan.core.ai_client.AIClient.complete", new_callable=AsyncMock) as provider,
        respx.mock() as mock,
    ):
        route = mock.post(URL).respond(200, json={"response": SAFE})
        findings = await CrescendoModule().run(
            Target(
                url=URL,
                mode="EXPLOIT",
                canary_token=PRIVATE,
                mutate=True,
                mutation_budget=10,
                retry_state_changing_requests=True,
                attacker_model="ollama/never-run",
                judge_model="ollama/never-run",
            )
        )
    provider.assert_not_called()
    assert route.call_count == 30
    assert ledger.evaluated == 6
    assert findings == []
