"""Regressions from independent ATK-010 boundary and concurrency review."""

from __future__ import annotations

import httpx
import pytest
import respx

from agentscan.attacks.exploit.crescendo import CrescendoModule
from agentscan.core.context import ScanContext, active_context
from agentscan.core.models import RequestTemplate, ScanMode, Target
from agentscan.core.outcomes import ExecutionLedger, execution_ledger

URL = "http://synthetic.invalid/crescendo-review"
PRIVATE = "SYNTHETIC_ATK010_REVIEW_P7qR8"


@pytest.fixture
def ledger():
    value = ExecutionLedger()
    context_token = active_context.set(None)
    ledger_token = execution_ledger.set(value)
    try:
        yield value
    finally:
        execution_ledger.reset(ledger_token)
        active_context.reset(context_token)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "body,path",
    [
        ({"result": {"reply": PRIVATE, "done": False}}, "result.reply"),
        ({"result": {"reply": PRIVATE, "truncated": True}}, "result.reply"),
        ({"response": PRIVATE, "raw": {"error": "synthetic failure"}}, None),
        ({"response": PRIVATE, "raw": {"choices": [{"finish_reason": "length"}]}}, None),
        ({"response": PRIVATE, "status_code": False}, None),
        ({"result": {"reply": [PRIVATE]}}, "result.reply"),
        ({"result": {"reply": {"private_metadata": PRIVATE}}}, "result.reply"),
    ],
)
async def test_nested_or_malformed_response_cannot_establish_disclosure(body, path, ledger):
    target = Target(url=URL, mode=ScanMode.EXPLOIT, canary_token=PRIVATE)
    if path is not None:
        target.request_template = RequestTemplate(
            url=URL, json_body={"message": ""}, message_path="message", response_path=path
        )
    with respx.mock() as mock:
        mock.post(URL).respond(200, json=body)
        assert await CrescendoModule().run(target) == []
    assert ledger.evaluated == 0
    assert ledger.errors or ledger.inconclusive_reasons
    assert PRIVATE not in str(ledger.observations)


@pytest.mark.asyncio
async def test_script_dispatch_counts_exclude_other_modules_requests(ledger):
    def handle(request):
        # Mixed scans share a context; other modules can dispatch while this
        # module awaits a response. Their deliveries must not enter this row.
        active_context.get().target_requests += 1
        return httpx.Response(200, json={"response": "Public response"})

    with respx.mock() as mock:
        route = mock.post(URL).mock(side_effect=handle)
        assert (
            await CrescendoModule().run(
                Target(url=URL, mode=ScanMode.EXPLOIT, canary_token=PRIVATE)
            )
            == []
        )
    assert route.call_count == 30
    assert ledger.evaluated == 6
    assert all(row["delivered_turns"] == 5 for row in ledger.observations)


@pytest.mark.asyncio
async def test_target_budget_applies_inside_existing_context_without_replacing_policy(ledger):
    context = ScanContext(request_budget=None)
    token = active_context.set(context)
    try:
        with respx.mock() as mock:
            route = mock.post(URL).respond(200, json={"response": PRIVATE})
            findings = await CrescendoModule().run(
                Target(url=URL, mode=ScanMode.EXPLOIT, canary_token=PRIVATE, request_budget=1)
            )
        assert route.call_count == len(findings) == 1
        assert context.target_requests == 1
        assert context.request_budget is None
        assert ledger.evaluated == 1 and ledger.errors
    finally:
        active_context.reset(token)


@pytest.mark.asyncio
async def test_failed_response_read_still_records_own_dispatch(ledger):
    with respx.mock() as mock:
        route = mock.post(URL).mock(side_effect=httpx.ReadError("Synthetic interrupted reply"))
        assert (
            await CrescendoModule().run(
                Target(url=URL, mode=ScanMode.EXPLOIT, canary_token=PRIVATE)
            )
            == []
        )
    assert route.call_count == 1
    assert ledger.observations[0]["status"] == "ERROR"
    assert ledger.observations[0]["delivered_turns"] == 1
    assert ledger.observations[0]["evaluated_turns"] == 0
    assert all(row["status"] == "NOT_RUN" for row in ledger.observations[1:])
