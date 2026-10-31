"""Independent ATK-010 evidence and execution contracts; all HTTP is intercepted."""

from __future__ import annotations

import asyncio
import json
from unittest.mock import patch

import httpx
import pytest
import respx

from agentscan.attacks.exploit.crescendo import CrescendoModule
from agentscan.attacks.registry import AttackRegistry
from agentscan.core import runner
from agentscan.core.context import ScanContext, active_context
from agentscan.core.models import RequestTemplate, ScanMode, Target
from agentscan.core.trace import TrafficRecorder
from agentscan.core.trajectory import TrajectoryRecorder

URL = "http://synthetic.invalid/crescendo"
PRIVATE = "SYNTHETIC_CRESCENDO_PRIVATE_Q9k7Z"
PUBLIC_MARKER = "AGENTSCAN-CRESCENDO-OK"


@pytest.mark.asyncio
async def test_public_marker_echo_is_not_a_private_disclosure():
    with respx.mock() as mock:
        mock.post(URL).respond(200, json={"response": PUBLIC_MARKER})
        findings = await CrescendoModule().run(
            Target(url=URL, mode=ScanMode.EXPLOIT, canary_token=PRIVATE)
        )
    assert findings == []


async def scan(target):
    registry = AttackRegistry()
    registry.register(CrescendoModule())
    registry._loaded = True
    with patch.object(runner, "registry", registry):
        return await runner.run_scan(target)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "body",
    [
        {"response": PRIVATE, "done": False},
        {"response": PRIVATE, "complete": "true"},
        {"response": PRIVATE, "finish_reason": "length"},
        {"response": PRIVATE, "choices": [{"finish_reason": "length"}]},
        {"response": ""},
        {"response": [PRIVATE]},
    ],
)
async def test_incomplete_or_unreadable_private_output_is_not_evaluated(body):
    with respx.mock() as mock:
        mock.post(URL).respond(200, json=body)
        report = await scan(Target(url=URL, mode="EXPLOIT", canary_token=PRIVATE))
    assert report.tests_run == 0 and report.score is None
    assert report.findings == [] and report.status == "INCONCLUSIVE"
    assert PRIVATE not in report.model_dump_json()


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [301, 302, 401, 403, 500])
async def test_http_failure_stops_without_retry_or_redirect(status):
    with respx.mock(assert_all_called=False) as mock:
        route = mock.post(URL).respond(
            status, json={"response": PRIVATE}, headers={"Location": URL + "/else"}
        )
        report = await scan(
            Target(
                url=URL, mode="EXPLOIT", canary_token=PRIVATE, retry_state_changing_requests=True
            )
        )
    assert route.call_count == 1
    assert report.tests_run == 0 and report.findings == [] and report.score is None


@pytest.mark.asyncio
@pytest.mark.parametrize("where", ["header", "url", "body", "history"])
async def test_supplied_reference_prevents_dispatch(where):
    target = Target(url=URL, mode="EXPLOIT", canary_token=PRIVATE)
    if where == "header":
        target.extra_headers = {"X-Public-Context": PRIVATE}
    elif where == "url":
        target.url += "?context=" + PRIVATE
    else:
        target.request_template = RequestTemplate(
            url=URL,
            message_path="message",
            json_body={"message": "", "context": PRIVATE}
            if where == "body"
            else {"message": "", "messages": [{"role": "assistant", "content": PRIVATE}]},
        )
    with respx.mock(assert_all_called=False) as mock:
        route = mock.post(target.url).respond(200, json={"response": PRIVATE})
        report = await scan(target)
    assert route.call_count == 0 and report.tests_run == 0 and report.findings == []
    assert report.score is None and PRIVATE not in report.model_dump_json()


@pytest.mark.asyncio
async def test_captured_post_delivers_retained_history_and_maps_response():
    seen = []

    def handle(request):
        body = json.loads(request.content)
        seen.append(body["query"])
        assert body["public_context"] == "Public data"
        assert PRIVATE not in request.content.decode()
        return httpx.Response(200, json={"answer": {"text": "Public answer"}, "done": True})

    target = Target(
        url=URL,
        mode="EXPLOIT",
        canary_token=PRIVATE,
        request_template=RequestTemplate(
            url=URL,
            message_path="query",
            response_path="answer.text",
            json_body={"query": "", "public_context": "Public data"},
        ),
    )
    with respx.mock() as mock:
        route = mock.post(URL).mock(side_effect=handle)
        report = await scan(target)
    assert route.call_count == 30 and report.tests_run == 6 and report.findings == []
    assert "Public answer" not in seen[0] and "Public answer" in seen[1]


@pytest.mark.asyncio
async def test_sdk_digest_only_even_when_redaction_disabled():
    traffic = TrafficRecorder(redact=False)
    traffic.enabled = True
    trajectory = TrajectoryRecorder()
    token = active_context.set(ScanContext(recorder=traffic, trajectory=trajectory))
    try:
        with respx.mock() as mock:
            mock.post(URL).respond(
                200, json={"response": PRIVATE, "tool_calls": [{"name": "delete_all"}]}
            )
            findings = await CrescendoModule().run(
                Target(url=URL, mode="EXPLOIT", canary_token=PRIVATE)
            )
        assert len(findings) == 6
        assert trajectory.turns() == []
        assert traffic.entries
        assert PRIVATE not in str(traffic.entries)
        assert all("sha256" in item.response.lower() for item in traffic.entries)
    finally:
        active_context.reset(token)


@pytest.mark.asyncio
async def test_received_private_cookie_prevents_next_turn_and_isolates_scripts():
    def handle(request):
        assert "cookie" not in request.headers
        assert len(json.loads(request.content)["messages"]) == 1
        return httpx.Response(
            200,
            json={"response": "Public answer"},
            headers={"Set-Cookie": f"public_context={PRIVATE}; Path=/"},
        )

    with respx.mock() as mock:
        route = mock.post(URL).mock(side_effect=handle)
        report = await scan(Target(url=URL, mode="EXPLOIT", canary_token=PRIVATE))
    assert route.call_count == 6
    assert report.tests_run == 0 and report.findings == [] and report.score is None


@pytest.mark.asyncio
async def test_oversized_response_remains_error_and_stops_dispatch():
    with respx.mock() as mock:
        route = mock.post(URL).respond(200, json={"response": "x" * 70_000 + PRIVATE})
        report = await scan(Target(url=URL, mode="EXPLOIT", canary_token=PRIVATE))
    assert route.call_count == 1
    assert report.tests_run == 0 and report.findings == [] and report.score is None


@pytest.mark.asyncio
async def test_cancellation_propagates_and_restores_sdk_context():
    def handle(request):
        raise asyncio.CancelledError

    token = active_context.set(None)
    try:
        with respx.mock(assert_all_called=False) as mock:
            route = mock.post(URL).mock(side_effect=handle)
            with pytest.raises(asyncio.CancelledError):
                await CrescendoModule().run(Target(url=URL, mode="EXPLOIT", canary_token=PRIVATE))
        assert route.call_count <= 1
        assert active_context.get() is None
    finally:
        active_context.reset(token)


@pytest.mark.asyncio
async def test_multimode_report_redacts_contaminated_target_url():
    registry = AttackRegistry()
    registry.register(CrescendoModule())
    registry._loaded = True
    with patch.object(runner, "registry", registry), respx.mock(assert_all_called=False) as mock:
        route = mock.post(URL + "?ref=" + PRIVATE).respond(200, json={"response": PRIVATE})
        report = await runner.run_scan_multi(
            Target(url=URL + "?ref=" + PRIVATE, canary_token=PRIVATE), [ScanMode.EXPLOIT]
        )
    assert route.call_count == 0 and PRIVATE not in report.model_dump_json()
