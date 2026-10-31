"""Captured-request credentials stay on their origin across approved redirects."""

from __future__ import annotations

import json

import h11
import httpx
import pytest
import respx

from agentscan.core.connectors.http import RequestTemplateConnector
from agentscan.core.context import active_context, begin_scan_context
from agentscan.core.egress import canonical_origin, enrolled_request
from agentscan.core.models import RequestTemplate, Target
from agentscan.core.outcomes import TargetRequestError

PRIVATE = "synthetic-captured-header-secret"


@pytest.fixture(autouse=True)
def isolated_context():
    token = active_context.set(None)
    try:
        yield
    finally:
        active_context.reset(token)


def target_for(first: str, second: str, **kwargs) -> Target:
    return Target(
        url=first,
        request_template=RequestTemplate(
            url=first,
            headers={"X-Captured-Session": PRIVATE, "X-Captured-Context": "synthetic-account"},
            json_body={"input": ""},
            message_path="input",
            response_path="answer",
        ),
        allowed_origins=list(dict.fromkeys([canonical_origin(first), canonical_origin(second)])),
        **kwargs,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [307, 308])
@pytest.mark.parametrize(
    "first,second",
    [
        ("https://first.test/chat", "https://second.test/chat"),
        ("https://first.test/chat", "https://first.test:8443/chat"),
        ("http://first.test/chat", "https://first.test/chat"),
    ],
)
async def test_actual_captured_connector_strips_captured_headers_on_origin_change(
    status, first, second
):
    target = target_for(first, second)
    context = begin_scan_context()
    with respx.mock() as mock:
        finish = mock.post(second).respond(200, json={"answer": "public response"})
        start = mock.post(first).respond(status, headers={"Location": second})
        async with RequestTemplateConnector(target) as connector:
            response = await connector.send_message("public request")
    assert response["response"] == "public response"
    assert start.call_count == finish.call_count == 1
    assert start.calls[0].request.headers["X-Captured-Session"] == PRIVATE
    assert "X-Captured-Session" not in finish.calls[0].request.headers
    assert "X-Captured-Context" not in finish.calls[0].request.headers
    assert finish.calls[0].request.method == "POST"
    assert finish.calls[0].request.content == start.calls[0].request.content
    assert context.target_requests == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [307, 308])
async def test_same_origin_keeps_captured_headers(status):
    first, second = "https://first.test/start", "https://first.test/next"
    target = target_for(first, second)
    with respx.mock() as mock:
        mock.post(first).respond(status, headers={"Location": "/next"})
        finish = mock.post(second).respond(200, json={"answer": "public response"})
        async with RequestTemplateConnector(target) as connector:
            response = await connector.send_message("public request")
    assert response["response"] == "public response"
    assert finish.calls[0].request.headers["X-Captured-Session"] == PRIVATE
    assert finish.calls[0].request.headers["X-Captured-Context"] == "synthetic-account"


@pytest.mark.asyncio
async def test_header_removal_is_case_insensitive_and_covers_overrides():
    first, second = "https://first.test/chat", "https://second.test/chat"
    target = target_for(first, second, extra_headers={"x-captured-session": "synthetic-override"})
    received = []

    def handle(request):
        received.append(request)
        if len(received) == 1:
            return httpx.Response(308, headers={"Location": second})
        return httpx.Response(200, json={"answer": "public response"})

    assert target.request_template is not None
    headers = {**target.request_template.headers, **target.extra_headers}
    async with httpx.AsyncClient(transport=httpx.MockTransport(handle), headers=headers) as client:
        await enrolled_request(client, target, "POST", first, {"input": "public request"})
    assert len(received) == 2
    assert "x-captured-session" in received[0].headers
    assert "x-captured-session" not in received[1].headers
    assert "x-captured-context" not in received[1].headers


@pytest.mark.asyncio
@pytest.mark.parametrize("stop", ["origin", "host", "budget"])
async def test_redirect_policy_and_shared_budget_prevent_second_contact(stop):
    first, second = "https://first.test/chat", "https://second.test/chat"
    target = target_for(first, second)
    if stop == "origin":
        target.allowed_origins = [canonical_origin(first)]
    elif stop == "host":
        target.allowed_hosts = ["first.test"]
    context = begin_scan_context()
    if stop == "budget":
        context.request_budget = 1
    received = []

    def handle(request):
        received.append(request)
        return httpx.Response(307, headers={"Location": second})

    assert target.request_template is not None
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handle), headers=target.request_template.headers
    ) as client:
        with pytest.raises(TargetRequestError if stop == "budget" else ValueError):
            await enrolled_request(client, target, "POST", first, {"input": "public request"})
    assert len(received) == context.target_requests == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [307, 308])
async def test_captured_protocol_headers_are_regenerated_without_source_values(status):
    first, second = "https://first.test/chat", "https://second.test:8443/chat"
    target = target_for(first, second)
    assert target.request_template is not None
    body = {"input": "public café request"}
    target.request_template.headers.update(
        {
            "Host": "first.test",
            "Content-Length": str(
                len(json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode())
            ),
            "Content-Type": "application/json; private-context=synthetic-only",
        }
    )
    received = []

    def handle(request):
        received.append(request)
        if len(received) == 1:
            return httpx.Response(status, headers={"Location": second})
        # A mocked transport alone accepts malformed framing. Verify the actual
        # HTTP/1.1 encoder would accept the rebuilt destination request too.
        connection = h11.Connection(h11.CLIENT)
        connection.send(
            h11.Request(
                method=request.method, target=request.url.raw_path, headers=request.headers.raw
            )
        )
        connection.send(h11.Data(data=request.content))
        connection.send(h11.EndOfMessage())
        return httpx.Response(200, json={"answer": "public response"})

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handle), headers=target.request_template.headers
    ) as client:
        await enrolled_request(client, target, "POST", first, body)
    assert len(received) == 2
    destination = received[1]
    assert destination.headers["Host"] == "second.test:8443"
    assert int(destination.headers["Content-Length"]) == len(destination.content)
    assert destination.headers["Content-Type"] == "application/json"
    assert "X-Captured-Session" not in destination.headers
    assert destination.content == received[0].content


@pytest.mark.asyncio
async def test_cross_origin_303_keeps_get_and_does_not_restore_original_post_body():
    first, second = "https://first.test/chat", "https://second.test/result"
    target = target_for(first, second)
    assert target.request_template is not None
    target.request_template.headers.update(
        {"Host": "first.test", "Content-Type": "application/json"}
    )
    received = []

    def handle(request):
        received.append(request)
        return (
            httpx.Response(303, headers={"Location": second})
            if len(received) == 1
            else httpx.Response(200, json={"answer": "public response"})
        )

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handle), headers=target.request_template.headers
    ) as client:
        await enrolled_request(client, target, "POST", first, {"input": "public request"})
    assert len(received) == 2
    assert received[0].method == "POST" and received[0].content
    assert received[1].method == "GET" and received[1].content == b""
    assert received[1].headers["Host"] == "second.test"
    assert "Content-Length" not in received[1].headers
    assert "Content-Type" not in received[1].headers
    assert "X-Captured-Session" not in received[1].headers


@pytest.mark.asyncio
async def test_redirect_chain_does_not_reattach_client_default_credentials():
    first, second = "https://first.test/chat", "https://second.test/stage"
    third = "https://second.test/result"
    target = target_for(first, second)
    assert target.request_template is not None
    received = []

    def handle(request):
        received.append(request)
        if len(received) <= 2:
            return httpx.Response(
                307, headers={"Location": second if len(received) == 1 else third}
            )
        return httpx.Response(200, json={"answer": "public response"})

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handle), headers=target.request_template.headers
    ) as client:
        await enrolled_request(client, target, "POST", first, {"input": "public request"})
        assert client.headers["X-Captured-Session"] == PRIVATE
    assert len(received) == 3
    assert received[0].headers["X-Captured-Session"] == PRIVATE
    assert all("X-Captured-Session" not in request.headers for request in received[1:])


@pytest.mark.asyncio
@pytest.mark.parametrize("cross_origin", [False, True])
async def test_cookie_jar_cannot_restore_source_cookie_after_origin_change(cross_origin):
    first = "https://owned.test/start"
    second = "https://owned.test:8443/stage" if cross_origin else "https://owned.test/stage"
    third = second.replace("/stage", "/result")
    target = target_for(first, second)
    received = []

    def handle(request):
        received.append(request)
        if len(received) == 1:
            return httpx.Response(
                307,
                headers={
                    "Location": second,
                    "Set-Cookie": "source-session=synthetic-source-cookie; Path=/; Secure",
                },
            )
        if len(received) == 2:
            return httpx.Response(307, headers={"Location": third})
        return httpx.Response(200, json={"answer": "public response"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as client:
        await enrolled_request(client, target, "POST", first, {"input": "public request"})
        # The guard affects the redirected chain, without mutating the jar.
        assert client.cookies.get("source-session") == "synthetic-source-cookie"
    assert len(received) == 3
    assert "cookie" not in received[0].headers
    if cross_origin:
        assert all("cookie" not in request.headers for request in received[1:])
    else:
        assert all(
            request.headers["cookie"] == "source-session=synthetic-source-cookie"
            for request in received[1:]
        )
