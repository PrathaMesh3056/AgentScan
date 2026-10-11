"""Negative controls for DNS rebinding, redirects, payload size and request budgets."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock

import httpx
import pytest

from agentscan.core.context import active_context, begin_scan_context
from agentscan.core.egress import (
    PinnedNetworkBackend,
    canonical_origin,
    enrolled_request,
    permitted_ip,
)
from agentscan.core.models import Target


@pytest.fixture(autouse=True)
def isolated_context():
    token = active_context.set(None)
    yield
    active_context.reset(token)


@pytest.mark.parametrize(
    "address",
    ["127.0.0.1", "10.0.0.1", "169.254.169.254", "::ffff:127.0.0.1", "::1", "0.0.0.0", "224.0.0.1"],
)
def test_private_metadata_loopback_and_special_addresses_denied_without_enrollment(address):
    assert not permitted_ip(address, [])


async def test_validated_dns_address_is_the_actual_tcp_destination(monkeypatch):
    resolver = AsyncMock(return_value=[(2, 1, 6, "", ("8.8.8.8", 443))])
    monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", resolver)
    delegate = AsyncMock()
    backend = PinnedNetworkBackend(
        Target(url="https://owned.test", allowed_hosts=["owned.test"], allowed_networks=[]),
        delegate,
    )
    await backend.connect_tcp("owned.test", 443)
    delegate.connect_tcp.assert_awaited_once()
    assert delegate.connect_tcp.await_args.args[:2] == ("8.8.8.8", 443)
    assert resolver.await_count == 1


async def test_mixed_public_and_private_dns_answers_fail_before_connect(monkeypatch):
    monkeypatch.setattr(
        asyncio.get_running_loop(),
        "getaddrinfo",
        AsyncMock(
            return_value=[(2, 1, 6, "", ("8.8.8.8", 443)), (2, 1, 6, "", ("127.0.0.1", 443))]
        ),
    )
    delegate = AsyncMock()
    backend = PinnedNetworkBackend(
        Target(url="https://owned.test", allowed_hosts=["owned.test"], allowed_networks=[]),
        delegate,
    )
    with pytest.raises(httpx.ConnectError, match="unauthorized"):
        await backend.connect_tcp("owned.test", 443)
    delegate.connect_tcp.assert_not_awaited()


def test_explicit_private_range_does_not_authorize_metadata_or_other_ranges():
    assert permitted_ip("10.8.0.3", ["10.8.0.0/24"])
    assert permitted_ip("::1", ["::1/128"])
    assert not permitted_ip("10.9.0.3", ["10.8.0.0/24"])
    assert not permitted_ip("169.254.169.254", ["169.254.0.0/16"])


async def test_port_change_redirect_is_denied_before_second_contact():
    calls = []

    def handler(request):
        calls.append(str(request.url))
        return httpx.Response(307, headers={"Location": "http://owned.test:8080/chat"})

    target = Target(
        url="http://owned.test/chat", allowed_origins=[canonical_origin("http://owned.test")]
    )
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(ValueError, match="origin"):
            await enrolled_request(client, target, "POST", target.url, {"message": "fixture"})
    assert calls == [target.url]


async def test_approved_cross_origin_redirect_strips_all_supplied_headers():
    received = []

    def handler(request):
        received.append(request)
        if request.url.host == "first.test":
            return httpx.Response(307, headers={"Location": "http://second.test/chat"})
        return httpx.Response(200, json={"response": "fixture"})

    target = Target(
        url="http://first.test/chat",
        extra_headers={"X-Custom-Credential": "fixture-private"},
        allowed_origins=[
            canonical_origin("http://first.test"),
            canonical_origin("http://second.test"),
        ],
    )
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler), headers=target.extra_headers
    ) as client:
        await enrolled_request(client, target, "POST", target.url, {})
    assert received[0].headers["X-Custom-Credential"] == "fixture-private"
    assert "X-Custom-Credential" not in received[1].headers


async def test_response_limit_closes_stream_instead_of_retaining_large_body():
    target = Target(url="http://owned.test", max_response_bytes=1024)
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, content=b"x" * 2048))
    ) as client:
        with pytest.raises(httpx.ReadError, match="size limit"):
            await enrolled_request(client, target, "POST", target.url, {})


async def test_redirects_consume_the_same_scan_request_budget():
    context = begin_scan_context()
    context.request_budget = 1
    target = Target(url="http://owned.test/start")
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(307, headers={"Location": "http://owned.test/next"})

    from agentscan.core.outcomes import TargetRequestError

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(TargetRequestError, match="budget"):
            await enrolled_request(client, target, "POST", target.url, {})
    assert len(calls) == 1
