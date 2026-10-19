"""Origin admission, DNS/IP pinning and bounded HTTP responses for service scans."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from collections.abc import Iterable
from typing import Any
from urllib.parse import urlsplit

import httpcore
import httpx

from agentscan.core.models import Target


def canonical_origin(url: str) -> str:
    parsed = urlsplit(url)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or "\\" in url
        or any(ord(c) <= 32 for c in url)
    ):
        raise ValueError("An HTTP(S) origin without credentials is required.")
    host = parsed.hostname.rstrip(".").encode("idna").decode("ascii").lower()
    host = f"[{host}]" if ":" in host else host
    return f"{parsed.scheme}://{host}:{parsed.port or (443 if parsed.scheme == 'https' else 80)}"


def validate_target_url(url: str, target: Target) -> None:
    validate_enrolled_url(url, target.allowed_hosts)
    if target.allowed_origins is not None and canonical_origin(url) not in target.allowed_origins:
        raise ValueError("Target or redirect origin is not authorized for this tenant.")


def permitted_ip(value: str, networks: list[str]) -> bool:
    address = ipaddress.ip_address(value)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    # Metadata/link-local, multicast and unspecified addresses have no target role.
    if (
        address.is_link_local
        or address.is_multicast
        or address.is_unspecified
        or (address.is_reserved and not address.is_loopback)
    ):
        return False
    return address.is_global or any(address in ipaddress.ip_network(n) for n in networks)


class PinnedNetworkBackend(httpcore.AsyncNetworkBackend):
    """Resolve once per connection and pass only an approved literal IP to TCP.

    The connection pool keeps the original hostname for Host and TLS verification.
    Mixed public/private DNS answers are rejected rather than selecting a safe one.
    """

    def __init__(self, target: Target, backend: httpcore.AsyncNetworkBackend | None = None) -> None:
        self.target = target
        self.backend = backend or httpcore.AnyIOBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        validate_enrolled_url(
            f"https://[{host}]:{port}" if ":" in host else f"https://{host}:{port}",
            self.target.allowed_hosts,
        )
        async with asyncio.timeout(min(timeout or 5, 5)):
            answers = await asyncio.get_running_loop().getaddrinfo(
                host, port, type=socket.SOCK_STREAM
            )
        addresses = sorted({answer[4][0] for answer in answers})
        if not addresses or not all(
            permitted_ip(ip, self.target.allowed_networks or []) for ip in addresses
        ):
            raise httpx.ConnectError("Target DNS resolved to an unauthorized network address.")
        return await self.backend.connect_tcp(
            addresses[0], port, timeout, local_address, socket_options
        )

    async def connect_unix_socket(
        self, path: str, timeout: float | None = None, socket_options: Iterable[Any] | None = None
    ) -> httpcore.AsyncNetworkStream:
        raise httpx.ConnectError("Unix sockets are unavailable to service scans.")

    async def sleep(self, seconds: float) -> None:
        await asyncio.sleep(seconds)


class _ResponseStream(httpx.AsyncByteStream):
    def __init__(self, response: httpcore.Response) -> None:
        self.response = response

    async def __aiter__(self):
        try:
            async for chunk in self.response.aiter_stream():
                yield chunk
        except httpcore.TimeoutException as exc:
            raise httpx.ReadTimeout("Target response timed out.") from exc
        except (httpcore.NetworkError, httpcore.ProtocolError) as exc:
            raise httpx.ReadError("Target response failed.") from exc

    async def aclose(self) -> None:
        await self.response.aclose()


class PinnedHTTPTransport(httpx.AsyncBaseTransport):
    def __init__(self, target: Target) -> None:
        self.target = target
        self.pool = httpcore.AsyncConnectionPool(
            network_backend=PinnedNetworkBackend(target),
            max_connections=target.concurrency,
            max_keepalive_connections=target.concurrency,
        )

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        validate_target_url(str(request.url), self.target)
        try:
            response = await self.pool.handle_async_request(
                httpcore.Request(
                    method=request.method,
                    url=httpcore.URL(
                        scheme=request.url.raw_scheme,
                        host=request.url.raw_host,
                        port=request.url.port,
                        target=request.url.raw_path,
                    ),
                    headers=request.headers.raw,
                    content=request.stream,
                    extensions=request.extensions,
                )
            )
        except httpcore.TimeoutException as exc:
            raise httpx.ConnectTimeout("Target connection timed out.", request=request) from exc
        except (httpcore.NetworkError, httpcore.ProtocolError) as exc:
            raise httpx.ConnectError("Target connection failed.", request=request) from exc
        return httpx.Response(
            response.status,
            headers=response.headers,
            stream=_ResponseStream(response),
            extensions=response.extensions,
        )

    async def aclose(self) -> None:
        await self.pool.aclose()


def validate_enrolled_url(url: str, allowed_hosts: list[str] | None) -> None:
    if allowed_hosts is None:
        return
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https", "ws", "wss"} or not parsed.hostname:
        raise ValueError("Only network URLs with enrolled hosts are permitted")
    if parsed.username or parsed.password:
        raise ValueError("Credentials in target URLs are not permitted")
    host = parsed.hostname.rstrip(".").encode("idna").decode("ascii").lower()
    enrolled = {
        value.strip().rstrip(".").encode("idna").decode("ascii").lower() for value in allowed_hosts
    }
    if host not in enrolled:
        raise ValueError("Target or redirect host is not enrolled")


async def enrolled_request(
    client: httpx.AsyncClient,
    target: Target,
    method: str,
    url: str,
    body: dict,
    *,
    count_target: bool = True,
) -> httpx.Response:
    validate_target_url(url, target)
    request = client.build_request(method, url, json=body)
    for _ in range(11):
        validate_target_url(str(request.url), target)
        from agentscan.core.client import consume_target_request

        if count_target:
            consume_target_request()
        response = await client.send(request, follow_redirects=False, stream=True)
        next_request = response.next_request
        if next_request is not None and target.factuality_baseline is not None:
            await response.aclose()
            raise ValueError("Approved-answer endpoint redirects are not permitted.")
        if next_request is None:
            try:
                if (
                    target.allowed_networks is not None
                    and response.headers.get("content-encoding", "identity") != "identity"
                ):
                    raise httpx.ReadError(
                        "Compressed target responses are not accepted by the service.",
                        request=request,
                    )
                chunks: list[bytes] = []
                size = 0
                async for chunk in response.aiter_bytes(chunk_size=65536):
                    size += len(chunk)
                    if size > target.max_response_bytes:
                        raise httpx.ReadError(
                            "Target response exceeds the configured size limit.", request=request
                        )
                    chunks.append(chunk)
                # Bytes are already decoded; avoid decoding compressed content twice.
                headers = response.headers.copy()
                headers.pop("content-encoding", None)
                headers.pop("content-length", None)
                return httpx.Response(
                    response.status_code,
                    headers=headers,
                    content=b"".join(chunks),
                    request=request,
                    extensions=response.extensions,
                )
            finally:
                await response.aclose()
        await response.aclose()
        if canonical_origin(str(request.url)) != canonical_origin(str(next_request.url)):
            sensitive = ["authorization", "cookie", "x-api-key", *target.extra_headers]
            if target.auth_header and ":" in target.auth_header:
                sensitive.append(target.auth_header.partition(":")[0].strip())
            for header in sensitive:
                next_request.headers.pop(header, None)
        request = next_request
    raise httpx.TooManyRedirects("Too many target redirects", request=request)
