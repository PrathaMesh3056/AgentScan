# agentscan/core/connectors/http.py
#
# HTTP JSON and RequestTemplate connectors for REST/JSON agent endpoints.

from __future__ import annotations

import asyncio
import copy
import hashlib
from typing import Any

import httpx
from loguru import logger

from agentscan.core.connectors.base import (
    DEFAULT_RETRIES,
    RETRY_BACKOFF_SECONDS,
    RETRY_ON_STATUS,
    Connector,
    flatten_conversation,
    get_by_path,
    parse_response,
    set_by_path,
)
from agentscan.core.egress import PinnedHTTPTransport, enrolled_request
from agentscan.core.models import Target, _installed_version


class HttpJsonConnector(Connector):
    """
    Default connector: POST a JSON body to target.url. Backwards-compatible with
    the original AgentScanClient — same headers, retry, and response handling.
    """

    def __init__(self, target: Target) -> None:
        self.target = target
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> HttpJsonConnector:
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.target.timeout),
            headers=self._build_headers(),
            follow_redirects=True,
            trust_env=self.target.allowed_networks is None,
            transport=PinnedHTTPTransport(self.target)
            if self.target.allowed_networks is not None
            else None,
        )
        return self

    async def __aexit__(self, *exc: Any) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    def _build_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {
            "Content-Type": "application/json",
            "User-Agent": f"AgentScan/{_installed_version()} (security-scanner)",
        }
        if self.target.allowed_networks is not None:
            headers["Accept-Encoding"] = "identity"
        if self.target.auth_header:
            if ":" in self.target.auth_header:
                key, _, value = self.target.auth_header.partition(":")
                headers[key.strip()] = value.strip()
            else:
                headers["Authorization"] = self.target.auth_header
        headers.update(self.target.extra_headers)
        return headers

    async def send_message(
        self, message: str, extra_body: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        if self._client is None:
            raise RuntimeError(
                "Client not initialised. Use 'async with AgentScanClient(target) as client:'"
            )
        body: dict[str, Any] = {"message": message}
        if extra_body:
            body.update(extra_body)
        return await self._post_with_retry(self.target.url, body)

    send_prompt = send_message

    @property
    def supports_indirect_document(self) -> bool:
        return self.target.indirect_adapter == "document_v1"

    async def send_indirect_document(
        self, task: str, document: str, probe_id: str, source_id: str
    ) -> dict[str, Any]:
        """Send separate data to an explicitly enrolled target-side document adapter."""
        if not self.supports_indirect_document:
            return await super().send_indirect_document(task, document, probe_id, source_id)
        return await self.send_message(
            task,
            {
                "indirect_probe": {
                    "protocol": "agentscan.document.v1",
                    "probe_id": probe_id,
                    "source_id": source_id,
                    "source_sha256": hashlib.sha256(document.encode("utf-8")).hexdigest(),
                    "content": document,
                }
            },
        )

    async def send_conversation(self, messages: list[dict[str, str]]) -> dict[str, Any]:
        if self._client is None:
            raise RuntimeError("Client not initialised.")
        # Send BOTH shapes: single-message APIs read "message" (a flattened history),
        # OpenAI-style APIs read "messages". Each ignores the field it doesn't use —
        # so multi-turn attacks land on stateless/single-message endpoints too.
        body = {"message": flatten_conversation(messages), "messages": messages}
        return await self._post_with_retry(self.target.url, body)

    async def _post_with_retry(self, url: str, body: dict[str, Any]) -> dict[str, Any]:
        assert self._client is not None
        last_error: Exception | None = None
        retries = DEFAULT_RETRIES if self.target.retry_state_changing_requests else 0
        for attempt in range(retries + 1):
            try:
                response = await enrolled_request(self._client, self.target, "POST", url, body)
                if response.status_code in RETRY_ON_STATUS and attempt < retries:
                    wait = RETRY_BACKOFF_SECONDS * (2**attempt)
                    logger.warning(
                        f"HTTP {response.status_code} from target. "
                        f"Retrying in {wait}s (attempt {attempt + 1}/{DEFAULT_RETRIES})"
                    )
                    await asyncio.sleep(wait)
                    continue
                return parse_response(response)
            except httpx.TimeoutException as e:
                last_error = e
                if attempt < retries:
                    wait = RETRY_BACKOFF_SECONDS * (2**attempt)
                    logger.warning(
                        f"Target request timed out. "
                        f"Retrying in {wait}s (attempt {attempt + 1}/{DEFAULT_RETRIES})"
                    )
                    await asyncio.sleep(wait)
            except httpx.ConnectError as e:
                logger.error("Target connection failed: {}", type(e).__name__)
                return {"error": "Connection failed.", "status_code": 0}
            except Exception as e:
                last_error = e
                logger.error("Target request failed: {}", type(e).__name__)
                break

        logger.error(
            "Target request failed after {} attempt(s): {}", retries + 1, type(last_error).__name__
        )
        reason = (
            str(last_error)
            if isinstance(last_error, ValueError)
            else f"Target request failed: {type(last_error).__name__}"
        )
        return {"error": reason, "status_code": 0}


class RequestTemplateConnector(Connector):
    """
    Replays a captured request (from target.request_template), substituting the
    attack payload into the configured message field, and normalises the reply
    into {"response": <text>} so every existing attack module reads it unchanged.
    """

    def __init__(self, target: Target) -> None:
        if target.request_template is None:
            raise ValueError("RequestTemplateConnector requires target.request_template")
        self.target = target
        self.template = target.request_template
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> RequestTemplateConnector:
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.template.timeout),
            headers={
                **self.template.headers,
                **self.target.extra_headers,
                **(
                    {"Accept-Encoding": "identity"}
                    if self.target.allowed_networks is not None
                    else {}
                ),
            },
            follow_redirects=True,
            trust_env=self.target.allowed_networks is None,
            transport=PinnedHTTPTransport(self.target)
            if self.target.allowed_networks is not None
            else None,
        )
        return self

    async def __aexit__(self, *exc: Any) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    async def send_message(
        self, message: str, extra_body: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        if self._client is None:
            raise RuntimeError(
                "Client not initialised. Use 'async with AgentScanClient(target) as client:'"
            )
        body = copy.deepcopy(self.template.json_body)
        set_by_path(body, self.template.message_path, message)
        if extra_body:
            body.update(extra_body)
        raw = await self._send(body)
        return self._normalise(raw)

    async def send_conversation(self, messages: list[dict[str, str]]) -> dict[str, Any]:
        # A single captured request can't express multi-turn history natively, so
        # inline the whole conversation into the one message field.
        return await self.send_message(flatten_conversation(messages))

    def _normalise(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Lift the reply text to the top-level 'response' key modules expect."""
        if self.template.response_path:
            extracted = get_by_path(raw, self.template.response_path)
            if extracted is not None:
                return {"response": str(extracted), "raw": raw}
        return raw

    async def _send(self, body: dict[str, Any]) -> dict[str, Any]:
        assert self._client is not None
        last_error: Exception | None = None
        retries = (
            DEFAULT_RETRIES
            if self.template.method.upper() in {"GET", "HEAD", "OPTIONS"}
            or self.target.retry_state_changing_requests
            else 0
        )
        for attempt in range(retries + 1):
            try:
                response = await enrolled_request(
                    self._client, self.target, self.template.method.upper(), self.template.url, body
                )
                if response.status_code in RETRY_ON_STATUS and attempt < retries:
                    wait = RETRY_BACKOFF_SECONDS * (2**attempt)
                    logger.warning(
                        f"HTTP {response.status_code} from {self.template.url}. "
                        f"Retrying in {wait}s (attempt {attempt + 1}/{DEFAULT_RETRIES})"
                    )
                    await asyncio.sleep(wait)
                    continue
                return parse_response(response)
            except httpx.TimeoutException as e:
                last_error = e
                if attempt < retries:
                    await asyncio.sleep(RETRY_BACKOFF_SECONDS * (2**attempt))
            except httpx.ConnectError as e:
                logger.error("Target connection failed: {}", type(e).__name__)
                return {"error": "Connection failed.", "status_code": 0}
            except Exception as e:
                last_error = e
                logger.error("Target request failed: {}", type(e).__name__)
                break

        return {"error": f"Target request failed: {type(last_error).__name__}", "status_code": 0}
