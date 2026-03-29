# agentscan/core/client.py
#
# The single HTTP client for all attack modules.
# Every module that fires HTTP requests uses this — never raw httpx directly.
#
# Features:
# - Async (non-blocking) — scans 30 attacks concurrently, not sequentially
# - Automatic retry with exponential backoff
# - Configurable timeout
# - Auth header injection
# - Session reuse (one connection pool per scan)

from __future__ import annotations

import asyncio
from typing import Any

import httpx
from loguru import logger

from agentscan.core.models import Target

# ── Retry configuration ───────────────────────────────────────────────────────

DEFAULT_RETRIES = 2
RETRY_BACKOFF_SECONDS = 1.0  # doubles on each retry: 1s, 2s
RETRY_ON_STATUS = {429, 502, 503, 504}  # retry on these HTTP status codes


# ── Client ────────────────────────────────────────────────────────────────────


class AgentScanClient:
    """
    Async HTTP client for firing attack payloads at LLM endpoints.

    Usage (inside an attack module):
        async with AgentScanClient(target) as client:
            response = await client.send_message("your payload here")
            text = response.get("text", "")

    The context manager handles session creation and cleanup.
    You never need to call .close() manually.
    """

    def __init__(self, target: Target) -> None:
        self.target = target
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> AgentScanClient:
        headers = self._build_headers()
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.target.timeout),
            headers=headers,
            follow_redirects=True,
        )
        return self

    async def __aexit__(self, *_: Any) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    def _build_headers(self) -> dict[str, str]:
        """Build the headers dict from the target configuration."""
        headers: dict[str, str] = {
            "Content-Type": "application/json",
            "User-Agent": "AgentScan/0.1.0 (security-scanner)",
        }

        # Inject auth header if provided
        if self.target.auth_header:
            # auth_header can be "Bearer sk-..." or "Authorization: Bearer sk-..."
            if ":" in self.target.auth_header:
                key, _, value = self.target.auth_header.partition(":")
                headers[key.strip()] = value.strip()
            else:
                headers["Authorization"] = self.target.auth_header

        # Add any extra headers from target config
        headers.update(self.target.extra_headers)

        return headers

    async def send_message(
        self,
        message: str,
        extra_body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Send a single message to the target agent endpoint.

        Args:
            message:    The user message / attack payload to send.
            extra_body: Additional JSON fields to merge into the request body.

        Returns:
            The parsed JSON response from the agent as a dict.
            Always returns a dict — never raises on HTTP errors (logs instead).

        This is the method every attack module calls.
        """
        if self._client is None:
            raise RuntimeError(
                "Client not initialised. Use 'async with AgentScanClient(target) as client:'"
            )

        body: dict[str, Any] = {"message": message}
        if extra_body:
            body.update(extra_body)

        return await self._post_with_retry(body)

    async def send_conversation(
        self,
        messages: list[dict[str, str]],
    ) -> dict[str, Any]:
        """
        Send a multi-turn conversation history to the agent.
        Used by crescendo and multi-turn attack modules.

        Args:
            messages: List of {"role": "user"|"assistant", "content": "..."}

        Returns:
            The parsed JSON response.
        """
        if self._client is None:
            raise RuntimeError("Client not initialised.")

        body: dict[str, Any] = {"messages": messages}
        return await self._post_with_retry(body)

    async def _post_with_retry(
        self,
        body: dict[str, Any],
    ) -> dict[str, Any]:
        """
        POST to target.url with automatic retry on transient errors.

        Retry logic:
        - Retries on network errors (connection refused, timeout)
        - Retries on specific HTTP status codes (429, 502, 503, 504)
        - Exponential backoff: waits RETRY_BACKOFF_SECONDS * 2^attempt
        - Does NOT retry on 4xx client errors (400, 401, 403, 404)
        """
        assert self._client is not None

        last_error: Exception | None = None

        for attempt in range(DEFAULT_RETRIES + 1):
            try:
                response = await self._client.post(
                    self.target.url,
                    json=body,
                )

                # Retry on specific server-side status codes
                if response.status_code in RETRY_ON_STATUS and attempt < DEFAULT_RETRIES:
                    wait = RETRY_BACKOFF_SECONDS * (2**attempt)
                    logger.warning(
                        f"HTTP {response.status_code} from {self.target.url}. "
                        f"Retrying in {wait}s (attempt {attempt + 1}/{DEFAULT_RETRIES})"
                    )
                    await asyncio.sleep(wait)
                    continue

                # Parse JSON — return empty dict if body is not JSON
                try:
                    return response.json()
                except Exception:
                    return {
                        "raw": response.text,
                        "status_code": response.status_code,
                    }

            except httpx.TimeoutException as e:
                last_error = e
                if attempt < DEFAULT_RETRIES:
                    wait = RETRY_BACKOFF_SECONDS * (2**attempt)
                    logger.warning(
                        f"Timeout hitting {self.target.url}. "
                        f"Retrying in {wait}s (attempt {attempt + 1}/{DEFAULT_RETRIES})"
                    )
                    await asyncio.sleep(wait)

            except httpx.ConnectError as e:
                # Don't retry connection errors — target is unreachable
                logger.error(f"Cannot connect to {self.target.url}: {e}")
                return {"error": f"Connection failed: {e}", "status_code": 0}

            except Exception as e:
                last_error = e
                logger.error(f"Unexpected error hitting {self.target.url}: {e}")
                break

        logger.error(
            f"All {DEFAULT_RETRIES + 1} attempts failed for {self.target.url}. "
            f"Last error: {last_error}"
        )
        return {"error": str(last_error), "status_code": 0}
