# agentscan/core/connectors.py
#
# Transport connectors — how AgentScan actually reaches a target agent.
#
# Every attack module talks to a target through a Connector (via AgentScanClient,
# which selects one). Modules only ever call send_message() / send_conversation(),
# so the SAME modules (SCAN, EXPLOIT, DEEP) work over ANY transport without change:
#
#   HttpJsonConnector        — the default: POST {"message": ...} to a documented endpoint.
#   RequestTemplateConnector — replay a captured request (cURL/HAR) with the payload
#                              substituted into one field. This is what lets AgentScan
#                              hit the undocumented internal APIs behind real website chat
#                              widgets behind undocumented / streaming / UI-only front-ends.

from __future__ import annotations

import asyncio
import contextlib
import copy
import json
from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import Any

import httpx
from loguru import logger

from agentscan.core.models import Target

# ── Retry configuration (shared) ──────────────────────────────────────────────

DEFAULT_RETRIES = 2
RETRY_BACKOFF_SECONDS = 1.0  # doubles on each retry: 1s, 2s
RETRY_ON_STATUS = {429, 502, 503, 504}


# ── Dotted-path helpers (for JSON request/response templating) ────────────────


def set_by_path(obj: Any, path: str, value: Any) -> None:
    """
    Set a value inside a nested dict/list using a dotted path.
    Supports list indices (including negative): "messages.-1.content".
    """
    keys = path.split(".")
    cur = obj
    for k in keys[:-1]:
        cur = cur[int(k)] if isinstance(cur, list) else cur[k]
    last = keys[-1]
    if isinstance(cur, list):
        cur[int(last)] = value
    else:
        cur[last] = value


def get_by_path(obj: Any, path: str) -> Any:
    """Read a value from a nested dict/list by dotted path, or None if absent."""
    cur = obj
    try:
        for k in path.split("."):
            cur = cur[int(k)] if isinstance(cur, list) else cur[k]
    except (KeyError, IndexError, TypeError, ValueError):
        return None
    return cur


def flatten_conversation(messages: list[dict[str, str]]) -> str:
    """
    Render a multi-turn history into a single prompt string.

    Needed because most real agent endpoints are single-message and stateless
    (they take {"message": ...} with no server-side memory), so the only way to
    convey prior turns is to inline them into one message.
    """
    return "\n".join(f"[{m.get('role', 'user')}]: {m.get('content', '')}" for m in messages)


# ── SSE / streaming response parsing ──────────────────────────────────────────

_SSE_TEXT_KEYS = ("content", "text", "delta", "token", "reply", "message", "response")


def parse_sse(text: str) -> str:
    """
    Reassemble the full reply from a Server-Sent Events stream.

    Handles the common chat shape `data: {"content": "...", "done": false}` by
    concatenating the text field of each chunk; ignores `[DONE]` sentinels.
    """
    parts: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line.startswith("data:"):
            continue
        data = line[len("data:") :].strip()
        if not data or data == "[DONE]":
            continue
        try:
            obj = json.loads(data)
        except json.JSONDecodeError:
            parts.append(data)
            continue
        if isinstance(obj, str):
            parts.append(obj)
        elif isinstance(obj, dict):
            for k in _SSE_TEXT_KEYS:
                v = obj.get(k)
                if isinstance(v, str):
                    parts.append(v)
                    break
    return "".join(parts)


def parse_response(response: httpx.Response) -> dict[str, Any]:
    """
    Turn an httpx response into a dict the attack modules can read.

    - text/event-stream (or a body that looks like SSE) → reassemble the stream
      and expose it under "response" so streamed bots aren't false-negatives.
    - JSON → return as-is.
    - anything else → {"raw": <text>}.
    """
    ctype = response.headers.get("content-type", "")
    text = response.text
    if "text/event-stream" in ctype or text.lstrip().startswith("data:"):
        return {"response": parse_sse(text), "raw": text}
    try:
        return response.json()
    except Exception:
        return {"raw": text, "status_code": response.status_code}


# ── Connector interface ───────────────────────────────────────────────────────


class Connector(ABC):
    """
    Transport contract every connector implements. Attack modules depend only on
    this surface, so swapping the transport never touches a module.
    """

    async def __aenter__(self) -> Connector:
        return self

    async def __aexit__(self, *exc: Any) -> None:
        return None

    @abstractmethod
    async def send_message(
        self, message: str, extra_body: dict[str, Any] | None = None
    ) -> dict[str, Any]: ...

    @abstractmethod
    async def send_conversation(self, messages: list[dict[str, str]]) -> dict[str, Any]: ...


# ── HTTP JSON connector (default — unchanged behaviour) ───────────────────────


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
        )
        return self

    async def __aexit__(self, *exc: Any) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    def _build_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {
            "Content-Type": "application/json",
            "User-Agent": "AgentScan/0.1.0 (security-scanner)",
        }
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

        for attempt in range(DEFAULT_RETRIES + 1):
            try:
                response = await self._client.post(url, json=body)
                if response.status_code in RETRY_ON_STATUS and attempt < DEFAULT_RETRIES:
                    wait = RETRY_BACKOFF_SECONDS * (2**attempt)
                    logger.warning(
                        f"HTTP {response.status_code} from {url}. "
                        f"Retrying in {wait}s (attempt {attempt + 1}/{DEFAULT_RETRIES})"
                    )
                    await asyncio.sleep(wait)
                    continue
                return parse_response(response)
            except httpx.TimeoutException as e:
                last_error = e
                if attempt < DEFAULT_RETRIES:
                    wait = RETRY_BACKOFF_SECONDS * (2**attempt)
                    logger.warning(
                        f"Timeout hitting {url}. "
                        f"Retrying in {wait}s (attempt {attempt + 1}/{DEFAULT_RETRIES})"
                    )
                    await asyncio.sleep(wait)
            except httpx.ConnectError as e:
                logger.error(f"Cannot connect to {url}: {e}")
                return {"error": f"Connection failed: {e}", "status_code": 0}
            except Exception as e:
                last_error = e
                logger.error(f"Unexpected error hitting {url}: {e}")
                break

        logger.error(
            f"All {DEFAULT_RETRIES + 1} attempts failed for {url}. Last error: {last_error}"
        )
        return {"error": str(last_error), "status_code": 0}


# ── Request-template connector (captured cURL/HAR) ────────────────────────────


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
            headers={**self.template.headers, **self.target.extra_headers},
            follow_redirects=True,
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

        for attempt in range(DEFAULT_RETRIES + 1):
            try:
                response = await self._client.request(
                    self.template.method.upper(), self.template.url, json=body
                )
                if response.status_code in RETRY_ON_STATUS and attempt < DEFAULT_RETRIES:
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
                if attempt < DEFAULT_RETRIES:
                    await asyncio.sleep(RETRY_BACKOFF_SECONDS * (2**attempt))
            except httpx.ConnectError as e:
                logger.error(f"Cannot connect to {self.template.url}: {e}")
                return {"error": f"Connection failed: {e}", "status_code": 0}
            except Exception as e:
                last_error = e
                logger.error(f"Unexpected error hitting {self.template.url}: {e}")
                break

        return {"error": str(last_error), "status_code": 0}


# ── Browser connector (Playwright — drives a real chat widget) ────────────────


class _BrowserSession:
    """
    A scan-scoped shared browser. Opened once per scan by the runner and reused by
    every module's BrowserConnector — so a --exploit scan launches ONE Chromium,
    not one per module. Module-level singleton (one scan per process).
    """

    def __init__(self) -> None:
        self.pw: Any = None
        self.browser: Any = None
        self.page: Any = None

    @property
    def active(self) -> bool:
        return self.page is not None


_session = _BrowserSession()


async def _launch_page(cfg: Any) -> tuple[Any, Any, Any]:
    """Launch Chromium, open the widget page, and (optionally) click the launcher."""
    from playwright.async_api import async_playwright

    pw = await async_playwright().start()
    browser = await pw.chromium.launch(headless=cfg.headless)
    page = await browser.new_page()
    await page.goto(cfg.url, wait_until="domcontentloaded")
    if cfg.open_selector:
        with contextlib.suppress(Exception):
            await page.click(cfg.open_selector, timeout=10000)
            await page.wait_for_selector(cfg.input_selector, timeout=10000)
    return pw, browser, page


def browser_session_active() -> bool:
    return _session.active


async def open_browser_session(cfg: Any) -> None:
    """Open the one shared browser for a scan (no-op if already open)."""
    if _session.active:
        return
    _session.pw, _session.browser, _session.page = await _launch_page(cfg)


async def close_browser_session() -> None:
    """Close the shared browser at scan end."""
    try:
        if _session.browser is not None:
            await _session.browser.close()
    finally:
        if _session.pw is not None:
            await _session.pw.stop()
    _session.pw = _session.browser = _session.page = None


class BrowserConnector(Connector):
    """
    Drives a chat WIDGET in a real browser for agents with no capturable HTTP API.
    Types the payload into the input, submits, waits for a new bot bubble, and reads
    it — so cookies, CSRF, and streaming all "just work" because it's a real browser.

    Requires Playwright (`pip install playwright` + `playwright install chromium`).
    """

    def __init__(self, target: Target) -> None:
        if target.browser is None:
            raise ValueError("BrowserConnector requires target.browser")
        self.target = target
        self.cfg = target.browser
        self._pw: Any = None
        self._browser: Any = None
        self._page: Any = None
        self._owns = False  # True only when we launched our own browser (standalone use)

    async def __aenter__(self) -> BrowserConnector:
        # Reuse the scan's shared browser if one is open (the common path — one
        # Chromium for the whole scan). Otherwise launch our own (standalone use).
        if _session.active:
            self._page = _session.page
            self._owns = False
        else:
            self._pw, self._browser, self._page = await _launch_page(self.cfg)
            self._owns = True
        return self

    async def __aexit__(self, *exc: Any) -> None:
        if not self._owns:
            self._page = None  # shared browser stays open for the next module
            return
        try:
            if self._browser is not None:
                await self._browser.close()
        finally:
            if self._pw is not None:
                await self._pw.stop()
        self._page = self._browser = self._pw = None

    async def send_message(
        self, message: str, extra_body: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        page = self._page
        if page is None:
            raise RuntimeError(
                "Client not initialised. Use 'async with AgentScanClient(target) as client:'"
            )
        sel = self.cfg.response_selector
        try:
            before = await page.locator(sel).count()
            await page.fill(self.cfg.input_selector, message)
            submitted = False
            if self.cfg.send_selector:
                try:
                    # Short timeout — if an overlay (e.g. a floating WhatsApp button)
                    # intercepts the click, fail fast and fall back to Enter.
                    await page.click(self.cfg.send_selector, timeout=5000)
                    submitted = True
                except Exception:
                    submitted = False
            if not submitted:
                await page.press(self.cfg.input_selector, "Enter")
            # Wait for a new bot bubble to appear, then let streaming settle.
            with contextlib.suppress(Exception):
                await page.wait_for_function(
                    "([s, n]) => document.querySelectorAll(s).length > n",
                    arg=[sel, before],
                    timeout=self.cfg.timeout * 1000,
                )
            await page.wait_for_timeout(self.cfg.settle_ms)
            text = await page.locator(sel).last.inner_text()
            return {"response": text}
        except Exception as e:  # noqa: BLE001 - surface as a normalised error dict
            logger.error(f"Browser interaction failed: {e}")
            return {"error": str(e), "status_code": 0}

    async def send_conversation(self, messages: list[dict[str, str]]) -> dict[str, Any]:
        return await self.send_message(flatten_conversation(messages))


# ── In-process connector (benchmarks / tests — no network) ────────────────────


class CallableConnector(Connector):
    """Talks to an in-process agent function `(message) -> reply`. No network."""

    def __init__(self, agent: Callable[[str], str]) -> None:
        self._agent = agent

    async def send_message(
        self, message: str, extra_body: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        return {"response": self._agent(message)}

    async def send_conversation(self, messages: list[dict[str, str]]) -> dict[str, Any]:
        return await self.send_message(flatten_conversation(messages))


# A scoped override so a whole scan can be routed to an in-process agent (used by
# the benchmark). Set via use_connector(); select_connector() honours it.
_forced_connector: Connector | None = None


@contextlib.contextmanager
def use_connector(connector: Connector) -> Any:
    """Force every connector for the duration of the block (benchmark/testing)."""
    global _forced_connector
    previous = _forced_connector
    _forced_connector = connector
    try:
        yield
    finally:
        _forced_connector = previous


def select_connector(target: Target) -> Connector:
    """
    Pick the transport for a target:
    forced override → browser widget → captured request → default HTTP JSON.
    """
    if _forced_connector is not None:
        return _forced_connector
    if target.browser is not None:
        return BrowserConnector(target)
    if target.request_template is not None:
        return RequestTemplateConnector(target)
    return HttpJsonConnector(target)
