# agentscan/core/connectors/browser.py
#
# Playwright-based browser connector for chat widgets with no exposed HTTP APIs.

from __future__ import annotations

import contextlib
import time
from typing import Any

from loguru import logger

from agentscan.core.connectors.base import Connector, flatten_conversation
from agentscan.core.context import ContextLocal
from agentscan.core.models import Target


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


_session = ContextLocal("browser", _BrowserSession)


async def _launch_page(cfg: Any) -> tuple[Any, Any, Any]:
    """Launch Chromium, open the widget page, and (optionally) click the launcher."""
    from playwright.async_api import async_playwright

    pw = await async_playwright().start()
    browser = None
    try:
        browser = await pw.chromium.launch(headless=cfg.headless)
        page = await browser.new_page()
        await page.goto(cfg.url, wait_until="domcontentloaded")
        if cfg.open_selector:
            await page.click(cfg.open_selector, timeout=10000)
            await page.wait_for_selector(cfg.input_selector, timeout=10000)
        return pw, browser, page
    except BaseException:
        if browser is not None:
            with contextlib.suppress(Exception):
                await browser.close()
        with contextlib.suppress(Exception):
            await pw.stop()
        raise


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
            deadline = time.monotonic() + self.cfg.timeout
            await page.wait_for_function(
                "([s, n]) => document.querySelectorAll(s).length > n",
                arg=[sel, before],
                timeout=self.cfg.timeout * 1000,
            )
            if self.cfg.completion_selector:
                await page.wait_for_function(
                    "([s,c]) => { const rows=document.querySelectorAll(s); const r=rows[rows.length-1]; return !!r && (r.matches(c)||!!r.querySelector(c)); }",
                    arg=[sel, self.cfg.completion_selector],
                    timeout=max(1, int((deadline - time.monotonic()) * 1000)),
                )
            else:
                if not self.cfg.allow_unverified_completion:
                    raise RuntimeError(
                        "Browser completion is unverified; configure completion_selector or explicitly opt into heuristic completion"
                    )
                # A quiet interval is an explicit heuristic, never evidence of
                # protocol completion. Reset the interval whenever text changes.
                previous = await page.locator(sel).last.inner_text()
                stable_since = time.monotonic()
                while True:
                    now = time.monotonic()
                    if now >= deadline:
                        raise TimeoutError("Browser response did not stabilize before timeout")
                    await page.wait_for_timeout(50)
                    current = await page.locator(sel).last.inner_text()
                    if current != previous:
                        previous, stable_since = current, time.monotonic()
                    if (time.monotonic() - stable_since) * 1000 >= self.cfg.settle_ms:
                        break
            text = await page.locator(sel).last.inner_text()
            return {
                "response": text,
                "completion_verified": self.cfg.completion_selector is not None,
            }
        except Exception as e:  # noqa: BLE001 - surface as a normalised error dict
            logger.error(f"Browser interaction failed: {e}")
            return {"error": str(e), "status_code": 0}

    async def send_conversation(self, messages: list[dict[str, str]]) -> dict[str, Any]:
        return await self.send_message(flatten_conversation(messages))
