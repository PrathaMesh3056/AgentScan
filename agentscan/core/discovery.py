# agentscan/core/discovery.py
#
# Auto-discovery of a chat widget's selectors, so users don't hand-pick CSS.
# `agentscan init <url>` drives a headless browser, finds the launcher / input /
# send button / reply bubbles heuristically, sends one benign test message to
# locate the reply element, and returns a BrowserConfig.
#
# Best-effort: it prints what it found so the user can confirm or tweak.

from __future__ import annotations

from typing import Any

from loguru import logger

from agentscan.core.models import BrowserConfig

# A selector generator injected into the page. Prefers id, then a stable
# placeholder/aria-label, then the lowest-match-count "clean" class (Tailwind
# utility classes with :,/,[,] are skipped — they don't make robust selectors).
_INJECT_ASCSS = r"""
() => {
  const clean = c => c && !/[:\/\[\]\\%().#!]/.test(c) && !/^[0-9]/.test(c);
  window.__ascss = function(el) {
    if (!el) return null;
    if (el.id && clean(el.id) && document.querySelectorAll('#' + el.id).length === 1) return '#' + el.id;
    if ((el.tagName === 'INPUT' || el.tagName === 'TEXTAREA') && el.placeholder) {
      const ph = el.placeholder.slice(0, 22).replace(/"/g, '');
      const sel = el.tagName.toLowerCase() + '[placeholder^="' + ph + '"]';
      if (document.querySelectorAll(sel).length === 1) return sel;
    }
    const al = el.getAttribute && el.getAttribute('aria-label');
    if (al) { const sel = el.tagName.toLowerCase() + '[aria-label="' + al.replace(/"/g, '') + '"]';
      if (document.querySelectorAll(sel).length <= 3) return sel; }
    const classes = [...(el.classList || [])].filter(clean);
    let best = null, bestCount = 1e9;
    for (const c of classes) { const n = document.querySelectorAll('.' + c).length;
      if (n >= 1 && n < bestCount) { best = '.' + c; bestCount = n; } }
    if (best && bestCount > 12) {
      const candClasses = classes.slice(0, 4);
      for (let i = 0; i < candClasses.length; i++) for (let j = i + 1; j < candClasses.length; j++) {
        const sel = '.' + candClasses[i] + '.' + candClasses[j]; const n = document.querySelectorAll(sel).length;
        if (n >= 1 && n < bestCount) { best = sel; bestCount = n; } } }
    // Scope to a parent class if still broad, to bias toward the newest bubble.
    if (best && bestCount > 12 && el.parentElement) {
      const pcs = [...(el.parentElement.classList || [])].filter(clean).slice(0, 3);
      for (const pc of pcs) { const sel = '.' + pc + ' ' + best; const n = document.querySelectorAll(sel).length;
        if (n >= 1 && n < bestCount) { best = sel; bestCount = n; } }
    }
    return best;
  };
  return true;
}
"""

_FIND_INPUT = r"""
() => {
  const kw = /ask|message|chat|type|help|question|reply|talk|say/i;
  const bad = /name|email|company|phone|subject|project|search|coupon|address/i;
  const cands = [...document.querySelectorAll('input, textarea')].filter(e => {
    const r = e.getBoundingClientRect();
    const st = getComputedStyle(e);
    const vis = r.width > 40 && r.height > 0 && st.visibility !== 'hidden' && st.display !== 'none' && !e.disabled;
    return vis && (e.tagName === 'TEXTAREA' || !e.type || e.type === 'text' || e.type === 'search');
  });
  const scored = cands.map(e => {
    let s = 0;
    const ph = (e.placeholder || '') + ' ' + (e.getAttribute('aria-label') || '');
    if (kw.test(ph)) s += 5;
    if (bad.test(ph + ' ' + (e.id || '') + ' ' + (e.name || ''))) s -= 6;
    let p = e, z = 0, fixed = false;
    for (let i = 0; i < 10 && p; i++) { const st = getComputedStyle(p);
      if (st.position === 'fixed') { fixed = true; z = Math.max(z, parseInt(st.zIndex) || 0); } p = p.parentElement; }
    if (fixed) s += 3; if (z >= 20) s += 1;
    return { e, s };
  }).filter(x => x.s > 0).sort((a, b) => b.s - a.s);
  return scored.length ? window.__ascss(scored[0].e) : null;
}
"""

_FIND_LAUNCHERS = r"""
() => {
  const out = [];
  for (const b of document.querySelectorAll('button')) {
    const st = getComputedStyle(b); const r = b.getBoundingClientRect();
    if (st.position !== 'fixed') continue;
    if (r.width > 96 || r.height > 96 || r.width < 24 || r.height < 24) continue;
    const nearRight = r.right > window.innerWidth - 180;
    const nearBottom = r.bottom > window.innerHeight - 220;
    if (!(nearRight && nearBottom)) continue;
    out.push({ sel: window.__ascss(b), z: parseInt(st.zIndex) || 0 });
  }
  return out.sort((a, b) => b.z - a.z).map(x => x.sel).filter(Boolean);
}
"""


_FIND_SEND = r"""
    (inputSel) => {
      const inp = document.querySelector(inputSel);
      if (!inp) return null;
      // Search the input's form / nearby containers for a send button.
      let scope = inp.closest('form') || inp.parentElement;
      for (let i = 0; i < 3 && scope && scope.parentElement; i++) scope = scope.parentElement;
      const btns = [...(scope ? scope.querySelectorAll('button') : [])];
      const score = b => {
        let s = 0; const al = (b.getAttribute('aria-label') || '') + ' ' + (b.title || '') + ' ' + (b.innerText || '');
        if (/send|submit/i.test(al)) s += 5;
        if (b.type === 'submit') s += 2;
        if (b.querySelector('svg')) s += 1;
        return s;
      };
      const ranked = btns.map(b => ({ b, s: score(b) })).filter(x => x.s > 0).sort((a, b) => b.s - a.s);
      return ranked.length ? window.__ascss(ranked[0].b) : null;
    }
"""


# ── HTTP API discovery (no browser) ───────────────────────────────────────────

_PROBE = "AgentScan probe: please say hello"

# Request body shapes to try, most common first. (message_path, body-builder).
_HTTP_SHAPES: list[tuple[str, Any]] = [
    ("message", lambda m: {"message": m}),
    ("query", lambda m: {"query": m}),
    ("prompt", lambda m: {"prompt": m}),
    ("text", lambda m: {"text": m}),
    ("input", lambda m: {"input": m}),
    ("messages.-1.content", lambda m: {"messages": [{"role": "user", "content": m}]}),
]

_REPLY_KEYS = ("response", "reply", "message", "answer", "text", "content", "output", "result")

# Keys the default HttpJsonConnector can read directly (no request_template needed).
_DEFAULT_READABLE = ("response", "text", "message", "output", "content", "raw")


def _string_paths(obj: Any, prefix: str = "") -> list[tuple[str, str]]:
    """Every (dotted-path, string-value) pair inside a nested dict/list."""
    out: list[tuple[str, str]] = []
    if isinstance(obj, str):
        if prefix:
            out.append((prefix, obj))
    elif isinstance(obj, dict):
        for k, v in obj.items():
            out += _string_paths(v, f"{prefix}.{k}" if prefix else str(k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out += _string_paths(v, f"{prefix}.{i}" if prefix else str(i))
    return out


def _find_reply_path(parsed: dict[str, Any]) -> str | None:
    """Dotted path to the reply text in a response — a common reply key, else the longest string."""
    pairs = [(p, v) for p, v in _string_paths(parsed) if len(v.strip()) > 1]
    if not pairs:
        return None
    # Map each leaf key to its first path, then pick by REPLY_KEYS *preference*
    # order (so 'response'/'message' — which the default connector reads — win
    # over 'reply' when several are present).
    by_leaf: dict[str, str] = {}
    for path, _ in pairs:
        by_leaf.setdefault(path.split(".")[-1].lower(), path)
    for key in _REPLY_KEYS:
        if key in by_leaf:
            return by_leaf[key]
    return max(pairs, key=lambda pv: len(pv[1]))[0]


async def discover_http(url: str, test_message: str = _PROBE) -> dict[str, Any] | None:
    """
    Probe `url` as a JSON chat API (no browser). Tries common request shapes concurrently and,
    on a plausible reply, returns {message_path, response_path, json_body, streaming}.
    """
    import asyncio

    import httpx

    from agentscan.core.connectors import parse_response

    async with httpx.AsyncClient(timeout=6.0, follow_redirects=True) as client:

        async def _probe_single(message_path: str, make_body: Any) -> dict[str, Any] | None:
            body = make_body(test_message)
            try:
                r = await client.post(url, json=body, headers={"content-type": "application/json"})
            except Exception:
                return None
            if r.status_code >= 400 or "html" in r.headers.get("content-type", ""):
                return None
            parsed = parse_response(r)
            if "error" in parsed:
                return None
            response_path = _find_reply_path(parsed)
            if response_path is None:
                return None
            return {
                "message_path": message_path,
                "response_path": response_path,
                "json_body": body,
                "streaming": "event-stream" in r.headers.get("content-type", ""),
            }

        tasks = [_probe_single(mp, mb) for mp, mb in _HTTP_SHAPES]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for res in results:
            if isinstance(res, dict):
                return res
    return None


async def discover_widget(
    url: str, headless: bool = True, test_message: str = "Hello"
) -> BrowserConfig | None:
    """Open `url`, find the chat widget, and return a BrowserConfig (or None)."""
    from playwright.async_api import async_playwright

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=headless)
        page = await browser.new_page()
        try:
            await page.goto(url, wait_until="domcontentloaded")
            await page.wait_for_timeout(1500)  # let JS widgets mount
            await page.evaluate(_INJECT_ASCSS)

            # 1. Input already visible? Otherwise click a launcher candidate.
            input_sel = await page.evaluate(_FIND_INPUT)
            open_sel: str | None = None
            if not input_sel:
                launchers = await page.evaluate(_FIND_LAUNCHERS)
                for cand in launchers[:4]:
                    try:
                        await page.click(cand, timeout=3000)
                    except Exception:
                        continue
                    await page.wait_for_timeout(1200)
                    await page.evaluate(_INJECT_ASCSS)
                    input_sel = await page.evaluate(_FIND_INPUT)
                    if input_sel:
                        open_sel = cand
                        break

            if not input_sel:
                logger.warning("Auto-discovery: no chat input found.")
                return None

            # 2. Send button (optional — Enter is the fallback).
            send_sel = await page.evaluate(_FIND_SEND, input_sel)

            # 3. Send one benign message and locate the reply bubble.
            response_sel = await _discover_response(page, input_sel, send_sel, test_message)

            return BrowserConfig(
                url=url,
                open_selector=open_sel,
                input_selector=input_sel,
                response_selector=response_sel or ".message",
                send_selector=send_sel,
            )
        finally:
            await browser.close()


async def _discover_response(
    page: Any, input_sel: str, send_sel: str | None, msg: str
) -> str | None:
    """Send a test message and derive a selector for the newest reply bubble."""
    before = await page.evaluate(
        "() => [...document.querySelectorAll('div,p,span,li')]"
        ".filter(e => (e.innerText||'').trim().length > 8).map(e => (e.innerText||'').trim())"
    )
    await page.fill(input_sel, msg)
    submitted = False
    if send_sel:
        try:
            await page.click(send_sel, timeout=4000)
            submitted = True
        except Exception:
            submitted = False
    if not submitted:
        await page.press(input_sel, "Enter")

    find_reply = r"""
    (args) => {
      const [before, msg] = args;
      const seen = new Set(before);
      const els = [...document.querySelectorAll('div,p,span,li')].filter(e => {
        const t = (e.innerText || '').trim();
        return t.length > 8 && !seen.has(t) && t !== msg && e.children.length <= 2;
      });
      if (!els.length) return null;
      // Newest appended text = the bot reply (it comes after the user's bubble).
      return window.__ascss(els[els.length - 1]);
    }
    """
    for _ in range(35):
        await page.wait_for_timeout(350)
        sel = await page.evaluate(find_reply, [before, msg])
        if sel:
            return sel
    return None
