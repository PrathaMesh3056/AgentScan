"""QA-182: the closed mobile drawer must leave the tab order and the AX tree.

These regressions drive the real dashboard in headless Chrome over the
DevTools protocol. They skip when Chrome or the ``websockets`` client used to
speak CDP is unavailable, so the rest of the suite still runs on headless CI
images without a browser.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
import urllib.request
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

pytest.importorskip("websockets")
websockets_sync_client = pytest.importorskip("websockets.sync.client")
connect = websockets_sync_client.connect

ROOT = Path(__file__).resolve().parents[1]
STATIC_DIR = ROOT / "agentscan" / "ui" / "static"

CHROME_CANDIDATES = (
    os.environ.get("AGENTSCAN_CHROME_PATH"),
    os.environ.get("CHROME_PATH"),
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-stable",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
)
CHROME = next(
    (Path(candidate) for candidate in CHROME_CANDIDATES if candidate and Path(candidate).is_file()),
    None,
)

pytestmark = pytest.mark.skipif(CHROME is None, reason="headless Chrome is not installed")


class _StaticHandler(SimpleHTTPRequestHandler):
    """Serve index.html at / and the dashboard assets under /static/."""

    def translate_path(self, path: str) -> str:
        path = path.split("?", 1)[0].split("#", 1)[0]
        if path in ("", "/", "/index.html"):
            return str(STATIC_DIR / "index.html")
        if path.startswith("/static/"):
            relative = Path(path[len("/static/") :])
            if ".." not in relative.parts:
                return str(STATIC_DIR / relative)
        return str(STATIC_DIR / "__not_found__")

    def log_message(self, *args: object) -> None:  # keep pytest output clean
        pass


class CDP:
    def __init__(self, websocket) -> None:
        self.ws = websocket
        self._next_id = 0
        self.events: list[dict] = []

    def send(self, method: str, **params: object) -> dict:
        self._next_id += 1
        message_id = self._next_id
        self.ws.send(json.dumps({"id": message_id, "method": method, "params": params}))
        while True:
            message = json.loads(self.ws.recv(timeout=30))
            if message.get("id") == message_id:
                if "error" in message:
                    raise AssertionError(f"{method} failed: {message['error']}")
                return message.get("result", {})
            self.events.append(message)

    def evaluate(self, expression: str):
        result = self.send("Runtime.evaluate", expression=expression, returnByValue=True)
        if "exceptionDetails" in result:
            raise AssertionError(f"JavaScript failed: {result['exceptionDetails']}")
        return result["result"].get("value")


def _wait_for(cdp: CDP, expression: str, timeout: float = 30.0):
    deadline = time.time() + timeout
    last_error: Exception | None = None
    while time.time() < deadline:
        try:
            value = cdp.evaluate(expression)
            if value:
                return value
        except Exception as exc:  # the page may still be navigating
            last_error = exc
        time.sleep(0.1)
    raise AssertionError(f"timed out waiting for {expression!r}: {last_error}")


def _wait_ready(cdp: CDP) -> None:
    _wait_for(
        cdp,
        "document.readyState === 'complete' && typeof toggleSidebarMobile === 'function'",
    )


def _set_viewport(cdp: CDP, width: int, height: int) -> None:
    cdp.send(
        "Emulation.setDeviceMetricsOverride",
        width=width,
        height=height,
        deviceScaleFactor=1,
        mobile=False,
    )


def _sidebar_state(cdp: CDP) -> dict:
    return cdp.evaluate(
        """(() => {
          const sb = document.getElementById('sidebar');
          const trigger = document.getElementById('btn-mobile-menu');
          const rect = sb.getBoundingClientRect();
          return {
            innerWidth: window.innerWidth,
            open: sb.classList.contains('mobile-open'),
            inert: sb.inert,
            inertAttribute: sb.hasAttribute('inert'),
            ariaHidden: sb.getAttribute('aria-hidden'),
            left: rect.left,
            right: rect.right,
            transform: getComputedStyle(sb).transform,
            expanded: trigger && trigger.getAttribute('aria-expanded'),
            controls: trigger && trigger.getAttribute('aria-controls'),
          };
        })()"""
    )


def _sidebar_focus_probe(cdp: CDP) -> dict:
    """Focus every candidate inside the drawer and report which ones accept it."""
    return cdp.evaluate(
        """(() => {
          const sb = document.getElementById('sidebar');
          const candidates = [...sb.querySelectorAll(
            'a[href],button:not([disabled]),input:not([disabled]),select,textarea,[tabindex]:not([tabindex="-1"])'
          )];
          const focusable = [];
          for (const el of candidates) {
            el.focus();
            if (document.activeElement === el) {
              focusable.push({
                id: el.id,
                className: typeof el.className === 'string' ? el.className : '',
                text: (el.textContent || '').trim().slice(0, 40),
              });
            }
          }
          if (document.activeElement && typeof document.activeElement.blur === 'function') {
            document.activeElement.blur();
          }
          return {candidates: candidates.length, focusable};
        })()"""
    )


def _sidebar_backend_ids(cdp: CDP) -> set[int]:
    document = cdp.send("DOM.getDocument", depth=1, pierce=True)
    node = cdp.send("DOM.querySelector", nodeId=document["root"]["nodeId"], selector="#sidebar")
    described = cdp.send("DOM.describeNode", nodeId=node["nodeId"], depth=-1)

    backend_ids: set[int] = set()

    def walk(current: dict) -> None:
        backend_ids.add(current.get("backendNodeId"))
        for child in current.get("children", []):
            walk(child)

    walk(described["node"])
    return backend_ids


def _sidebar_ax_nodes(cdp: CDP) -> list[dict]:
    """Return non-ignored accessibility nodes that belong to the drawer."""
    backend_ids = _sidebar_backend_ids(cdp)
    tree = cdp.send("Accessibility.getFullAXTree")
    return [
        {
            "role": node.get("role", {}).get("value"),
            "name": node.get("name", {}).get("value"),
        }
        for node in tree["nodes"]
        if node.get("backendDOMNodeId") in backend_ids and not node.get("ignored")
    ]


def _press_key(
    cdp: CDP, key: str, code: str, virtual_key_code: int, text: str | None = None
) -> None:
    down: dict[str, object] = {
        "type": "keyDown",
        "key": key,
        "code": code,
        "windowsVirtualKeyCode": virtual_key_code,
        "nativeVirtualKeyCode": virtual_key_code,
    }
    if text is not None:
        down["text"] = text
    cdp.send("Input.dispatchKeyEvent", **down)
    cdp.send(
        "Input.dispatchKeyEvent",
        type="keyUp",
        key=key,
        code=code,
        windowsVirtualKeyCode=virtual_key_code,
        nativeVirtualKeyCode=virtual_key_code,
    )


def _tab_from_top(cdp: CDP) -> dict:
    cdp.evaluate(
        """(() => {
          if (document.activeElement && typeof document.activeElement.blur === 'function') {
            document.activeElement.blur();
          }
          window.scrollTo(0, 0);
          document.body.setAttribute('tabindex', '-1');
          document.body.focus();
          document.body.removeAttribute('tabindex');
          return true;
        })()"""
    )
    _press_key(cdp, "Tab", "Tab", 9)
    time.sleep(0.2)
    return cdp.evaluate(
        """(() => {
          const el = document.activeElement;
          if (!el) return null;
          const rect = el.getBoundingClientRect();
          return {
            tag: el.tagName,
            id: el.id,
            text: (el.textContent || '').trim().slice(0, 40),
            left: rect.left,
            top: rect.top,
            inSidebar: Boolean(el.closest('#sidebar')),
          };
        })()"""
    )


class _Dashboard:
    def __init__(self, chrome_path: Path) -> None:
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _StaticHandler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/"
        self.profile = Path(tempfile.mkdtemp(prefix="agentscan-chrome-"))
        self.chrome = subprocess.Popen(
            [
                str(chrome_path),
                "--headless=new",
                "--disable-gpu",
                "--no-first-run",
                "--no-default-browser-check",
                "--disable-extensions",
                "--disable-background-networking",
                "--remote-allow-origins=*",
                "--remote-debugging-address=127.0.0.1",
                "--remote-debugging-port=0",
                f"--user-data-dir={self.profile}",
                "--window-size=390,844",
                "about:blank",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def debug_port(self) -> int:
        port_file = self.profile / "DevToolsActivePort"
        deadline = time.time() + 20
        while time.time() < deadline:
            if port_file.is_file():
                return int(port_file.read_text(encoding="utf-8").splitlines()[0])
            if self.chrome.poll() is not None:
                raise AssertionError(f"Chrome exited with {self.chrome.returncode}")
            time.sleep(0.1)
        raise AssertionError("Chrome did not expose a DevTools port")

    def page_websocket(self) -> str:
        url = f"http://127.0.0.1:{self.debug_port()}/json/list"
        targets = json.loads(urllib.request.urlopen(url, timeout=10).read())
        page = next((target for target in targets if target.get("type") == "page"), None)
        assert page is not None, targets
        return page["webSocketDebuggerUrl"]

    def stop(self) -> None:
        self.chrome.terminate()
        try:
            self.chrome.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.chrome.kill()
        self.server.shutdown()
        self.server.server_close()
        shutil.rmtree(self.profile, ignore_errors=True)


@pytest.fixture
def dashboard():
    instance = _Dashboard(CHROME)
    try:
        yield instance
    finally:
        instance.stop()


def _open_page(dashboard: _Dashboard, cdp: CDP, width: int, height: int) -> None:
    cdp.send("Page.enable")
    cdp.send("Runtime.enable")
    _set_viewport(cdp, width, height)
    cdp.send("Page.navigate", url=dashboard.url)
    _wait_ready(cdp)


def test_closed_mobile_drawer_is_inert_and_skipped_by_keyboard(dashboard) -> None:
    with connect(dashboard.page_websocket(), max_size=None, open_timeout=15) as websocket:
        cdp = CDP(websocket)
        _open_page(dashboard, cdp, 390, 844)

        closed = _sidebar_state(cdp)
        assert closed["innerWidth"] == 390
        assert closed["open"] is False
        assert closed["left"] < 0, "the closed drawer should be translated off-screen"
        assert closed["inert"] is True
        assert closed["inertAttribute"] is True
        assert closed["ariaHidden"] == "true"
        assert closed["expanded"] == "false"
        assert closed["controls"] == "sidebar"

        closed_focus = _sidebar_focus_probe(cdp)
        # The drawer still contains focusable-looking markup, but inert must
        # prevent every one of them from accepting focus.
        assert closed_focus["candidates"] >= 1
        assert closed_focus["focusable"] == []

        trigger_box = cdp.evaluate(
            "(() => { const r = document.getElementById('btn-mobile-menu').getBoundingClientRect();"
            " return {width: r.width, height: r.height}; })()"
        )
        assert trigger_box["width"] >= 24
        assert trigger_box["height"] >= 24

        assert _sidebar_ax_nodes(cdp) == []

        first_tab = _tab_from_top(cdp)
        assert first_tab is not None
        assert first_tab["inSidebar"] is False
        assert first_tab["id"] == "btn-mobile-menu"
        assert first_tab["left"] >= 0

        # Opening must lift inert/aria-hidden and expose the drawer again.
        # The focused hamburger is activated with the keyboard, not a scripted click.
        _press_key(cdp, "Enter", "Enter", 13, text="\r")
        opened = _wait_for(
            cdp,
            "(() => { const s = document.getElementById('sidebar');"
            " const r = s.getBoundingClientRect();"
            " return s.classList.contains('mobile-open') && !s.inert"
            " && s.getAttribute('aria-hidden') === null && r.left >= -1; })()",
        )
        assert opened is True
        opened_state = _sidebar_state(cdp)
        assert opened_state["inert"] is False
        assert opened_state["ariaHidden"] is None
        assert opened_state["expanded"] == "true"
        assert opened_state["left"] == pytest.approx(0, abs=1)

        opened_focus = _sidebar_focus_probe(cdp)
        assert any(
            "brand-link" in item["className"] for item in opened_focus["focusable"]
        )
        assert any(
            item["text"].startswith("Overview") for item in opened_focus["focusable"]
        )

        # The open drawer must still accept pointer/touch hits and keep its
        # 44px-tall mobile nav rows.
        touch = cdp.evaluate(
            """(() => {
              const nav = document.querySelector('#sidebar .sidebar-nav-item');
              const list = document.querySelector('#sidebar nav');
              if (list) list.scrollTop = 0;
              const rect = nav.getBoundingClientRect();
              const hit = document.elementFromPoint(
                rect.left + rect.width / 2, rect.top + rect.height / 2
              );
              return {
                height: rect.height,
                left: rect.left,
                top: rect.top,
                hitTarget: Boolean(hit && nav.contains(hit)),
                hitTag: hit && hit.tagName,
                hitClass: hit && typeof hit.className === 'string' ? hit.className : '',
              };
            })()"""
        )
        assert touch["height"] >= 24
        assert touch["hitTarget"] is True, touch

        opened_ax = _sidebar_ax_nodes(cdp)
        assert any(
            node["role"] == "link" and node["name"] == "Overview" for node in opened_ax
        ), opened_ax

        # Closing must also drop focus that was inside the drawer.
        assert cdp.evaluate(
            "(() => { const el = document.querySelector('#sidebar .brand-link');"
            " el.focus(); return document.activeElement === el; })()"
        )
        cdp.evaluate("document.getElementById('sidebar-backdrop').click()")
        assert _wait_for(
            cdp,
            "(() => { const s = document.getElementById('sidebar');"
            " const active = document.activeElement;"
            " return !s.classList.contains('mobile-open') && s.inert"
            " && s.getAttribute('aria-hidden') === 'true'"
            " && (!active || !active.closest('#sidebar')); })()",
        )
        assert _sidebar_state(cdp)["expanded"] == "false"
        assert _sidebar_focus_probe(cdp)["focusable"] == []

        # The no-argument toggle used elsewhere must update both directions.
        cdp.evaluate("toggleSidebarMobile()")
        assert _sidebar_state(cdp)["inert"] is False
        assert _sidebar_state(cdp)["expanded"] == "true"
        cdp.evaluate("toggleSidebarMobile()")
        assert _sidebar_state(cdp)["inert"] is True
        assert _sidebar_state(cdp)["expanded"] == "false"


def test_desktop_sidebar_stays_available_and_viewport_changes_resync(dashboard) -> None:
    with connect(dashboard.page_websocket(), max_size=None, open_timeout=15) as websocket:
        cdp = CDP(websocket)
        _open_page(dashboard, cdp, 1440, 900)

        desktop = _sidebar_state(cdp)
        assert desktop["innerWidth"] == 1440
        assert desktop["inert"] is False
        assert desktop["inertAttribute"] is False
        assert desktop["ariaHidden"] is None
        assert desktop["left"] >= 0
        assert desktop["expanded"] == "false"

        desktop_focus = _sidebar_focus_probe(cdp)
        assert any(
            item["text"].startswith("Overview") for item in desktop_focus["focusable"]
        )
        assert any(
            node["role"] == "link" and node["name"] == "Overview"
            for node in _sidebar_ax_nodes(cdp)
        )

        # Crossing below the drawer breakpoint hides and disables the sidebar,
        # and crossing back restores it without a reload.
        _set_viewport(cdp, 390, 844)
        assert _wait_for(
            cdp,
            "(() => { const s = document.getElementById('sidebar');"
            " return window.innerWidth === 390 && s.inert"
            " && s.getAttribute('aria-hidden') === 'true'; })()",
        )
        assert _sidebar_focus_probe(cdp)["focusable"] == []

        _set_viewport(cdp, 1440, 900)
        assert _wait_for(
            cdp,
            "(() => { const s = document.getElementById('sidebar');"
            " return window.innerWidth === 1440 && !s.inert"
            " && s.getAttribute('aria-hidden') === null; })()",
        )
        assert any(
            item["text"].startswith("Overview")
            for item in _sidebar_focus_probe(cdp)["focusable"]
        )
