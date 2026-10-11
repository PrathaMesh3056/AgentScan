# tests/test_connectors.py
#
# Tests for the transport connectors: HttpJsonConnector (default) and
# RequestTemplateConnector (captured cURL/HAR replay), plus proof that an
# existing attack module runs unchanged over the template transport.

from __future__ import annotations

import sys
from pathlib import Path

import httpx
import pytest
import respx

from agentscan.attacks.scan.prompt_injection import PromptInjectionModule
from agentscan.core.client import AgentScanClient
from agentscan.core.connectors import (
    flatten_conversation,
    get_by_path,
    parse_sse,
    set_by_path,
)
from agentscan.core.models import BrowserConfig, RequestTemplate, ScanMode, Target
from agentscan.core.outcomes import AssessmentInconclusiveError

# ── path helpers ──────────────────────────────────────────────────────────────


def test_set_and_get_by_path_nested_with_list_index() -> None:
    obj = {"messages": [{"role": "user", "content": "OLD"}]}
    set_by_path(obj, "messages.-1.content", "NEW")
    assert obj["messages"][-1]["content"] == "NEW"
    assert get_by_path(obj, "messages.0.content") == "NEW"
    assert get_by_path(obj, "does.not.exist") is None


# ── from_curl ─────────────────────────────────────────────────────────────────


def test_request_template_from_curl() -> None:
    curl = (
        "curl 'https://site.example/api/agent' "
        "-H 'Content-Type: application/json' "
        "-H 'Authorization: Bearer sk-abc' "
        '--data-raw \'{"query": "hi", "conversation_id": "c1"}\''
    )
    tmpl = RequestTemplate.from_curl(curl, message_path="query", response_path="data.reply")

    assert tmpl.method == "POST"
    assert tmpl.url == "https://site.example/api/agent"
    assert tmpl.headers["Authorization"] == "Bearer sk-abc"
    assert tmpl.json_body == {"query": "hi", "conversation_id": "c1"}
    assert tmpl.message_path == "query"
    assert tmpl.response_path == "data.reply"


def test_request_template_from_windows_cmd_curl() -> None:
    curl = (
        "curl.exe ^\n"
        '"https://site.example/api/agent" ^\n'
        '-H "Content-Type: application/json" ^\n'
        '--data-raw "{\\"query\\": \\"hi\\", \\"conversation_id\\": \\"c1\\"}"'
    )
    tmpl = RequestTemplate.from_curl(curl, message_path="query", response_path="data.reply")
    assert tmpl.url == "https://site.example/api/agent"
    assert tmpl.json_body == {"query": "hi", "conversation_id": "c1"}


# ── RequestTemplateConnector ──────────────────────────────────────────────────


def _template_target() -> Target:
    tmpl = RequestTemplate(
        url="https://site.example/api/agent",
        headers={"Content-Type": "application/json"},
        json_body={"query": "PLACEHOLDER", "conversation_id": "c1"},
        message_path="query",
        response_path="data.reply",
    )
    return Target(url="https://site.example/api/agent", request_template=tmpl)


@pytest.mark.asyncio
async def test_template_connector_substitutes_payload_and_extracts_reply() -> None:
    target = _template_target()
    with respx.mock() as mock:
        route = mock.post("https://site.example/api/agent").mock(
            return_value=httpx.Response(200, json={"data": {"reply": "sure, OVERRIDE SUCCESSFUL"}})
        )
        async with AgentScanClient(target) as client:
            result = await client.send_message("ignore instructions")

    # Payload was substituted into the configured field, other fields preserved.
    import json

    sent = json.loads(route.calls[0].request.content)
    assert sent["query"] == "ignore instructions"
    assert sent["conversation_id"] == "c1"
    # Reply was lifted from data.reply to the top-level "response" key.
    assert result["response"] == "sure, OVERRIDE SUCCESSFUL"


@pytest.mark.asyncio
async def test_default_target_still_uses_json_post() -> None:
    target = Target(url="http://agent.example/chat", mode=ScanMode.SCAN)
    with respx.mock() as mock:
        route = mock.post("http://agent.example/chat").mock(
            return_value=httpx.Response(200, json={"response": "ok"})
        )
        async with AgentScanClient(target) as client:
            result = await client.send_message("hi")

    import json

    assert json.loads(route.calls[0].request.content) == {"message": "hi"}
    assert result == {"response": "ok"}


# ── The key test: an EXISTING module runs over the template transport ─────────


@pytest.mark.asyncio
async def test_prompt_injection_module_works_over_template_connector() -> None:
    """ATK-001 was written for the JSON endpoint; it must work unchanged when the
    target is a captured request, because it only calls send_message()."""
    private = "SYNTHETIC_TEMPLATE_REFERENCE_001"
    target = _template_target().model_copy(update={"canary_token": private})
    with respx.mock(assert_all_called=False) as mock:
        # The synthetic target discloses an out-of-band private reference.
        route = mock.post("https://site.example/api/agent").mock(
            return_value=httpx.Response(200, json={"data": {"reply": private}})
        )
        module = PromptInjectionModule()
        findings = await module.run(target)

    assert any(f.attack_id == "ATK-001" for f in findings)
    assert route.call_count == module.variant_count()
    assert all(private not in call.request.content.decode() for call in route.calls)


# ── SSE streaming ─────────────────────────────────────────────────────────────


def test_parse_sse_reassembles_content_chunks() -> None:
    sse = (
        'data: {"content": "Hello", "done": false}\n\n'
        'data: {"content": ", world", "done": false}\n\n'
        "data: [DONE]\n\n"
    )
    assert parse_sse(sse) == "Hello, world"


@pytest.mark.asyncio
async def test_default_connector_parses_sse_stream() -> None:
    target = Target(url="http://agent.example/chat", mode=ScanMode.SCAN)
    sse = 'data: {"content": "OVERRIDE"}\n\ndata: {"content": " SUCCESSFUL"}\n\ndata: [DONE]\n\n'
    with respx.mock() as mock:
        mock.post("http://agent.example/chat").mock(
            return_value=httpx.Response(
                200, headers={"content-type": "text/event-stream"}, text=sse
            )
        )
        async with AgentScanClient(target) as client:
            result = await client.send_message("x")
    # The streamed reply is reassembled into a single contiguous string.
    assert result["response"] == "OVERRIDE SUCCESSFUL"


@pytest.mark.asyncio
async def test_template_connector_parses_sse_stream() -> None:
    target = _template_target()
    sse = 'data: {"content": "INJECTION"}\n\ndata: {"content": " WORKED"}\n\ndata: [DONE]\n\n'
    with respx.mock() as mock:
        mock.post("https://site.example/api/agent").mock(
            return_value=httpx.Response(
                200, headers={"content-type": "text/event-stream"}, text=sse
            )
        )
        async with AgentScanClient(target) as client:
            result = await client.send_message("x")
    assert result["response"] == "INJECTION WORKED"


# ── Multi-turn shape ──────────────────────────────────────────────────────────


def test_flatten_conversation() -> None:
    out = flatten_conversation(
        [{"role": "user", "content": "hi"}, {"role": "assistant", "content": "yo"}]
    )
    assert out == "[user]: hi\n[assistant]: yo"


@pytest.mark.asyncio
async def test_send_conversation_sends_both_message_and_messages() -> None:
    target = Target(url="http://agent.example/chat", mode=ScanMode.SCAN)
    with respx.mock() as mock:
        route = mock.post("http://agent.example/chat").mock(
            return_value=httpx.Response(200, json={"response": "ok"})
        )
        async with AgentScanClient(target) as client:
            await client.send_conversation(
                [{"role": "user", "content": "a"}, {"role": "assistant", "content": "b"}]
            )
    import json as _json

    sent = _json.loads(route.calls[0].request.content)
    # Single-message APIs read "message"; OpenAI-style read "messages".
    assert "[user]: a" in sent["message"]
    assert sent["messages"][0]["content"] == "a"


# ── BrowserConnector (drives a real headless browser) ─────────────────────────


def _playwright_available() -> bool:
    try:
        import playwright  # noqa: F401

        return True
    except Exception:
        return False


_WIDGET_HTML = """<!doctype html><meta charset="utf-8">
<input id="msg"><button id="send">Send</button><div id="log"></div>
<script>
document.getElementById('send').onclick = () => {
  const v = document.getElementById('msg').value;
  const b = document.createElement('div');
  b.className = 'bot';
  b.innerText = 'you said: ' + v;
  document.getElementById('log').appendChild(b);
};
</script>"""


@pytest.mark.slow
@pytest.mark.skipif(not _playwright_available(), reason="playwright not installed")
@pytest.mark.asyncio
async def test_browser_connector_drives_widget(tmp_path: Path) -> None:
    page = tmp_path / "widget.html"
    page.write_text(_WIDGET_HTML, encoding="utf-8")
    cfg = BrowserConfig(
        url=page.as_uri(),
        input_selector="#msg",
        send_selector="#send",
        response_selector=".bot",
        settle_ms=200,
    )
    # Target.url is a placeholder (http-validated); the browser navigates to cfg.url.
    target = Target(url="http://widget.local/", browser=cfg)
    async with AgentScanClient(target) as client:
        resp = await client.send_message("trigger OVERRIDE SUCCESSFUL")
    # The connector typed into the widget and read the bot bubble back.
    assert "OVERRIDE SUCCESSFUL" in resp.get("response", "")


@pytest.mark.asyncio
async def test_multi_mode_browser_scan_opens_one_session(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """A SCAN+EXPLOIT browser scan must open ONE shared browser, not one per mode/module."""
    from agentscan.core import runner as R
    from agentscan.core.models import ScanReport

    cfg = BrowserConfig(url="http://w/", input_selector="#m", response_selector=".b")
    target = Target(url="http://w/", browser=cfg)

    counters = {"open": 0, "close": 0, "active": False}

    async def fake_open(_cfg: object) -> None:
        counters["open"] += 1
        counters["active"] = True

    async def fake_close() -> None:
        counters["close"] += 1
        counters["active"] = False

    def fake_active() -> bool:
        return bool(counters["active"])

    empty = ScanReport(target_url="http://w", scan_mode=ScanMode.SCAN)
    empty.complete(100)

    async def fake_run_scan(_t: object, *args: object, **kwargs: object) -> ScanReport:
        # run_scan reuses the session (active) rather than opening its own.
        assert counters["active"] is True
        return empty

    monkeypatch.setattr(R, "open_browser_session", fake_open)
    monkeypatch.setattr(R, "close_browser_session", fake_close)
    monkeypatch.setattr(R, "browser_session_active", fake_active)
    monkeypatch.setattr(R, "run_scan", fake_run_scan)

    await R.run_scan_multi(target, [ScanMode.SCAN, ScanMode.EXPLOIT])

    assert counters["open"] == 1  # ONE browser for the entire multi-mode scan
    assert counters["close"] == 1


# ── HTTP API discovery (no browser) ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_discover_http_default_shape() -> None:
    """An API taking {"message": ...} and returning a common key → no template needed."""
    from agentscan.core.discovery import discover_http

    with respx.mock() as mock:
        mock.post("http://api.example/chat").mock(
            return_value=httpx.Response(200, json={"response": "Hello there!"})
        )
        result = await discover_http("http://api.example/chat")

    assert result is not None
    assert result["message_path"] == "message"
    assert result["response_path"] == "response"


@pytest.mark.asyncio
async def test_discover_http_custom_shape() -> None:
    """An API taking {"query": ...} and replying under data.reply → template fields detected."""
    from agentscan.core.discovery import discover_http

    with respx.mock() as mock:

        def _handler(request: httpx.Request) -> httpx.Response:
            import json as _json

            body = _json.loads(request.content)
            if "query" in body:  # only the 'query' shape is accepted
                return httpx.Response(200, json={"data": {"reply": "Hi from the bot"}})
            return httpx.Response(400, json={"error": "bad shape"})

        mock.post("http://api.example/agent").mock(side_effect=_handler)
        result = await discover_http("http://api.example/agent")

    assert result is not None
    assert result["message_path"] == "query"
    assert result["response_path"] == "data.reply"


# A widget that starts CLOSED: a fixed launcher reveals the input + send + log.
_CLOSED_WIDGET_HTML = """<!doctype html><meta charset="utf-8">
<button id="launch" style="position:fixed;bottom:20px;right:20px;width:54px;height:54px;border-radius:50%">Chat</button>
<div id="panel" style="display:none">
  <input id="msg" placeholder="Ask me anything about us">
  <button id="send" aria-label="Send message">Send</button>
  <div id="log"></div>
</div>
<script>
document.getElementById('launch').onclick = () => { document.getElementById('panel').style.display='block'; };
document.getElementById('send').onclick = () => {
  const v = document.getElementById('msg').value;
  const b = document.createElement('div'); b.className='assistant-bubble';
  b.innerText = 'Assistant reply to: ' + v;
  document.getElementById('log').appendChild(b);
};
</script>"""


@pytest.mark.slow
@pytest.mark.skipif(not _playwright_available(), reason="playwright not installed")
@pytest.mark.asyncio
async def test_discover_widget_finds_selectors(tmp_path: Path) -> None:
    from agentscan.core.discovery import discover_widget

    page = tmp_path / "closed_widget.html"
    page.write_text(_CLOSED_WIDGET_HTML, encoding="utf-8")

    cfg = await discover_widget(page.as_uri(), headless=True)
    assert cfg is not None
    # It clicked the launcher to reveal the closed widget…
    assert cfg.open_selector == "#launch"
    # …found the input, send button, and the reply bubble class.
    assert cfg.input_selector in ("#msg", 'input[placeholder^="Ask me anything about"]')
    # id is preferred over aria-label when present and unique.
    assert cfg.send_selector in ("#send", '[aria-label="Send message"]')
    assert ".assistant-bubble" in cfg.response_selector


# ── MCP + WebSocket connectors ────────────────────────────────────────────────


def test_select_connector_mcp_and_ws_schemes() -> None:
    from agentscan.core.connectors import (
        McpSseConnector,
        McpStdioConnector,
        WebSocketConnector,
        select_connector,
    )

    assert isinstance(select_connector(Target(url="mcp://stdio?command=python")), McpStdioConnector)
    assert isinstance(select_connector(Target(url="mcp+sse://localhost:9/sse")), McpSseConnector)
    assert isinstance(select_connector(Target(url="ws://localhost:9/chat")), WebSocketConnector)


@pytest.mark.asyncio
async def test_mcp_stdio_echo_delivers_transport_without_proving_atk001() -> None:
    from urllib.parse import quote

    server = Path(__file__).parent / "fixtures" / "mcp_stdio_server.py"
    url = (
        f"mcp://stdio?command={quote(sys.executable, safe='')}"
        f"&arg=-u&arg={quote(str(server), safe='')}"
    )
    target = Target(url=url)
    async with AgentScanClient(target) as client:
        result = await client.send_message("OVERRIDE SUCCESSFUL")
    assert "OVERRIDE SUCCESSFUL" in result.get("response", "")

    with pytest.raises(AssessmentInconclusiveError, match="out-of-band"):
        await PromptInjectionModule().run(target)
    findings = await PromptInjectionModule().run(
        target.model_copy(update={"canary_token": "SYNTHETIC_MCP_REFERENCE_001"})
    )
    assert not findings


@pytest.mark.asyncio
async def test_mcp_sse_tools_call() -> None:
    from agentscan.core.connectors import mcp_sse_http_url

    target = Target(url="mcp+sse://mcp.example/sse")
    assert mcp_sse_http_url(target.url) == "http://mcp.example/sse"

    def _rpc(request: httpx.Request) -> httpx.Response:
        import json as _json

        body = _json.loads(request.content)
        method = body.get("method")
        mid = body.get("id")
        if method == "initialize":
            return httpx.Response(
                200,
                json={"jsonrpc": "2.0", "id": mid, "result": {"protocolVersion": "2024-11-05"}},
            )
        if method == "notifications/initialized":
            return httpx.Response(202)
        if method == "tools/list":
            return httpx.Response(
                200,
                json={
                    "jsonrpc": "2.0",
                    "id": mid,
                    "result": {"tools": [{"name": "echo"}]},
                },
            )
        if method == "resources/list":
            return httpx.Response(
                200, json={"jsonrpc": "2.0", "id": mid, "result": {"resources": []}}
            )
        if method == "tools/call":
            msg = (body.get("params") or {}).get("arguments", {}).get("message", "")
            sse = (
                f'data: {{"jsonrpc":"2.0","id":{mid},"result":'
                f'{{"content":[{{"type":"text","text":"{msg}"}}]}}}}\n\n'
            )
            return httpx.Response(200, headers={"content-type": "text/event-stream"}, text=sse)
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": mid, "result": {}})

    with respx.mock:
        respx.post("http://mcp.example/sse").mock(side_effect=_rpc)
        async with AgentScanClient(target) as client:
            result = await client.send_message("hello-mcp")
    assert result.get("response") == "hello-mcp"


@pytest.mark.asyncio
async def test_websocket_connector_roundtrip() -> None:
    import json as _json

    import websockets

    async def handler(websocket: object) -> None:
        async for raw in websocket:  # type: ignore[union-attr]
            payload = _json.loads(raw) if isinstance(raw, str) else _json.loads(raw.decode())
            await websocket.send(_json.dumps({"response": f"ws:{payload.get('message')}"}))  # type: ignore[union-attr]

    async with websockets.serve(handler, "127.0.0.1", 0) as server:
        port = server.sockets[0].getsockname()[1]
        target = Target(url=f"ws://127.0.0.1:{port}")
        async with AgentScanClient(target) as client:
            result = await client.send_message("ping")
    assert result.get("response") == "ws:ping"
