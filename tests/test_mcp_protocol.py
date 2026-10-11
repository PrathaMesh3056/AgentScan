from __future__ import annotations

import json

import httpx
import pytest
import respx

from agentscan.core.connectors.mcp import McpSseConnector, _McpClientMixin
from agentscan.core.models import Target


async def test_mcp_http_session_pagination_and_correlated_sse_notifications():
    requests = []

    def reply(request):
        requests.append(request)
        if request.method == "DELETE":
            assert request.headers["Mcp-Session-Id"] == "synthetic-session"
            return httpx.Response(204)
        body = json.loads(request.content)
        method, rid = body["method"], body.get("id")
        if method == "initialize":
            return httpx.Response(
                200,
                headers={"Mcp-Session-Id": "synthetic-session"},
                json={
                    "jsonrpc": "2.0",
                    "id": rid,
                    "result": {"protocolVersion": "2025-06-18", "capabilities": {"resources": {}}},
                },
            )
        assert request.headers["Mcp-Session-Id"] == "synthetic-session"
        assert request.headers["MCP-Protocol-Version"] == "2025-06-18"
        if method == "notifications/initialized":
            return httpx.Response(202)
        if method == "tools/list":
            result = (
                {"tools": [{"name": "second"}]}
                if body.get("params", {}).get("cursor") == "page2"
                else {"tools": [{"name": "first"}], "nextCursor": "page2"}
            )
        elif method == "resources/list":
            result = {"resources": []}
        else:
            result = {"content": [{"type": "text", "text": "actual correlated reply"}]}
            frames = [
                {
                    "jsonrpc": "2.0",
                    "method": "notifications/message",
                    "params": {"text": "not a response"},
                },
                {"jsonrpc": "2.0", "id": 999, "result": {"content": [{"text": "wrong request"}]}},
                {"jsonrpc": "2.0", "id": rid, "result": result},
            ]
            return httpx.Response(
                200,
                headers={"content-type": "text/event-stream"},
                text="".join("data: " + json.dumps(f) + "\r\n\r\n" for f in frames),
            )
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": rid, "result": result})

    with respx.mock:
        respx.route(url="http://mcp.example/mcp").mock(side_effect=reply)
        async with McpSseConnector(Target(url="mcp+sse://mcp.example/mcp")) as connector:
            assert [t["name"] for t in connector._tools] == ["first", "second"]
            assert (await connector.send_message("synthetic probe"))[
                "response"
            ] == "actual correlated reply"
        assert connector._client is None
    assert requests[-1].method == "DELETE"


@pytest.mark.parametrize(
    "result", [{"tools": [], "nextCursor": "repeat"}, {"tools": "invalid"}, {}]
)
async def test_incomplete_or_invalid_mcp_catalog_fails_instead_of_clean(result):
    class Fake(_McpClientMixin):
        async def _rpc(self, method, params=None):
            return {"result": result}

    with pytest.raises(ValueError):
        await Fake()._list_all("tools/list", "tools")


async def test_empty_mcp_catalog_is_unavailable_for_active_probe():
    class Fake(_McpClientMixin):
        _tools = []

    response = await Fake()._probe_message("synthetic probe")
    assert "error" in response and "response" not in response


async def test_http_failed_handshake_closes_client():
    connector = McpSseConnector(Target(url="mcp+sse://mcp.example/mcp"))
    with respx.mock:
        respx.post("http://mcp.example/mcp").respond(
            200, json={"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "unsupported"}}
        )
        with pytest.raises(ValueError, match="protocol"):
            await connector.__aenter__()
    assert connector._client is None


async def test_expired_mcp_session_reinitializes_without_replaying_tool():
    initialization = 0
    tools = 0

    def reply(request):
        nonlocal initialization, tools
        if request.method == "DELETE":
            return httpx.Response(204)
        body = json.loads(request.content)
        method, rid = body["method"], body.get("id")
        if method == "initialize":
            initialization += 1
            return httpx.Response(
                200,
                headers={"Mcp-Session-Id": f"session-{initialization}"},
                json={"jsonrpc": "2.0", "id": rid, "result": {"protocolVersion": "2025-06-18"}},
            )
        if method == "notifications/initialized":
            return httpx.Response(202)
        if method == "tools/list":
            return httpx.Response(
                200, json={"jsonrpc": "2.0", "id": rid, "result": {"tools": [{"name": "echo"}]}}
            )
        tools += 1
        return httpx.Response(404)

    with respx.mock:
        respx.route(url="http://mcp.example/mcp").mock(side_effect=reply)
        async with McpSseConnector(Target(url="mcp+sse://mcp.example/mcp")) as connector:
            result = await connector.send_message("synthetic tool request")
            assert "not replayed" in result["error"]
    assert initialization == 2 and tools == 1
