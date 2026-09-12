# tests/test_mcp/test_server.py

from __future__ import annotations

import json

from agentscan.mcp.server import process_jsonrpc_message


def test_mcp_initialize() -> None:
    req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "test-client", "version": "1.0.0"},
        },
    }
    resp = process_jsonrpc_message(req)
    assert resp is not None
    assert resp["id"] == 1
    assert resp["result"]["serverInfo"]["name"] == "agentscan"
    assert "tools" in resp["result"]["capabilities"]


def test_mcp_ping() -> None:
    req = {"jsonrpc": "2.0", "id": 2, "method": "ping"}
    resp = process_jsonrpc_message(req)
    assert resp is not None
    assert resp["id"] == 2
    assert resp["result"] == {}


def test_mcp_notifications_initialized() -> None:
    req = {"jsonrpc": "2.0", "method": "notifications/initialized"}
    resp = process_jsonrpc_message(req)
    assert resp is None


def test_mcp_tools_list() -> None:
    req = {"jsonrpc": "2.0", "id": 3, "method": "tools/list"}
    resp = process_jsonrpc_message(req)
    assert resp is not None
    tools = resp["result"]["tools"]
    tool_names = [t["name"] for t in tools]
    assert "agentscan_list_attacks" in tool_names
    assert "agentscan_audit" in tool_names
    assert "agentscan_scan" in tool_names


def test_mcp_tools_call_list_attacks() -> None:
    req = {
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {"name": "agentscan_list_attacks", "arguments": {}},
    }
    resp = process_jsonrpc_message(req)
    assert resp is not None
    assert resp["id"] == 4
    content = resp["result"]["content"]
    assert content[0]["type"] == "text"
    assert "AgentScan Attack Registry" in content[0]["text"]
    assert "ATK-013" in content[0]["text"]


def test_mcp_tools_call_audit() -> None:
    req = {
        "jsonrpc": "2.0",
        "id": 5,
        "method": "tools/call",
        "params": {
            "name": "agentscan_audit",
            "arguments": {"path": "tests/fixtures/supply_chain", "offline": True},
        },
    }
    resp = process_jsonrpc_message(req)
    assert resp is not None
    assert resp["id"] == 5
    content = resp["result"]["content"]
    assert content[0]["type"] == "text"
    audit_data = json.loads(content[0]["text"])
    assert "score" in audit_data
    assert "status" in audit_data


def test_mcp_tools_call_unknown_tool() -> None:
    req = {
        "jsonrpc": "2.0",
        "id": 6,
        "method": "tools/call",
        "params": {"name": "nonexistent_tool", "arguments": {}},
    }
    resp = process_jsonrpc_message(req)
    assert resp is not None
    assert "error" in resp
    assert resp["error"]["code"] == -32601


def test_mcp_unknown_method() -> None:
    req = {"jsonrpc": "2.0", "id": 7, "method": "invalid_method"}
    resp = process_jsonrpc_message(req)
    assert resp is not None
    assert "error" in resp
    assert resp["error"]["code"] == -32601
