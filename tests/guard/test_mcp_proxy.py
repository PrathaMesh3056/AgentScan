# tests/guard/test_mcp_proxy.py

from __future__ import annotations

import json
from pathlib import Path

from agentscan.guard.mcp_proxy import MCPCapabilityProxy


def test_mcp_proxy_clean_request_passes(tmp_path: Path) -> None:
    """Verifies that a clean tool call within the workspace passes through (returns None)."""
    proxy = MCPCapabilityProxy(workspace_root=tmp_path)
    valid_file = tmp_path / "notes.txt"
    valid_file.write_text("ok", encoding="utf-8")

    clean_req = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": "req-1",
            "method": "tools/call",
            "params": {
                "name": "read_notes",
                "arguments": {"path": str(valid_file)},
            },
        }
    )

    result = proxy.process_request(clean_req)
    assert result is None  # Pass-through clean


def test_mcp_proxy_non_tool_call_passes(tmp_path: Path) -> None:
    """Verifies non-tools/call RPC methods (initialize, ping, tools/list) pass through."""
    proxy = MCPCapabilityProxy(workspace_root=tmp_path)

    init_req = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": "req-0",
            "method": "initialize",
            "params": {"clientInfo": {"name": "test-agent"}},
        }
    )
    assert proxy.process_request(init_req) is None

    invalid_json = "not-json-line"
    assert proxy.process_request(invalid_json) is None


def test_mcp_proxy_blocks_path_escape_in_any_argument_key(tmp_path: Path) -> None:
    """
    Standing Security Requirement:
    Asserts proxy inspects ALL arguments of every tools/call request,
    blocking path escapes in ANY argument key even if tool name lacks 'file'.
    """
    proxy = MCPCapabilityProxy(workspace_root=tmp_path)

    # 1. Arbitrary tool name with 'destination' key
    req_1 = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": "req-101",
            "method": "tools/call",
            "params": {
                "name": "custom_data_exporter",
                "arguments": {"destination": "../../etc/shadow"},
            },
        }
    )
    res_1 = proxy.process_request(req_1)
    assert res_1 is not None
    parsed_1 = json.loads(res_1)
    assert parsed_1["id"] == "req-101"
    assert parsed_1["result"]["isError"] is True
    assert "instruction_for_agent" in parsed_1["result"]
    assert "destination" in parsed_1["result"]["instruction_for_agent"]

    # 2. Key does NOT contain 'file' or 'path', but value starts with path indicator '..'
    req_2 = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": "req-102",
            "method": "tools/call",
            "params": {
                "name": "generic_compute",
                "arguments": {"random_flag": "../../../escaped_dir"},
            },
        }
    )
    res_2 = proxy.process_request(req_2)
    assert res_2 is not None
    parsed_2 = json.loads(res_2)
    assert parsed_2["result"]["isError"] is True
    assert "random_flag" in parsed_2["result"]["instruction_for_agent"]

    # 3. Target key matching regex
    req_3 = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": "req-103",
            "method": "tools/call",
            "params": {
                "name": "sync_worker",
                "arguments": {"target": "/etc/passwd"},
            },
        }
    )
    res_3 = proxy.process_request(req_3)
    assert res_3 is not None
    parsed_3 = json.loads(res_3)
    assert parsed_3["result"]["isError"] is True


def test_mcp_proxy_nested_argument_inspection(tmp_path: Path) -> None:
    """Verifies that nested dictionary and list arguments are recursively inspected."""
    proxy = MCPCapabilityProxy(workspace_root=tmp_path)

    nested_req = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": "req-nested",
            "method": "tools/call",
            "params": {
                "name": "batch_job",
                "arguments": {
                    "config": {
                        "output_target": "../../secrets/keys.json",
                    }
                },
            },
        }
    )

    res = proxy.process_request(nested_req)
    assert res is not None
    parsed = json.loads(res)
    assert parsed["result"]["isError"] is True
    assert "config.output_target" in parsed["result"]["instruction_for_agent"]


def test_mcp_proxy_command_guard_integration(tmp_path: Path) -> None:
    """Verifies that command inspection in MCP tools blocks shell injection."""
    proxy = MCPCapabilityProxy(
        workspace_root=tmp_path,
        allowed_binaries=["git", "ls"],
    )

    # Shell injection in command parameter
    bad_cmd_req = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": "req-cmd",
            "method": "tools/call",
            "params": {
                "name": "terminal_exec",
                "arguments": {"command": "git status; rm -rf /"},
            },
        }
    )
    res = proxy.process_request(bad_cmd_req)
    assert res is not None
    parsed = json.loads(res)
    assert parsed["result"]["isError"] is True
    assert "Command Security Policy Error" in parsed["result"]["content"][0]["text"]


def test_mcp_proxy_list_arguments_inspection(tmp_path: Path) -> None:
    """Verifies that lists within arguments are inspected."""
    proxy = MCPCapabilityProxy(workspace_root=tmp_path)

    list_req = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": "req-list",
            "method": "tools/call",
            "params": {
                "name": "multi_file_handler",
                "arguments": {
                    "files": ["valid.txt", "../../etc/shadow"],
                },
            },
        }
    )
    res = proxy.process_request(list_req)
    assert res is not None
    parsed = json.loads(res)
    assert parsed["result"]["isError"] is True
    assert "files[1]" in parsed["result"]["instruction_for_agent"]


def test_mcp_proxy_malformed_params_handling(tmp_path: Path) -> None:
    """Verifies that non-dict params or arguments are gracefully ignored."""
    proxy = MCPCapabilityProxy(workspace_root=tmp_path)

    bad_params = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": "req-bad-p",
            "method": "tools/call",
            "params": "not-a-dict",
        }
    )
    assert proxy.process_request(bad_params) is not None

    bad_args = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": "req-bad-a",
            "method": "tools/call",
            "params": {"arguments": "not-a-dict"},
        }
    )
    assert proxy.process_request(bad_args) is not None
