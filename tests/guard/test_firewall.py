# tests/guard/test_firewall.py

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import BaseModel, Field

from agentscan.guard.firewall import CapabilityGuard, protect_tool


class SampleToolSchema(BaseModel):
    query: str
    limit: int = Field(default=10, ge=1, le=100)


def test_protect_tool_happy_path(tmp_path: Path) -> None:
    """Verifies that clean invocations pass through without interference."""
    guard = CapabilityGuard(allowed_root=tmp_path)

    @guard.protect_tool
    def read_file(file_path: str) -> str:
        return f"read:{file_path}"

    test_file = tmp_path / "doc.txt"
    test_file.write_text("content", encoding="utf-8")

    res = read_file(file_path=str(test_file))
    assert res == f"read:{test_file}"


def test_protect_tool_path_traversal_blocked(tmp_path: Path) -> None:
    """Verifies that path traversal returns structured JSON error string rather than raising."""
    guard = CapabilityGuard(allowed_root=tmp_path)

    @guard.protect_tool
    def read_file(file_path: str) -> str:
        return f"read:{file_path}"

    res = read_file(file_path="../../../etc/passwd")
    parsed = json.loads(res)
    assert parsed["error"] == "SecurityPolicyViolation"
    assert parsed["type"] == "path_confinement_error"
    assert "instruction_for_agent" in parsed
    assert "workspace" in parsed["instruction_for_agent"].lower()


def test_protect_tool_shell_metacharacter_blocked(tmp_path: Path) -> None:
    """Verifies that shell metacharacters in arguments return structured JSON error string."""
    guard = CapabilityGuard(allowed_root=tmp_path)

    @guard.protect_tool
    def search_code(pattern: str) -> str:
        return f"found:{pattern}"

    res = search_code(pattern="main; rm -rf /")
    parsed = json.loads(res)
    assert parsed["error"] == "SecurityPolicyViolation"
    assert parsed["type"] == "shell_injection_error"
    assert "blocked" in parsed["instruction_for_agent"].lower()


def test_protect_tool_pydantic_schema_validation() -> None:
    """Verifies that Pydantic schema validation enforces bounds and types."""
    guard = CapabilityGuard()

    @guard.protect_tool(schema_model=SampleToolSchema)
    def query_db(query: str, limit: int = 10) -> str:
        return f"query:{query}:{limit}"

    # Valid schema invocation
    res_ok = query_db(query="SELECT 1", limit=5)
    assert res_ok == "query:SELECT 1:5"

    # Schema violation (limit > 100)
    res_bad = query_db(query="SELECT 1", limit=999)
    parsed = json.loads(res_bad)
    assert parsed["error"] == "SecurityPolicyViolation"
    assert parsed["type"] == "schema_validation_error"
    assert "instruction_for_agent" in parsed


def test_protect_tool_domain_allowlist() -> None:
    """Verifies that unauthorized domains are intercepted and permitted domains pass."""
    guard = CapabilityGuard(allowed_domains=["api.github.com", "huggingface.co"])

    @guard.protect_tool
    def fetch_api(endpoint_url: str) -> str:
        return f"fetched:{endpoint_url}"

    # Permitted domain
    res_ok = fetch_api(endpoint_url="https://api.github.com/repos/agentscan")
    assert "fetched:" in res_ok

    # Unauthorized domain
    res_bad = fetch_api(endpoint_url="https://malicious-c2.com/steal")
    parsed = json.loads(res_bad)
    assert parsed["error"] == "SecurityPolicyViolation"
    assert parsed["type"] == "unauthorized_domain"
    assert "api.github.com" in parsed["instruction_for_agent"]


def test_protect_tool_positional_arguments_inspection(tmp_path: Path) -> None:
    """Verifies positional argument passing is properly inspected via signature binding."""
    guard = CapabilityGuard(allowed_root=tmp_path)

    @guard.protect_tool
    def export_data(dest_path: str, format_type: str) -> str:
        return f"exported:{dest_path}:{format_type}"

    # Positional traversal attempt
    res = export_data("../../../etc/shadow", "json")
    parsed = json.loads(res)
    assert parsed["error"] == "SecurityPolicyViolation"
    assert parsed["type"] == "path_confinement_error"


@pytest.mark.asyncio
async def test_protect_tool_async_support(tmp_path: Path) -> None:
    """Verifies async tool functions are supported and protected seamlessly."""
    guard = CapabilityGuard(allowed_root=tmp_path)

    @guard.protect_tool
    async def async_read(file_path: str) -> str:
        return f"async:{file_path}"

    # Blocked traversal
    res_blocked = await async_read(file_path="../../../secret.txt")
    parsed = json.loads(res_blocked)
    assert parsed["error"] == "SecurityPolicyViolation"

    # Allowed local read
    local_file = tmp_path / "hello.txt"
    local_file.write_text("world", encoding="utf-8")
    res_ok = await async_read(file_path=str(local_file))
    assert res_ok == f"async:{local_file}"


def test_module_level_protect_tool_decorator() -> None:
    """Verifies module-level @protect_tool functions correctly with default settings."""

    @protect_tool
    def simple_tool(command_arg: str) -> str:
        return f"ran:{command_arg}"

    res = simple_tool(command_arg="run | evil")
    parsed = json.loads(res)
    assert parsed["error"] == "SecurityPolicyViolation"
    assert parsed["type"] == "shell_injection_error"
