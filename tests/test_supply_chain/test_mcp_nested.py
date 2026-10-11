"""Nested MCP declarations retain per-server coverage without running servers."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from agentscan.supply_chain.mcp_auditor import scan_mcp_configs


def _scan(tmp_path: Path, config: object, filename: str = "mcp.json"):
    file = tmp_path / filename
    file.write_text(json.dumps(config), encoding="utf-8")
    coverage: list[dict] = []
    findings, checks = scan_mcp_configs(str(file), coverage=coverage)
    return findings, checks, coverage[-1]


@pytest.mark.parametrize(
    "filename", ["agent.mcp.json", "mcp.json", "mcp_config.json", "claude_desktop_config.json"]
)
def test_common_client_filenames_and_declared_scope(tmp_path, filename):
    findings, checks, coverage = _scan(
        tmp_path,
        {"mcpServers": {"public": {"url": "https://example.test/mcp"}}},
        filename,
    )
    assert checks == 1
    assert coverage["files_selected"] == 1
    assert coverage["inputs_selected"] == 1
    assert coverage["status"] == "COMPLETE"
    assert coverage["runtime_permissions_verified"] is False
    assert len(findings) == 1 and findings[0].attack_id == "SC-018"
    assert findings[0].metadata["server_name"] == "public"
    assert findings[0].metadata["runtime_permissions_verified"] is False


def test_stdio_is_not_flagged_for_http_auth_and_never_executed(tmp_path):
    secret = "synthetic-do-not-include-credential"
    marker = tmp_path / "must-not-exist.txt"
    config = {
        "mcpServers": {
            "local": {
                "command": "python",
                "args": ["-c", f"open({str(marker)!r}, 'w').write('executed')"],
                "env": {"API_KEY": secret},
                "tools": [{"name": "run_shell_command", "scopes": ["shell_access"]}],
            },
            "remote": {
                "url": "https://example.test/mcp",
                "headers": {"Authorization": "Bearer " + secret},
                "scopes": ["read_only"],
            },
        }
    }
    with patch("subprocess.run", side_effect=AssertionError("must not execute")):
        findings, checks, coverage = _scan(tmp_path, config)
    assert checks == 2 and coverage["inputs_selected"] == 2
    assert coverage["status"] == "COMPLETE"
    assert not marker.exists()
    assert findings and all(f.attack_id == "SC-020" for f in findings)
    assert all(f.metadata["server_name"] == "local" for f in findings)
    assert secret not in json.dumps([f.model_dump(mode="json") for f in findings])
    assert secret not in json.dumps(coverage)


def test_valid_sibling_findings_survive_malformed_declarations(tmp_path):
    findings, checks, coverage = _scan(
        tmp_path,
        {
            "mcpServers": {
                "remote": {"url": "https://example.test/mcp"},
                "bad": {"command": "python", "url": "https://example.test/mcp"},
                "broken": [],
            }
        },
    )
    assert checks == 1 and coverage["inputs_selected"] == 3
    assert coverage["status"] == "INCONCLUSIVE"
    assert len(findings) == 1 and findings[0].metadata["server_name"] == "remote"
    assert len(coverage["limitations"]) == 2


@pytest.mark.parametrize(
    "server",
    [
        {},
        {"command": "  "},
        {"command": ["python"]},
        {"command": "python", "args": "-m server"},
        {"command": "python", "env": {"KEY": 7}},
        {"url": "https://user:pass@example.test/mcp"},
        {"url": "https://example.test:0/mcp"},
        {"url": "https://example.test:65536/mcp"},
        {"url": "https://example.test/mcp#fragment"},
        {"url": "file:///tmp/mcp"},
        {"url": "https://example.test/\nsecret"},
        {"url": "https://example.test\\other/mcp"},
        {"url": "https://example.test/mcp", "headers": ["secret"]},
        {"url": "https://example.test/mcp", "tools": [{"scopes": None}]},
        {"url": "https://example.test/mcp", "auth": None},
    ],
)
def test_malformed_nested_declarations_are_unassessed(tmp_path, server):
    findings, checks, coverage = _scan(tmp_path, {"mcpServers": {"broken": server}})
    assert findings == [] and checks == 0
    assert coverage["inputs_selected"] == 1
    assert coverage["status"] == "INCONCLUSIVE"


@pytest.mark.parametrize("headers", [[], "Authorization: secret", {"Authorization": 7}])
def test_flat_invalid_headers_are_unassessed_without_crashing(tmp_path, headers):
    findings, checks, coverage = _scan(tmp_path, {"headers": headers})
    assert findings == [] and checks == 0
    assert coverage["status"] == "INCONCLUSIVE"


@pytest.mark.parametrize("auth_type", ["none", "disabled", "anonymous"])
def test_explicitly_disabled_auth_is_flagged(tmp_path, auth_type):
    findings, checks, _ = _scan(tmp_path, {"auth": {"type": auth_type}})
    assert checks == 1
    assert len(findings) == 1 and findings[0].attack_id == "SC-018"


def test_unavailable_capability_policy_withholds_complete_coverage(tmp_path):
    with patch(
        "agentscan.supply_chain.mcp_auditor.load_dangerous_keywords",
        side_effect=OSError("do not include private details"),
    ):
        findings, checks, coverage = _scan(tmp_path, {"auth": {"type": "oauth2"}})
    assert findings == [] and checks == 1
    assert coverage["status"] == "INCONCLUSIVE"
    assert "OSError" in coverage["limitations"][0]
    assert "private details" not in json.dumps(coverage)


def test_directory_discovery_deduplicates_and_ignores_test_environments(tmp_path):
    (tmp_path / "mcp.json").write_text('{"auth": {"type": "oauth2"}}', encoding="utf-8")
    ignored = tmp_path / ".test-tmp"
    ignored.mkdir()
    (ignored / "mcp.json").write_text("invalid", encoding="utf-8")
    coverage: list[dict] = []
    findings, checks = scan_mcp_configs(str(tmp_path), coverage=coverage)
    assert findings == [] and checks == 1
    assert coverage[-1]["files_selected"] == 1
    assert coverage[-1]["status"] == "COMPLETE"


def test_oversized_configuration_is_unassessed(tmp_path):
    file = tmp_path / "mcp.json"
    file.write_text(" " * (1024 * 1024 + 1), encoding="utf-8")
    coverage: list[dict] = []
    findings, checks = scan_mcp_configs(str(file), coverage=coverage)
    assert findings == [] and checks == 0
    assert coverage[-1]["status"] == "INCONCLUSIVE"
