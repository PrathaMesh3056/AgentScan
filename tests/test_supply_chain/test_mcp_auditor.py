# tests/test_supply_chain/test_mcp_auditor.py
#
# Tests for agentscan/supply_chain/mcp_auditor.py
# 3 tests: missing auth flagged, dangerous keyword scope flagged,
#          clean/authenticated config → no findings.

from __future__ import annotations

import json
from pathlib import Path

from agentscan.supply_chain.mcp_auditor import scan_mcp_configs

# ── Helpers ────────────────────────────────────────────────────────────────────


def _write_mcp(tmp_path: Path, filename: str, config: dict) -> str:  # type: ignore[type-arg]
    (tmp_path / filename).write_text(json.dumps(config))
    return str(tmp_path)


# ── Tests ─────────────────────────────────────────────────────────────────────


class TestMcpAuditor:
    def test_missing_auth_flagged(self, tmp_path: Path) -> None:
        """MCP config missing 'auth' key must produce a SC-018 HIGH finding."""
        _write_mcp(
            tmp_path,
            "noauth.mcp.json",
            {"name": "my-server", "tools": []},
        )
        findings, checks_run = scan_mcp_configs(str(tmp_path))
        assert checks_run == 1
        sc018 = [f for f in findings if f.attack_id == "SC-018"]
        assert len(sc018) == 1
        assert sc018[0].severity.value == "HIGH"

    def test_dangerous_keyword_scope_flagged(self, tmp_path: Path) -> None:
        """A tool scope matching the imported dangerous keyword list must produce SC-020 CRITICAL."""
        _write_mcp(
            tmp_path,
            "danger.mcp.json",
            {
                "name": "risky-server",
                "auth": {"type": "api_key"},
                "tools": [
                    {
                        "name": "run_shell_command",
                        "scopes": ["shell_access"],
                    }
                ],
            },
        )
        findings, _ = scan_mcp_configs(str(tmp_path))
        sc020 = [f for f in findings if f.attack_id == "SC-020"]
        assert len(sc020) >= 1
        assert sc020[0].severity.value == "CRITICAL"

    def test_clean_authenticated_config_no_findings(self, tmp_path: Path) -> None:
        """A properly authenticated MCP config with safe tools must produce zero findings."""
        _write_mcp(
            tmp_path,
            "clean.mcp.json",
            {
                "name": "safe-server",
                "auth": {"type": "oauth2"},
                "tools": [
                    {
                        "name": "read_document",
                        "scopes": ["read_customer_data"],
                    }
                ],
            },
        )
        findings, _ = scan_mcp_configs(str(tmp_path))
        assert len(findings) == 0
