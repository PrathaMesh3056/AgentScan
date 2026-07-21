# tests/test_supply_chain/test_typosquat_detector.py
#
# Tests for agentscan/supply_chain/typosquat_detector.py
# 3 tests: known typosquat flagged, legitimate name not flagged, case-insensitive match.

from __future__ import annotations

import textwrap
from pathlib import Path

from agentscan.supply_chain.typosquat_detector import scan_typosquats

# ── Helpers ────────────────────────────────────────────────────────────────────


def _write_req(tmp_path: Path, content: str) -> str:
    (tmp_path / "requirements.txt").write_text(textwrap.dedent(content))
    return str(tmp_path)


# ── Tests ─────────────────────────────────────────────────────────────────────


class TestScanTyposquats:
    def test_known_typosquat_flagged_critical(self, tmp_path: Path) -> None:
        """'langchian' is a known typosquat of 'langchain' — must produce SC-006 CRITICAL."""
        path = _write_req(tmp_path, "langchian==0.0.1\n")
        findings, _ = scan_typosquats(path)
        sc006 = [f for f in findings if f.attack_id == "SC-006"]
        assert len(sc006) == 1
        assert sc006[0].severity.value == "CRITICAL"
        assert "langchain" in sc006[0].description

    def test_legitimate_name_not_flagged(self, tmp_path: Path) -> None:
        """'langchain' (the real package) must not be flagged."""
        path = _write_req(tmp_path, "langchain==0.1.20\n")
        findings, _ = scan_typosquats(path)
        assert len(findings) == 0

    def test_case_insensitive_match(self, tmp_path: Path) -> None:
        """Typosquat detection must be case-insensitive ('LANGCHIAN' matches 'langchian')."""
        path = _write_req(tmp_path, "LANGCHIAN==0.0.1\n")
        findings, _ = scan_typosquats(path)
        sc006 = [f for f in findings if f.attack_id == "SC-006"]
        assert len(sc006) == 1
