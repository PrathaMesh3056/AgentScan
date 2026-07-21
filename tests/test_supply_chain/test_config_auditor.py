# tests/test_supply_chain/test_config_auditor.py
#
# Tests for agentscan/supply_chain/config_auditor.py
# 5 tests: torch.load without weights_only, torch.load WITH it, allow_dangerous_deserialization,
#          DEBUG=True, and clean file → no findings.

from __future__ import annotations

import textwrap
from pathlib import Path

from agentscan.supply_chain.config_auditor import scan_config

# ── Helpers ────────────────────────────────────────────────────────────────────


def _write_py(tmp_path: Path, filename: str, code: str) -> str:
    (tmp_path / filename).write_text(textwrap.dedent(code))
    return str(tmp_path)


# ── Tests ─────────────────────────────────────────────────────────────────────


class TestConfigAuditor:
    def test_torch_load_without_weights_only_flagged(self, tmp_path: Path) -> None:
        """torch.load() without weights_only=True must produce a SC-011 CRITICAL finding."""
        _write_py(
            tmp_path,
            "bad.py",
            """\
            import torch
            model = torch.load("weights.pt")
            """,
        )
        findings, checks_run = scan_config(str(tmp_path))
        assert checks_run == 1
        sc011 = [f for f in findings if f.attack_id == "SC-011"]
        assert len(sc011) >= 1
        assert sc011[0].severity.value == "CRITICAL"

    def test_torch_load_with_weights_only_not_flagged(self, tmp_path: Path) -> None:
        """torch.load(weights_only=True) must NOT produce findings."""
        _write_py(
            tmp_path,
            "safe.py",
            """\
            import torch
            model = torch.load("weights.pt", weights_only=True)
            """,
        )
        findings, _ = scan_config(str(tmp_path))
        sc011 = [f for f in findings if f.attack_id == "SC-011"]
        assert len(sc011) == 0

    def test_allow_dangerous_deserialization_flagged(self, tmp_path: Path) -> None:
        """allow_dangerous_deserialization=True on any call must produce SC-011 CRITICAL."""
        _write_py(
            tmp_path,
            "danger.py",
            """\
            from langchain.document_loaders import SomeLoader
            loader = SomeLoader("file.pdf", allow_dangerous_deserialization=True)
            """,
        )
        findings, _ = scan_config(str(tmp_path))
        sc011 = [f for f in findings if f.attack_id == "SC-011"]
        assert len(sc011) >= 1
        assert sc011[0].severity.value == "CRITICAL"

    def test_debug_true_flagged(self, tmp_path: Path) -> None:
        """Module-level DEBUG = True must produce a SC-014 HIGH finding."""
        _write_py(
            tmp_path,
            "settings.py",
            """\
            DEBUG = True
            """,
        )
        findings, _ = scan_config(str(tmp_path))
        sc014 = [f for f in findings if f.attack_id == "SC-014"]
        assert len(sc014) == 1
        assert sc014[0].severity.value == "HIGH"

    def test_clean_file_produces_no_findings(self, tmp_path: Path) -> None:
        """A file with no dangerous patterns must produce zero findings."""
        _write_py(
            tmp_path,
            "clean.py",
            """\
            import torch
            model = torch.load("weights.pt", weights_only=True)
            DEBUG = False
            """,
        )
        findings, _ = scan_config(str(tmp_path))
        assert len(findings) == 0
