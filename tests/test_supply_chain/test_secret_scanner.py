# tests/test_supply_chain/test_secret_scanner.py
#
# Tests for agentscan/supply_chain/secret_scanner.py
# 4 tests: OpenAI key detected, Anthropic key detected,
#          low-entropy string NOT flagged, clean file → no findings.

from __future__ import annotations

import textwrap
from pathlib import Path

from agentscan.supply_chain.secret_scanner import scan_secrets

# ── Helpers ────────────────────────────────────────────────────────────────────


def _write_file(tmp_path: Path, filename: str, content: str) -> str:
    (tmp_path / filename).write_text(textwrap.dedent(content))
    return str(tmp_path)


# ── Tests ─────────────────────────────────────────────────────────────────────


class TestSecretScanner:
    def test_openai_style_key_detected(self, tmp_path: Path) -> None:
        """A high-entropy OPENAI_API_KEY literal must produce a SC-015 CRITICAL finding."""
        _write_file(
            tmp_path,
            "config.py",
            # Realistic high-entropy OpenAI key format
            'OPENAI_API_KEY = "sk-proj-aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890abcdefghij"\n',
        )
        findings, _ = scan_secrets(str(tmp_path))
        sc015 = [f for f in findings if f.attack_id == "SC-015"]
        assert len(sc015) >= 1
        assert sc015[0].severity.value == "CRITICAL"

    def test_anthropic_style_key_detected(self, tmp_path: Path) -> None:
        """A high-entropy ANTHROPIC_API_SECRET literal must produce a SC-015 CRITICAL finding."""
        _write_file(
            tmp_path,
            "secrets.py",
            'ANTHROPIC_API_SECRET = "sk-ant-api03-xK9mP2nQ8vR4sT6uW0yB5cF7hJ1lN3oAqWe"\n',
        )
        findings, _ = scan_secrets(str(tmp_path))
        sc015 = [f for f in findings if f.attack_id == "SC-015"]
        assert len(sc015) >= 1

    def test_low_entropy_string_not_flagged(self, tmp_path: Path) -> None:
        """Low-entropy values like 'password123' must NOT be flagged (entropy < 3.5)."""
        _write_file(
            tmp_path,
            "bad_pw.py",
            # 'password123' is low-entropy — all lowercase letters + digits, repetitive
            'DEBUG_TOKEN = "password123"\n',
        )
        findings, _ = scan_secrets(str(tmp_path))
        sc015 = [f for f in findings if f.attack_id == "SC-015"]
        assert len(sc015) == 0

    def test_clean_file_no_findings(self, tmp_path: Path) -> None:
        """A file using only os.environ calls must produce zero SC-015 findings."""
        _write_file(
            tmp_path,
            "safe.py",
            """\
            import os
            OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
            ANTHROPIC_API_SECRET = os.environ.get("ANTHROPIC_SECRET", "")
            """,
        )
        findings, _ = scan_secrets(str(tmp_path))
        sc015 = [f for f in findings if f.attack_id == "SC-015"]
        assert len(sc015) == 0
