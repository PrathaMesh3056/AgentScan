# tests/test_supply_chain/test_dep_scanner.py
#
# Tests for agentscan/supply_chain/dep_scanner.py
# 6 tests covering parsing and CVE matching.

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from agentscan.supply_chain.dep_scanner import _parse_dependencies, scan_dependencies

# ── Helpers ────────────────────────────────────────────────────────────────────


@pytest.fixture
def tmp_req(tmp_path: Path) -> Path:
    """Create a directory with a requirements.txt for testing."""
    return tmp_path


def _write_req(tmp_path: Path, content: str) -> str:
    (tmp_path / "requirements.txt").write_text(textwrap.dedent(content))
    return str(tmp_path)


def _write_pyproject(tmp_path: Path, deps: list[str]) -> str:
    deps_toml = "\n".join(f'  "{d}",' for d in deps)
    toml = f"""
[project]
name = "test-project"
version = "0.1.0"
dependencies = [
{deps_toml}
]
"""
    (tmp_path / "pyproject.toml").write_text(toml)
    return str(tmp_path)


# ── Tests ─────────────────────────────────────────────────────────────────────


class TestParseDependencies:
    def test_parse_requirements_txt(self, tmp_path: Path) -> None:
        """_parse_dependencies reads exact pins from requirements.txt."""
        path = _write_req(
            tmp_path,
            """\
            langchain==0.0.154
            openai==1.30.0
        """,
        )
        deps = _parse_dependencies(path)
        assert ("langchain", "0.0.154") in deps
        assert ("openai", "1.30.0") in deps

    def test_parse_pyproject_toml(self, tmp_path: Path) -> None:
        """_parse_dependencies reads exact pins from pyproject.toml."""
        path = _write_pyproject(tmp_path, ["langchain==0.1.0", "pydantic==2.7.0"])
        deps = _parse_dependencies(path)
        assert ("langchain", "0.1.0") in deps
        assert ("pydantic", "2.7.0") in deps


class TestScanDependencies:
    def test_known_vulnerable_exact_pin_flagged(self, tmp_path: Path) -> None:
        """langchain==0.0.154 (CVE-2023-34541) must produce a SC-001 finding."""
        path = _write_req(tmp_path, "langchain==0.0.154\n")
        findings, checks_run = scan_dependencies(path)
        assert checks_run == 1
        sc001 = [f for f in findings if f.attack_id == "SC-001"]
        assert len(sc001) == 1
        assert "CVE-2023-34541" in sc001[0].description

    def test_safe_version_not_flagged(self, tmp_path: Path) -> None:
        """A non-vulnerable pin of langchain must produce no findings."""
        path = _write_req(tmp_path, "langchain==0.1.20\n")
        findings, _ = scan_dependencies(path)
        assert len(findings) == 0

    def test_unknown_package_not_flagged(self, tmp_path: Path) -> None:
        """A package not in the CVE database must not produce findings."""
        path = _write_req(tmp_path, "requests==2.31.0\n")
        findings, _ = scan_dependencies(path)
        assert len(findings) == 0

    def test_checks_run_matches_parsed_count(self, tmp_path: Path) -> None:
        """checks_run must equal the number of exact-pin dependencies parsed."""
        path = _write_req(
            tmp_path,
            """\
            langchain==0.0.154
            openai==1.30.0
            pydantic==2.7.0
        """,
        )
        _, checks_run = scan_dependencies(path)
        assert checks_run == 3
