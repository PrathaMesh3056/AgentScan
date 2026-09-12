# tests/test_supply_chain/test_dep_scanner.py
#
# Tests for Dependency Vulnerability Scanner (dep_scanner.py).

from __future__ import annotations

import textwrap
from pathlib import Path

import httpx
import pytest
import respx

from agentscan.supply_chain.dep_scanner import _parse_dependencies, scan_dependencies

_OSV_BASE = "https://api.osv.dev"

_LANGCHAIN_VULN = {
    "id": "GHSA-xxxx-yyyy-zzzz",
    "aliases": ["CVE-2023-34541"],
    "summary": "Arbitrary code execution in langchain.",
    "severity": [{"type": "CVSS_V3", "score": "9.8"}],
    "affected": [
        {
            "package": {"name": "langchain", "ecosystem": "PyPI"},
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}, {"fixed": "0.0.155"}],
                }
            ],
        }
    ],
    "database_specific": {"severity": "CRITICAL"},
}

_REQUESTS_VULN = {
    "id": "OSV-2099-0001",
    "aliases": ["CVE-2099-0001"],
    "summary": "Hypothetical requests vulnerability for testing.",
    "severity": [{"type": "CVSS_V3", "score": "7.5"}],
    "affected": [
        {
            "package": {"name": "requests", "ecosystem": "PyPI"},
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}, {"fixed": "2.1.0"}],
                }
            ],
        }
    ],
}


def _mock_osv_empty(count: int = 1) -> None:
    respx.post(f"{_OSV_BASE}/v1/querybatch").mock(
        return_value=httpx.Response(
            200,
            json={"results": [{"vulns": []} for _ in range(count)]},
        )
    )


def _mock_osv_langchain() -> None:
    respx.post(f"{_OSV_BASE}/v1/querybatch").mock(
        return_value=httpx.Response(
            200,
            json={
                "results": [
                    {
                        "vulns": [
                            {
                                "id": "GHSA-xxxx-yyyy-zzzz",
                                "modified": "2023-06-01T00:00:00Z",
                            }
                        ]
                    }
                ]
            },
        )
    )
    respx.get(f"{_OSV_BASE}/v1/vulns/GHSA-xxxx-yyyy-zzzz").mock(
        return_value=httpx.Response(200, json=_LANGCHAIN_VULN)
    )


def _mock_osv_requests() -> None:
    respx.post(f"{_OSV_BASE}/v1/querybatch").mock(
        return_value=httpx.Response(
            200,
            json={
                "results": [
                    {
                        "vulns": [
                            {
                                "id": "OSV-2099-0001",
                                "modified": "2099-01-01T00:00:00Z",
                            }
                        ]
                    }
                ]
            },
        )
    )
    respx.get(f"{_OSV_BASE}/v1/vulns/OSV-2099-0001").mock(
        return_value=httpx.Response(200, json=_REQUESTS_VULN)
    )


# â”€â”€â”€ Helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


@pytest.fixture
def tmp_req(tmp_path: Path) -> Path:
    """Create a directory with a requirements.txt for testing."""
    return tmp_path


def _write_req(tmp_path: Path, content: str) -> str:
    (tmp_path / "requirements.txt").write_text(textwrap.dedent(content), encoding="utf-8")
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
    (tmp_path / "pyproject.toml").write_text(toml, encoding="utf-8")
    return str(tmp_path)


# â”€â”€â”€ Tests â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


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

    def test_parse_uv_lock(self, tmp_path: Path) -> None:
        """_parse_dependencies reads exact resolved packages from uv.lock."""
        uv_content = """\
version = 1
revision = 1
requires-python = ">=3.12"

[[package]]
name = "langchain"
version = "0.0.154"

[[package]]
name = "pydantic"
version = "2.7.0"
"""
        (tmp_path / "uv.lock").write_text(uv_content, encoding="utf-8")
        deps = _parse_dependencies(str(tmp_path))
        assert ("langchain", "0.0.154") in deps
        assert ("pydantic", "2.7.0") in deps

    def test_parse_poetry_lock(self, tmp_path: Path) -> None:
        """_parse_dependencies reads exact resolved packages from poetry.lock."""
        poetry_content = """\
[[package]]
name = "transformers"
version = "4.29.0"

[[package]]
name = "fastapi"
version = "0.110.0"
"""
        (tmp_path / "poetry.lock").write_text(poetry_content, encoding="utf-8")
        deps = _parse_dependencies(str(tmp_path))
        assert ("transformers", "4.29.0") in deps
        assert ("fastapi", "0.110.0") in deps

    def test_parse_version_ranges(self, tmp_path: Path) -> None:
        """_parse_dependencies extracts PEP 508 specifiers when not exact pins."""
        path = _write_req(
            tmp_path,
            """\
            langchain>=0.0.150,<0.0.160
            requests>=2.28.0
        """,
        )
        deps = _parse_dependencies(path)
        names = [d[0] for d in deps]
        assert "langchain" in names
        assert "requests" in names


class TestScanDependencies:
    @respx.mock
    def test_known_vulnerable_exact_pin_flagged(self, tmp_path: Path) -> None:
        """langchain==0.0.154 (CVE-2023-34541) must produce a SC-001 finding."""
        _mock_osv_langchain()
        path = _write_req(tmp_path, "langchain==0.0.154\n")
        findings, checks_run = scan_dependencies(path)
        assert checks_run == 1
        sc001 = [f for f in findings if f.attack_id == "SC-001"]
        assert len(sc001) == 1
        assert "CVE-2023-34541" in sc001[0].description
        assert sc001[0].metadata.get("source") == "osv"

    @respx.mock
    def test_safe_version_not_flagged(self, tmp_path: Path) -> None:
        """A non-vulnerable pin of langchain must produce no findings."""
        respx.post(f"{_OSV_BASE}/v1/querybatch").mock(
            return_value=httpx.Response(200, json={"results": [{"vulns": []}]})
        )
        path = _write_req(tmp_path, "langchain==0.1.20\n")
        findings, _ = scan_dependencies(path)
        assert len(findings) == 0

    @respx.mock
    def test_unknown_package_not_flagged(self, tmp_path: Path) -> None:
        """A package not in the CVE database must not produce findings."""
        respx.post(f"{_OSV_BASE}/v1/querybatch").mock(
            return_value=httpx.Response(200, json={"results": [{"vulns": []}]})
        )
        path = _write_req(tmp_path, "requests==2.31.0\n")
        findings, _ = scan_dependencies(path)
        assert len(findings) == 0

    @respx.mock
    def test_checks_run_matches_parsed_count(self, tmp_path: Path) -> None:
        """checks_run must equal the number of exact-pin dependencies parsed."""
        _mock_osv_empty(3)
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

    @respx.mock
    def test_connect_error_falls_back_to_yaml(self, tmp_path: Path) -> None:
        """When OSV is unreachable, the offline YAML database is used."""
        respx.post(f"{_OSV_BASE}/v1/querybatch").mock(
            side_effect=httpx.ConnectError("connection refused")
        )
        path = _write_req(tmp_path, "langchain==0.0.154\n")
        findings, _ = scan_dependencies(path)
        assert len(findings) == 1
        assert "CVE-2023-34541" in findings[0].description
        assert findings[0].metadata.get("source") == "offline"

    @respx.mock
    def test_timeout_falls_back_to_yaml(self, tmp_path: Path) -> None:
        """OSV timeout triggers YAML fallback for known vulnerable pins."""
        respx.post(f"{_OSV_BASE}/v1/querybatch").mock(
            side_effect=httpx.TimeoutException("timed out")
        )
        path = _write_req(tmp_path, "langchain==0.0.154\n")
        findings, _ = scan_dependencies(path)
        assert len(findings) == 1
        assert findings[0].metadata.get("source") == "offline"

    @respx.mock
    def test_live_osv_cve_not_in_yaml(self, tmp_path: Path) -> None:
        """A CVE returned by OSV but absent from YAML still produces SC-001."""
        _mock_osv_requests()
        path = _write_req(tmp_path, "requests==2.0.0\n")
        findings, _ = scan_dependencies(path)
        assert len(findings) == 1
        assert "CVE-2099-0001" in findings[0].description
        assert findings[0].metadata.get("source") == "osv"

    def test_range_constraint_vulnerable_flagged(self, tmp_path: Path) -> None:
        """A range constraint permitting vulnerable version (CVE-2023-34541) is flagged."""
        path = _write_req(tmp_path, "langchain<0.0.155\n")
        findings, checks_run = scan_dependencies(path, offline=True)
        assert checks_run == 1
        sc001 = [f for f in findings if f.attack_id == "SC-001"]
        assert len(sc001) == 1
        assert "CVE-2023-34541" in sc001[0].description
        assert sc001[0].metadata.get("source") == "offline_range"

    def test_range_constraint_safe_not_flagged(self, tmp_path: Path) -> None:
        """A range constraint excluding vulnerable versions is not flagged."""
        path = _write_req(tmp_path, "langchain>=0.2.0\n")
        findings, checks_run = scan_dependencies(path, offline=True)
        assert checks_run == 1
        assert len(findings) == 0

    def test_scan_offline_flag(self, tmp_path: Path) -> None:
        """offline=True bypasses network and flags against offline YAML."""
        path = _write_req(tmp_path, "langchain==0.0.154\n")
        findings, checks_run = scan_dependencies(path, offline=True)
        assert checks_run == 1
        assert len(findings) == 1
        assert findings[0].metadata.get("source") == "offline"
