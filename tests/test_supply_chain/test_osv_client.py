# tests/test_supply_chain/test_osv_client.py
#
# Tests for agentscan/supply_chain/osv_client.py

from __future__ import annotations

import httpx
import pytest
import respx

from agentscan.core.models import Severity
from agentscan.supply_chain.osv_client import OsvUnavailableError, query, querybatch

_OSV_BASE = "https://api.osv.dev"

_LANGCHAIN_VULN = {
    "id": "GHSA-xxxx-yyyy-zzzz",
    "aliases": ["CVE-2023-34541"],
    "summary": "Arbitrary code execution via eval() in LLMMathChain.",
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


class TestOsvQuery:
    @respx.mock
    async def test_query_maps_full_vuln(self) -> None:
        respx.post(f"{_OSV_BASE}/v1/query").mock(
            return_value=httpx.Response(200, json={"vulns": [_LANGCHAIN_VULN]})
        )
        vulns = await query("langchain", "0.0.154")
        assert len(vulns) == 1
        assert vulns[0].cve_id == "CVE-2023-34541"
        assert vulns[0].osv_id == "GHSA-xxxx-yyyy-zzzz"
        assert vulns[0].severity == Severity.CRITICAL
        assert vulns[0].fix_version == "0.0.155"
        assert "eval()" in vulns[0].summary


class TestOsvQuerybatch:
    @respx.mock
    async def test_querybatch_hydrates_vuln_ids(self) -> None:
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

        hits = await querybatch([("langchain", "0.0.154")])
        assert len(hits) == 1
        pkg, ver, vuln = hits[0]
        assert pkg == "langchain"
        assert ver == "0.0.154"
        assert vuln.cve_id == "CVE-2023-34541"
        assert vuln.fix_version == "0.0.155"


class TestOsvUnavailable:
    @respx.mock
    async def test_timeout_raises_unavailable(self) -> None:
        respx.post(f"{_OSV_BASE}/v1/query").mock(side_effect=httpx.TimeoutException("timed out"))
        with pytest.raises(OsvUnavailableError):
            await query("langchain", "0.0.154")

    @respx.mock
    async def test_503_raises_unavailable(self) -> None:
        respx.post(f"{_OSV_BASE}/v1/querybatch").mock(
            return_value=httpx.Response(503, json={"error": "unavailable"})
        )
        with pytest.raises(OsvUnavailableError):
            await querybatch([("langchain", "0.0.154")])
