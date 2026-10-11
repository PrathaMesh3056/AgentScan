# tests/test_supply_chain/test_osv_client.py
#
# Tests for agentscan/supply_chain/osv_client.py

from __future__ import annotations

import httpx
import pytest
import respx

from agentscan.core.models import Severity
from agentscan.supply_chain.osv_client import (
    OsvUnavailableError,
    _extract_fix_version,
    _parse_vuln,
    query,
    querybatch,
)

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


def test_cvss_vectors_unknown_and_moderate_severity_are_distinct():
    critical = _parse_vuln(
        {"severity": [{"score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}
    )
    low = _parse_vuln({"severity": [{"score": "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"}]})
    unknown = _parse_vuln({"severity": [{"score": "CVSS:3.1/INVALID"}]})
    moderate = _parse_vuln({"database_specific": {"severity": "MODERATE"}})
    assert critical.severity == Severity.CRITICAL and low.severity == Severity.LOW
    assert unknown.severity == Severity.INFO and unknown.severity_known is False
    assert moderate.severity == Severity.MEDIUM


def test_fix_version_matches_package_and_installed_release_branch():
    record = {
        "affected": [
            {
                "package": {"name": "unrelated", "ecosystem": "PyPI"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "9.0"}]}
                ],
            },
            {
                "package": {"name": "owned", "ecosystem": "PyPI"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [
                            {"introduced": "1.0"},
                            {"fixed": "1.5"},
                            {"introduced": "2.0"},
                            {"fixed": "2.5"},
                        ],
                    }
                ],
            },
        ]
    }
    assert _extract_fix_version(record, "owned", "2.2") == "2.5"
    assert _extract_fix_version(record, "owned", "1.2") == "1.5"
    assert _extract_fix_version(record, "owned", "1.8") == "unknown"
    assert _extract_fix_version(record, "missing", "1.2") == "unknown"


async def test_all_1001_packages_and_paginated_batch_hits_are_assessed():
    import json

    batches, pages = [], []

    def response(request):
        body = json.loads(request.content) if request.method == "POST" else {}
        if request.url.path.endswith("querybatch"):
            count = len(body["queries"])
            batches.append(count)
            results = [{} for _ in range(count)]
            if count == 1:
                results[0] = {"next_page_token": "more", "vulns": [{"id": "stub"}]}
            return httpx.Response(200, json={"results": results})
        pages.append(body.get("page_token"))
        return httpx.Response(
            200,
            json={
                "vulns": [{"id": "page-two" if body.get("page_token") else "page-one"}],
                **({} if body.get("page_token") else {"next_page_token": "more"}),
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(response)) as client:
        hits = await querybatch([(f"owned-{i}", "1.0") for i in range(1001)], client)
    assert batches == [1000, 1] and pages == [None, "more"]
    assert {hit[2].osv_id for hit in hits} == {"page-one", "page-two"}


async def test_incomplete_batch_is_an_error_instead_of_a_clean_result():
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda req: httpx.Response(200, json={"results": []}))
    ) as client:
        with pytest.raises(OsvUnavailableError, match="coverage"):
            await querybatch([("owned", "1.0")], client)
