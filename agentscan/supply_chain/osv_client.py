# agentscan/supply_chain/osv_client.py
#
# Async client for the OSV.dev vulnerability API (PyPI ecosystem).
# Used by dep_scanner.py for live CVE lookups with offline YAML fallback.

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx
from loguru import logger

from agentscan.core.models import Severity

_BASE_URL = "https://api.osv.dev"
_TIMEOUT = 10.0
_ECOSYSTEM = "PyPI"
_MAX_BATCH = 1000


class OsvUnavailableError(Exception):
    """Raised when the OSV API cannot be reached or returns a server error."""


@dataclass(frozen=True)
class OsvVuln:
    """Normalised vulnerability record from OSV.dev."""

    osv_id: str
    cve_id: str
    summary: str
    severity: Severity
    fix_version: str


def _parse_cvss_severity(score_str: str) -> Severity:
    try:
        score = float(score_str)
    except (TypeError, ValueError):
        return Severity.HIGH
    if score >= 9:
        return Severity.CRITICAL
    if score >= 7:
        return Severity.HIGH
    if score >= 4:
        return Severity.MEDIUM
    return Severity.LOW


def _map_severity(vuln: dict[str, Any]) -> Severity:
    db_specific = vuln.get("database_specific") or {}
    raw = str(db_specific.get("severity", "")).upper()
    if raw in Severity.__members__:
        return Severity(raw)

    for entry in vuln.get("severity") or []:
        if isinstance(entry, dict) and entry.get("score"):
            return _parse_cvss_severity(str(entry["score"]))

    return Severity.HIGH


def _extract_cve_id(vuln: dict[str, Any]) -> str:
    osv_id = str(vuln.get("id", "unknown"))
    for alias in vuln.get("aliases") or []:
        if isinstance(alias, str) and alias.startswith("CVE-"):
            return alias
    return osv_id


def _extract_fix_version(vuln: dict[str, Any]) -> str:
    for affected in vuln.get("affected") or []:
        for range_entry in affected.get("ranges") or []:
            for event in range_entry.get("events") or []:
                if isinstance(event, dict) and "fixed" in event:
                    return str(event["fixed"])
    return "unknown"


def _parse_vuln(vuln: dict[str, Any]) -> OsvVuln:
    osv_id = str(vuln.get("id", "unknown"))
    return OsvVuln(
        osv_id=osv_id,
        cve_id=_extract_cve_id(vuln),
        summary=str(vuln.get("summary") or "No summary available.").strip(),
        severity=_map_severity(vuln),
        fix_version=_extract_fix_version(vuln),
    )


def _raise_on_bad_response(response: httpx.Response) -> None:
    if response.status_code >= 500:
        raise OsvUnavailableError(f"OSV API returned {response.status_code}")
    if response.status_code >= 400:
        raise OsvUnavailableError(f"OSV API returned {response.status_code}")


async def query(name: str, version: str, client: httpx.AsyncClient | None = None) -> list[OsvVuln]:
    """Query OSV for a single PyPI package version. Returns full vuln records."""
    payload = {
        "package": {"name": name, "ecosystem": _ECOSYSTEM},
        "version": version,
    }
    try:
        if client is None:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as owned:
                response = await owned.post(f"{_BASE_URL}/v1/query", json=payload)
        else:
            response = await client.post(f"{_BASE_URL}/v1/query", json=payload)
    except (httpx.ConnectError, httpx.TimeoutException) as exc:
        raise OsvUnavailableError(str(exc)) from exc

    _raise_on_bad_response(response)
    data = response.json()
    vulns = data.get("vulns") or []
    return [_parse_vuln(v) for v in vulns if isinstance(v, dict)]


async def _hydrate_vuln(vuln_id: str, client: httpx.AsyncClient) -> dict[str, Any]:
    try:
        response = await client.get(f"{_BASE_URL}/v1/vulns/{vuln_id}")
    except (httpx.ConnectError, httpx.TimeoutException) as exc:
        raise OsvUnavailableError(str(exc)) from exc

    _raise_on_bad_response(response)
    data = response.json()
    if not isinstance(data, dict):
        raise OsvUnavailableError(f"Unexpected OSV response for {vuln_id}")
    return data


async def querybatch(
    packages: list[tuple[str, str]],
    client: httpx.AsyncClient | None = None,
) -> list[tuple[str, str, OsvVuln]]:
    """
    Batch-query OSV for many (name, version) pairs.

    Hydrates stub batch hits via GET /v1/vulns/{id} (deduped).
    Returns (package, version, OsvVuln) tuples — one per matched vuln.
    """
    if not packages:
        return []

    queries = [
        {"package": {"name": name, "ecosystem": _ECOSYSTEM}, "version": version}
        for name, version in packages[:_MAX_BATCH]
    ]

    try:
        if client is None:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as owned:
                return await _querybatch_with_client(queries, packages[:_MAX_BATCH], owned)
        return await _querybatch_with_client(queries, packages[:_MAX_BATCH], client)
    except OsvUnavailableError:
        raise
    except (httpx.ConnectError, httpx.TimeoutException) as exc:
        raise OsvUnavailableError(str(exc)) from exc


async def _querybatch_with_client(
    queries: list[dict[str, Any]],
    packages: list[tuple[str, str]],
    client: httpx.AsyncClient,
) -> list[tuple[str, str, OsvVuln]]:
    try:
        response = await client.post(f"{_BASE_URL}/v1/querybatch", json={"queries": queries})
    except (httpx.ConnectError, httpx.TimeoutException) as exc:
        raise OsvUnavailableError(str(exc)) from exc

    _raise_on_bad_response(response)
    data = response.json()
    results = data.get("results") or []

    # Collect vuln ids per package index, then hydrate once.
    per_pkg_ids: list[list[str]] = []
    all_ids: set[str] = set()
    for result in results:
        ids: list[str] = []
        for stub in (result.get("vulns") or []) if isinstance(result, dict) else []:
            if isinstance(stub, dict) and stub.get("id"):
                vid = str(stub["id"])
                ids.append(vid)
                all_ids.add(vid)
        per_pkg_ids.append(ids)

    hydrated: dict[str, OsvVuln] = {}
    for vuln_id in all_ids:
        try:
            hydrated[vuln_id] = _parse_vuln(await _hydrate_vuln(vuln_id, client))
        except OsvUnavailableError:
            logger.warning(f"Failed to hydrate OSV record {vuln_id}")
            raise

    findings: list[tuple[str, str, OsvVuln]] = []
    for (pkg, ver), ids in zip(packages, per_pkg_ids, strict=False):
        for vid in ids:
            if vid in hydrated:
                findings.append((pkg, ver, hydrated[vid]))
    return findings
