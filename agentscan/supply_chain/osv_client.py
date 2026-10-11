"""OSV lookups with complete batch/page coverage and version-specific fixes.

References: https://google.github.io/osv.dev/post-v1-querybatch/
https://github.com/RedHatProductSecurity/cvss
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

import httpx
from cvss import CVSS2, CVSS3, CVSS4
from cvss.exceptions import CVSSError
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from agentscan.core.models import Severity

_BASE_URL = "https://api.osv.dev"
_TIMEOUT = 10.0
_ECOSYSTEM = "PyPI"
_MAX_BATCH = 1000
_MAX_PAGES = 100


class OsvUnavailableError(Exception):
    """Incomplete live lookup; callers must report fallback coverage."""


@dataclass(frozen=True)
class OsvVuln:
    osv_id: str
    cve_id: str
    summary: str
    severity: Severity
    fix_version: str
    severity_known: bool = True


def _cvss_score(value: str) -> float | None:
    try:
        if value.startswith("CVSS:4."):
            score = float(CVSS4(value).scores()[0])
        elif value.startswith("CVSS:3."):
            score = float(CVSS3(value).scores()[0])
        elif value.startswith("AV:"):
            score = float(CVSS2(value).scores()[0])
        else:
            score = float(value)
        return score if math.isfinite(score) and 0 <= score <= 10 else None
    except (ValueError, TypeError, KeyError, CVSSError):
        return None


def _parse_cvss_severity(score_str: str) -> Severity:
    score = _cvss_score(score_str)
    if score is None:
        return Severity.INFO
    return (
        Severity.CRITICAL
        if score >= 9
        else Severity.HIGH
        if score >= 7
        else Severity.MEDIUM
        if score >= 4
        else Severity.LOW
        if score > 0
        else Severity.INFO
    )


def _severity(vuln: dict[str, Any]) -> tuple[Severity, bool]:
    db = vuln.get("database_specific") or {}
    raw = str(db.get("severity", "")).upper() if isinstance(db, dict) else ""
    raw = "MEDIUM" if raw == "MODERATE" else raw
    if raw in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
        return Severity(raw), True
    scores = [
        score
        for entry in vuln.get("severity") or []
        if isinstance(entry, dict)
        and (score := _cvss_score(str(entry.get("score", "")))) is not None
    ]
    return (_parse_cvss_severity(str(max(scores))), True) if scores else (Severity.INFO, False)


def _map_severity(vuln: dict[str, Any]) -> Severity:
    return _severity(vuln)[0]


def _extract_cve_id(vuln: dict[str, Any]) -> str:
    return next(
        (a for a in vuln.get("aliases") or [] if isinstance(a, str) and a.startswith("CVE-")),
        str(vuln.get("id", "unknown")),
    )


def _extract_fix_version(vuln: dict[str, Any], name: str = "", version: str = "") -> str:
    if not name or not version:
        return "unknown"
    try:
        installed = Version(version)
    except InvalidVersion:
        return "unknown"
    candidates: list[Version] = []
    for affected in vuln.get("affected") or []:
        package = affected.get("package") or {}
        if package.get("ecosystem") != _ECOSYSTEM or canonicalize_name(
            str(package.get("name", ""))
        ) != canonicalize_name(name):
            continue
        for interval in affected.get("ranges") or []:
            if interval.get("type") not in {"ECOSYSTEM", "SEMVER"}:
                continue
            introduced: Version | None = None
            opened = False
            for event in interval.get("events") or []:
                try:
                    if "introduced" in event:
                        introduced = (
                            None if event["introduced"] == "0" else Version(event["introduced"])
                        )
                        opened = True
                    elif "fixed" in event:
                        fixed = Version(event["fixed"])
                        if (
                            opened
                            and (introduced is None or introduced <= installed)
                            and installed < fixed
                        ):
                            candidates.append(fixed)
                        opened = False
                    elif "last_affected" in event or "limit" in event:
                        opened = False
                except (InvalidVersion, TypeError):
                    opened = False
    return str(min(candidates)) if candidates else "unknown"


def _parse_vuln(vuln: dict[str, Any], name: str = "", version: str = "") -> OsvVuln:
    severity, known = _severity(vuln)
    return OsvVuln(
        str(vuln.get("id", "unknown")),
        _extract_cve_id(vuln),
        str(vuln.get("summary") or "No summary available.").strip(),
        severity,
        _extract_fix_version(vuln, name, version),
        known,
    )


def _json(response: httpx.Response) -> dict[str, Any]:
    if response.status_code >= 400:
        raise OsvUnavailableError(f"OSV returned HTTP {response.status_code}")
    try:
        data = response.json()
        if not isinstance(data, dict):
            raise ValueError("Object required")
        return data
    except (ValueError, TypeError) as exc:
        raise OsvUnavailableError("Invalid OSV response.") from exc


async def query(name: str, version: str, client: httpx.AsyncClient | None = None) -> list[OsvVuln]:
    if client is None:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as owned:
            return await query(name, version, owned)
    payload: dict[str, Any] = {
        "package": {"name": name, "ecosystem": _ECOSYSTEM},
        "version": version,
    }
    found: dict[str, OsvVuln] = {}
    seen: set[str] = set()
    try:
        for _ in range(_MAX_PAGES):
            data = _json(await client.post(f"{_BASE_URL}/v1/query", json=payload))
            for vuln in data.get("vulns") or []:
                if not isinstance(vuln, dict) or not vuln.get("id"):
                    raise OsvUnavailableError("Invalid OSV vulnerability record.")
                found[str(vuln["id"])] = _parse_vuln(vuln, name, version)
            token = data.get("next_page_token")
            if not token:
                return list(found.values())
            if not isinstance(token, str) or token in seen:
                raise OsvUnavailableError("Invalid OSV pagination.")
            seen.add(token)
            payload["page_token"] = token
    except httpx.HTTPError as exc:
        raise OsvUnavailableError("OSV network lookup failed.") from exc
    raise OsvUnavailableError("OSV page limit exceeded; lookup incomplete.")


async def _hydrate_vuln(vuln_id: str, client: httpx.AsyncClient) -> dict[str, Any]:
    return _json(await client.get(f"{_BASE_URL}/v1/vulns/{quote(vuln_id, safe='')}"))


async def querybatch(
    packages: list[tuple[str, str]], client: httpx.AsyncClient | None = None
) -> list[tuple[str, str, OsvVuln]]:
    if not packages:
        return []
    if client is None:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as owned:
            return await querybatch(packages, owned)
    findings: list[tuple[str, str, OsvVuln]] = []
    hydrated: dict[str, dict[str, Any]] = {}
    try:
        for start in range(0, len(packages), _MAX_BATCH):
            batch = packages[start : start + _MAX_BATCH]
            queries = [
                {"package": {"name": name, "ecosystem": _ECOSYSTEM}, "version": ver}
                for name, ver in batch
            ]
            data = _json(await client.post(f"{_BASE_URL}/v1/querybatch", json={"queries": queries}))
            results = data.get("results")
            if not isinstance(results, list) or len(results) != len(batch):
                raise OsvUnavailableError("OSV batch coverage is incomplete.")
            for (name, version), result in zip(batch, results, strict=True):
                if not isinstance(result, dict):
                    raise OsvUnavailableError("Invalid OSV batch result.")
                if result.get("next_page_token"):
                    findings.extend((name, version, v) for v in await query(name, version, client))
                    continue
                for stub in result.get("vulns") or []:
                    if not isinstance(stub, dict) or not isinstance(stub.get("id"), str):
                        raise OsvUnavailableError("Invalid OSV batch record.")
                    vid = stub["id"]
                    if vid not in hydrated:
                        hydrated[vid] = await _hydrate_vuln(vid, client)
                    findings.append((name, version, _parse_vuln(hydrated[vid], name, version)))
    except httpx.HTTPError as exc:
        raise OsvUnavailableError("OSV network lookup failed.") from exc
    return findings
