# agentscan/supply_chain/dep_scanner.py
#
# Dependency vulnerability scanner.
#
# Parses exact-pin dependencies from:
#   - pyproject.toml  ([project.dependencies] list, via stdlib tomllib)
#   - requirements.txt (line-by-line, exact-pin regex)
#
# Live path: queries OSV.dev (PyPI) via querybatch + per-id hydration.
# Fallback: bundled known_vulnerabilities.yaml on network/API failure.
#
# v0.1 limitation: only exact-pin matches (package==version). Version-range
# matching (>=, ~=, <) requires the `packaging` library — documented future add.

from __future__ import annotations

import asyncio
import re
import tomllib
from pathlib import Path

import yaml
from loguru import logger

from agentscan.core.models import Finding, Severity
from agentscan.supply_chain.osv_client import OsvUnavailableError, OsvVuln, querybatch

# ── Paths ─────────────────────────────────────────────────────────────────────

_VULN_DB = Path(__file__).parent / "known_vulnerabilities.yaml"

# Regex: matches "packagename==1.2.3" lines in requirements.txt
_EXACT_PIN_RE = re.compile(r"^([\w\-]+)==([\d.]+)$")


# ── Dependency parsing ────────────────────────────────────────────────────────


def _parse_dependencies(path: str) -> list[tuple[str, str]]:
    """
    Parse exact-pinned dependencies from a project directory.

    Checks for (in order):
      1. pyproject.toml — reads [project.dependencies]
      2. requirements.txt — reads line by line

    Returns a list of (package_name, version) tuples for exact pins only.
    Non-exact pins (>=, ~=, etc.) are silently skipped in v0.1.

    Exported: typosquat_detector.py imports this to avoid duplicate parsing.
    """
    root = Path(path)
    deps: list[tuple[str, str]] = []

    # ── pyproject.toml ────────────────────────────────────────────────────────
    pyproject = root / "pyproject.toml"
    if pyproject.exists():
        try:
            with open(pyproject, "rb") as f:
                data = tomllib.load(f)
            raw_deps: list[str] = data.get("project", {}).get("dependencies", [])
            for dep_str in raw_deps:
                m = _EXACT_PIN_RE.match(dep_str.strip())
                if m:
                    deps.append((m.group(1).lower(), m.group(2)))
        except Exception as e:
            logger.error(f"Failed to parse pyproject.toml at {pyproject}: {e}")

    # ── requirements.txt ──────────────────────────────────────────────────────
    req_txt = root / "requirements.txt"
    if req_txt.exists():
        try:
            for line in req_txt.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                m = _EXACT_PIN_RE.match(line)
                if m:
                    deps.append((m.group(1).lower(), m.group(2)))
        except Exception as e:
            logger.error(f"Failed to parse requirements.txt at {req_txt}: {e}")

    return deps


# ── Vulnerability database ────────────────────────────────────────────────────


def _load_vuln_db() -> list[dict]:  # type: ignore[type-arg]
    """Load and return the bundled vulnerability database."""
    with open(_VULN_DB, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return data.get("vulnerabilities", [])


def _finding_from_osv(pkg: str, ver: str, vuln: OsvVuln) -> Finding:
    cve = vuln.cve_id
    fix = vuln.fix_version
    return Finding(
        attack_id="SC-001",
        attack_name="Known-vulnerable dependency",
        severity=vuln.severity,
        owasp_id="LLM05",
        description=(
            f"Dependency '{pkg}=={ver}' matches {cve}: {vuln.summary} Upgrade to >={fix}."
        ),
        evidence=f"package={pkg}, version={ver}, cve={cve}, osv={vuln.osv_id}",
        remediation=(
            f"Upgrade {pkg} to at least {fix}. "
            f"See https://nvd.nist.gov/vuln/detail/{cve} for details."
        ),
        metadata={
            "package": pkg,
            "version": ver,
            "cve_id": cve,
            "fix_version": fix,
            "osv_id": vuln.osv_id,
            "source": "osv",
        },
    )


def _finding_from_yaml(pkg: str, ver: str, matched: dict[str, object]) -> Finding:
    sev = Severity(str(matched["severity"]).upper())
    cve = str(matched["cve_id"])
    fix = str(matched["fix_version"])
    return Finding(
        attack_id="SC-001",
        attack_name="Known-vulnerable dependency",
        severity=sev,
        owasp_id="LLM05",
        description=(
            f"Dependency '{pkg}=={ver}' matches {cve}: "
            f"{str(matched['description']).strip()} "
            f"Upgrade to >={fix}."
        ),
        evidence=f"package={pkg}, version={ver}, cve={cve}",
        remediation=(
            f"Upgrade {pkg} to at least {fix}. "
            f"See https://nvd.nist.gov/vuln/detail/{cve} for details."
        ),
        metadata={
            "package": pkg,
            "version": ver,
            "cve_id": cve,
            "fix_version": fix,
            "source": "offline",
        },
    )


async def _scan_live(deps: list[tuple[str, str]]) -> list[Finding]:
    """Query OSV.dev for all parsed dependencies."""
    if not deps:
        return []

    hits = await querybatch(deps)
    return [_finding_from_osv(pkg, ver, vuln) for pkg, ver, vuln in hits]


def _scan_offline(deps: list[tuple[str, str]]) -> list[Finding]:
    """Match dependencies against the bundled YAML database."""
    vuln_db = _load_vuln_db()
    vuln_index: dict[tuple[str, str], dict[str, object]] = {}
    for entry in vuln_db:
        key = (str(entry["package"]).lower(), str(entry["bad_version"]))
        vuln_index[key] = entry

    findings: list[Finding] = []
    for pkg, ver in deps:
        matched = vuln_index.get((pkg.lower(), ver))
        if matched is not None:
            findings.append(_finding_from_yaml(pkg, ver, matched))
    return findings


async def _scan_live_or_fallback(deps: list[tuple[str, str]]) -> list[Finding]:
    try:
        return await _scan_live(deps)
    except OsvUnavailableError as exc:
        logger.warning(f"OSV.dev unavailable, falling back to offline database: {exc}")
        return _scan_offline(deps)


# ── Public scanner ────────────────────────────────────────────────────────────


def scan_dependencies(path: str) -> tuple[list[Finding], int]:
    """
    Scan dependencies in `path` for known CVEs.

    Tries live OSV.dev lookups first; falls back to bundled YAML on failure.
    Returns (findings, checks_run) where checks_run = number of dependencies parsed.
    """
    deps = _parse_dependencies(path)
    checks_run = len(deps)
    findings = asyncio.run(_scan_live_or_fallback(deps))
    return findings, checks_run
