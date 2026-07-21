# agentscan/supply_chain/dep_scanner.py
#
# Dependency vulnerability scanner.
#
# Parses exact-pin dependencies from:
#   - pyproject.toml  ([project.dependencies] list, via stdlib tomllib)
#   - requirements.txt (line-by-line, exact-pin regex)
#
# Then cross-references against the bundled known_vulnerabilities.yaml.
#
# v0.1 limitation: only exact-pin matches (package==version). Version-range
# matching (>=, ~=, <) requires the `packaging` library — documented future add.

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import yaml
from loguru import logger

from agentscan.core.models import Finding, Severity

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


# ── Public scanner ────────────────────────────────────────────────────────────


def scan_dependencies(path: str) -> tuple[list[Finding], int]:
    """
    Scan dependencies in `path` against the bundled CVE database.

    Returns:
        (findings, checks_run) where checks_run = number of dependencies parsed.
    """
    deps = _parse_dependencies(path)
    checks_run = len(deps)

    vuln_db = _load_vuln_db()
    # Build lookup: (package_lower, version) -> vuln entry
    vuln_index: dict[tuple[str, str], dict[str, object]] = {}
    for entry in vuln_db:
        key = (str(entry["package"]).lower(), str(entry["bad_version"]))
        vuln_index[key] = entry

    findings: list[Finding] = []
    for pkg, ver in deps:
        matched: dict[str, object] | None = vuln_index.get((pkg.lower(), ver))
        if matched is None:
            continue

        sev = Severity(str(matched["severity"]).upper())
        findings.append(
            Finding(
                attack_id="SC-001",
                attack_name="Known-vulnerable dependency",
                severity=sev,
                owasp_id="LLM05",
                description=(
                    f"Dependency '{pkg}=={ver}' matches {matched['cve_id']}: "
                    f"{str(matched['description']).strip()} "
                    f"Upgrade to >={matched['fix_version']}."
                ),
                evidence=f"package={pkg}, version={ver}, cve={matched['cve_id']}",
                remediation=(
                    f"Upgrade {pkg} to at least {matched['fix_version']}. "
                    f"See https://nvd.nist.gov/vuln/detail/{matched['cve_id']} for details."
                ),
                metadata={
                    "package": pkg,
                    "version": ver,
                    "cve_id": matched["cve_id"],
                    "fix_version": matched["fix_version"],
                },
            )
        )

    return findings, checks_run
