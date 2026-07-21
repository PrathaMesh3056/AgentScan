# agentscan/supply_chain/typosquat_detector.py
#
# Typosquatting detection for AI package dependencies.
#
# Reuses dep_scanner._parse_dependencies() — no duplicate file parsing.
# Matches installed package names (case-insensitive) against known_typosquats.yaml.

from __future__ import annotations

from pathlib import Path

import yaml
from loguru import logger

from agentscan.core.models import Finding, Severity
from agentscan.supply_chain.dep_scanner import _parse_dependencies

# ── Paths ─────────────────────────────────────────────────────────────────────

_TYPOSQUAT_DB = Path(__file__).parent / "known_typosquats.yaml"


# ── Data loading ──────────────────────────────────────────────────────────────


def _load_typosquats() -> dict[str, str]:
    """Load malicious_name -> legitimate_name mapping from YAML."""
    try:
        with open(_TYPOSQUAT_DB, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        raw: dict[str, str] = data.get("typosquats", {})
        # Normalise keys to lowercase
        return {k.lower(): v for k, v in raw.items()}
    except Exception as e:
        logger.error(f"Failed to load typosquat database: {e}")
        return {}


# ── Public scanner ────────────────────────────────────────────────────────────


def scan_typosquats(path: str) -> tuple[list[Finding], int]:
    """
    Detect typosquatted AI packages in `path`'s dependencies.

    Reuses _parse_dependencies() — does not re-parse pyproject.toml /
    requirements.txt separately.

    Returns:
        (findings, checks_run) where checks_run = number of dependencies parsed.
    """
    deps = _parse_dependencies(path)
    checks_run = len(deps)

    typosquat_map = _load_typosquats()
    findings: list[Finding] = []

    for pkg, ver in deps:
        pkg_lower = pkg.lower()
        legitimate = typosquat_map.get(pkg_lower)
        if legitimate is None:
            continue

        findings.append(
            Finding(
                attack_id="SC-006",
                attack_name="Typosquatted package detected",
                severity=Severity.CRITICAL,
                owasp_id="LLM05",
                description=(
                    f"Package '{pkg}=={ver}' appears to be a typosquatted version of "
                    f"'{legitimate}'. This is a known supply-chain attack vector — "
                    f"the package may contain malicious code."
                ),
                evidence=f"installed={pkg}=={ver}, legitimate_package={legitimate}",
                remediation=(
                    f"Uninstall '{pkg}' immediately and replace with '{legitimate}'. "
                    f"Audit your environment for signs of compromise."
                ),
                metadata={
                    "malicious_package": pkg,
                    "version": ver,
                    "legitimate_package": legitimate,
                },
            )
        )

    return findings, checks_run
