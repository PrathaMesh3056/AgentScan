# agentscan/supply_chain/dep_scanner.py
#
# Dependency vulnerability scanner.
#
# Parses dependencies from:
#   - uv.lock (exact resolved packages via tomllib)
#   - poetry.lock (exact resolved packages via tomllib)
#   - pyproject.toml ([project.dependencies] & optional-dependencies)
#   - requirements.txt (line-by-line, exact pin or PEP 508 range)
#
# Live path: queries OSV.dev (PyPI) via querybatch for exact pins.
# Specifier ranges: evaluated via packaging.specifiers.SpecifierSet.
# Fallback / Offline: bundled known_vulnerabilities.yaml.

from __future__ import annotations

import asyncio
import re
import tomllib
from pathlib import Path
from typing import Any

import networkx as nx
import yaml
from loguru import logger
from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from agentscan.core.models import Finding, Severity
from agentscan.supply_chain.osv_client import OsvUnavailableError, OsvVuln, querybatch

# â”€â”€â”€ Paths â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

_VULN_DB = Path(__file__).parent / "known_vulnerabilities.yaml"

# Regex fallback: matches "packagename==1.2.3"
_EXACT_PIN_RE = re.compile(r"^([\w\-]+)==([\d.]+)$")


# â”€â”€â”€ Dependency parsing â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


def _parse_requirement_str(dep_str: str) -> tuple[str, str] | None:
    """Parse a requirement string into (package_name, version_or_spec)."""
    try:
        req = Requirement(dep_str)
        spec = str(req.specifier).strip()
        if spec.startswith("==") and "," not in spec:
            ver = spec[2:].strip()
            return (req.name.lower(), ver)
        elif spec:
            return (req.name.lower(), spec)
        else:
            return (req.name.lower(), "*")
    except InvalidRequirement:
        m = _EXACT_PIN_RE.match(dep_str)
        if m:
            return (m.group(1).lower(), m.group(2))
        return None


def _is_exact_version(v: str) -> bool:
    """True if string represents a concrete version rather than an open specifier."""
    if not v or v == "*":
        return False
    if any(c in v for c in ("<", ">", "~", "!", ",", "*")):
        return False
    try:
        Version(v)
        return True
    except InvalidVersion:
        return False


def _parse_dependencies(path: str) -> list[tuple[str, str]]:
    """
    Parse dependencies from a project directory.

    Checks for (in priority order):
      1. uv.lock -> [[package]] name and version (exact resolved transitive dependencies)
      2. poetry.lock -> [[package]] name and version (exact resolved transitive dependencies)
      3. pyproject.toml -> [project.dependencies] and [project.optional-dependencies]
      4. requirements.txt -> line-by-line requirements

    Returns a list of (package_name, version_or_spec) tuples.
    Exported: typosquat_detector.py & aibom.py import this to avoid duplicate parsing.
    """
    root = Path(path)
    deps: list[tuple[str, str]] = []

    # 1. uv.lock
    uv_lock = root / "uv.lock"
    if uv_lock.exists():
        try:
            with open(uv_lock, "rb") as f:
                data = tomllib.load(f)
            packages = data.get("package", [])
            for pkg in packages:
                name = pkg.get("name")
                ver = pkg.get("version")
                if name and ver:
                    deps.append((str(name).lower(), str(ver)))
            if deps:
                return list(dict.fromkeys(deps))
        except Exception as e:
            logger.error(f"Failed to parse uv.lock at {uv_lock}: {e}")

    # 2. poetry.lock
    poetry_lock = root / "poetry.lock"
    if poetry_lock.exists():
        try:
            with open(poetry_lock, "rb") as f:
                data = tomllib.load(f)
            packages = data.get("package", [])
            for pkg in packages:
                name = pkg.get("name")
                ver = pkg.get("version")
                if name and ver:
                    deps.append((str(name).lower(), str(ver)))
            if deps:
                return list(dict.fromkeys(deps))
        except Exception as e:
            logger.error(f"Failed to parse poetry.lock at {poetry_lock}: {e}")

    # 3. pyproject.toml
    pyproject = root / "pyproject.toml"
    if pyproject.exists():
        try:
            with open(pyproject, "rb") as f:
                data = tomllib.load(f)
            project_data = data.get("project", {})
            raw_deps: list[str] = list(project_data.get("dependencies", []))
            opt_deps = project_data.get("optional-dependencies", {})
            for opt_group in opt_deps.values():
                if isinstance(opt_group, list):
                    raw_deps.extend(opt_group)

            for dep_str in raw_deps:
                dep_str = dep_str.strip()
                if not dep_str or dep_str.startswith("#"):
                    continue
                parsed = _parse_requirement_str(dep_str)
                if parsed:
                    deps.append(parsed)
        except Exception as e:
            logger.error(f"Failed to parse pyproject.toml at {pyproject}: {e}")

    # 4. requirements.txt
    req_txt = root / "requirements.txt"
    if req_txt.exists():
        try:
            for line in req_txt.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parsed = _parse_requirement_str(line)
                if parsed:
                    deps.append(parsed)
        except Exception as e:
            logger.error(f"Failed to parse requirements.txt at {req_txt}: {e}")

    return list(dict.fromkeys(deps))


# â”€â”€â”€ Vulnerability database â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


def _load_vuln_db() -> list[dict[str, Any]]:
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


def _finding_from_specifier(
    pkg: str, spec_str: str, bad_ver: str, matched: dict[str, object]
) -> Finding:
    sev = Severity(str(matched["severity"]).upper())
    cve = str(matched["cve_id"])
    fix = str(matched["fix_version"])
    return Finding(
        attack_id="SC-001",
        attack_name="Known-vulnerable dependency",
        severity=sev,
        owasp_id="LLM05",
        description=(
            f"Dependency '{pkg}' constraint '{spec_str}' permits vulnerable version "
            f"'{bad_ver}' ({cve}): {str(matched['description']).strip()} Upgrade constraint to >={fix}."
        ),
        evidence=f"package={pkg}, specifier={spec_str}, permits_vulnerable={bad_ver}, cve={cve}",
        remediation=(
            f"Constrain {pkg} to at least >={fix} in dependencies. "
            f"See https://nvd.nist.gov/vuln/detail/{cve} for details."
        ),
        metadata={
            "package": pkg,
            "specifier": spec_str,
            "vulnerable_version": bad_ver,
            "cve_id": cve,
            "fix_version": fix,
            "source": "offline_range",
        },
    )


def _scan_range_dependencies(range_deps: list[tuple[str, str]]) -> list[Finding]:
    """Evaluate specifier ranges against the offline vulnerability database."""
    vuln_db = _load_vuln_db()
    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()

    for pkg, spec_str in range_deps:
        for entry in vuln_db:
            if str(entry["package"]).lower() != pkg.lower():
                continue
            bad_ver = str(entry["bad_version"])
            cve = str(entry["cve_id"])
            key = (pkg.lower(), bad_ver, cve)
            if key in seen:
                continue

            try:
                spec_set = SpecifierSet(spec_str) if spec_str != "*" else None
                if spec_set is None or spec_set.contains(bad_ver):
                    seen.add(key)
                    findings.append(_finding_from_specifier(pkg, spec_str, bad_ver, entry))
            except InvalidSpecifier:
                pass

    return findings


async def _scan_live(deps: list[tuple[str, str]]) -> list[Finding]:
    """Query OSV.dev for exact dependencies, and evaluate ranges against vuln DB."""
    if not deps:
        return []

    exact_deps: list[tuple[str, str]] = []
    range_deps: list[tuple[str, str]] = []

    for pkg, ver_or_spec in deps:
        if _is_exact_version(ver_or_spec):
            exact_deps.append((pkg, ver_or_spec))
        else:
            range_deps.append((pkg, ver_or_spec))

    findings: list[Finding] = []

    if exact_deps:
        hits = await querybatch(exact_deps)
        findings.extend([_finding_from_osv(pkg, ver, vuln) for pkg, ver, vuln in hits])

    if range_deps:
        findings.extend(_scan_range_dependencies(range_deps))

    return findings


def _scan_offline(deps: list[tuple[str, str]]) -> list[Finding]:
    """Match dependencies against the bundled YAML database."""
    vuln_db = _load_vuln_db()
    vuln_index: dict[str, list[dict[str, Any]]] = {}
    for entry in vuln_db:
        pkg_name = str(entry["package"]).lower()
        vuln_index.setdefault(pkg_name, []).append(entry)

    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()

    for pkg, ver_or_spec in deps:
        entries = vuln_index.get(pkg.lower(), [])
        if not entries:
            continue

        for entry in entries:
            bad_ver = str(entry["bad_version"])
            cve = str(entry["cve_id"])
            key = (pkg.lower(), bad_ver, cve)
            if key in seen:
                continue

            if _is_exact_version(ver_or_spec):
                if ver_or_spec == bad_ver:
                    seen.add(key)
                    findings.append(_finding_from_yaml(pkg, ver_or_spec, entry))
            else:
                try:
                    spec_set = SpecifierSet(ver_or_spec) if ver_or_spec != "*" else None
                    if spec_set is None or spec_set.contains(bad_ver):
                        seen.add(key)
                        findings.append(_finding_from_specifier(pkg, ver_or_spec, bad_ver, entry))
                except InvalidSpecifier:
                    if ver_or_spec == bad_ver:
                        seen.add(key)
                        findings.append(_finding_from_yaml(pkg, ver_or_spec, entry))

    return findings


async def _scan_live_or_fallback(deps: list[tuple[str, str]]) -> list[Finding]:
    try:
        return await _scan_live(deps)
    except OsvUnavailableError as exc:
        logger.warning(f"OSV.dev unavailable, falling back to offline database: {exc}")
        return _scan_offline(deps)


# â”€â”€â”€ Public scanner â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


# â”€â”€ Dependency Graph & Transitive Chain Resolution â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


def build_dependency_graph(path: str | Path) -> nx.DiGraph:
    """
    Build a directed dependency graph from lockfiles in `path`.

    Edges point from parent package to dependent child package (parent -> child).
    Node attributes include 'version' and 'is_root'.
    """
    root = Path(path)
    if not root.is_dir():
        root = root.parent

    graph = nx.DiGraph()

    uv_lock = root / "uv.lock"
    if uv_lock.exists():
        try:
            with open(uv_lock, "rb") as f:
                data = tomllib.load(f)
            packages = data.get("package", [])
            for pkg in packages:
                name = str(pkg.get("name", "")).lower()
                ver = str(pkg.get("version", ""))
                is_editable = bool(pkg.get("source", {}).get("editable"))
                graph.add_node(name, version=ver, is_root=is_editable)

                for dep in pkg.get("dependencies", []):
                    dep_name = str(dep.get("name", "")).lower()
                    if dep_name:
                        graph.add_edge(name, dep_name)

                for group in ("optional-dependencies", "dev-dependencies"):
                    deps_group = pkg.get(group, {})
                    if isinstance(deps_group, dict):
                        for group_deps in deps_group.values():
                            if isinstance(group_deps, list):
                                for d in group_deps:
                                    dname = str(d.get("name", "")).lower()
                                    if dname:
                                        graph.add_edge(name, dname)
            return graph
        except Exception as e:
            logger.error(f"Failed to build dependency graph from uv.lock at {uv_lock}: {e}")

    poetry_lock = root / "poetry.lock"
    if poetry_lock.exists():
        try:
            with open(poetry_lock, "rb") as f:
                data = tomllib.load(f)
            packages = data.get("package", [])
            for pkg in packages:
                name = str(pkg.get("name", "")).lower()
                ver = str(pkg.get("version", ""))
                graph.add_node(name, version=ver, is_root=False)
                for dep_name in pkg.get("dependencies", {}):
                    graph.add_edge(name, str(dep_name).lower())
            return graph
        except Exception as e:
            logger.error(f"Failed to build dependency graph from poetry.lock at {poetry_lock}: {e}")

    return graph


def find_dependency_chain(graph: nx.DiGraph, target_pkg: str) -> list[str] | None:
    """Find the shortest dependency chain from a root package to `target_pkg`."""
    target = target_pkg.lower()
    if target not in graph:
        return None

    roots = [n for n, d in graph.nodes(data=True) if d.get("is_root")]
    if not roots:
        roots = [n for n in graph.nodes if graph.in_degree(n) == 0]
    if not roots:
        roots = list(graph.nodes)

    shortest: list[str] | None = None
    for r in roots:
        if r == target:
            return [target]
        if nx.has_path(graph, r, target):
            path = nx.shortest_path(graph, r, target)
            if shortest is None or len(path) < len(shortest):
                shortest = path

    return shortest


def format_dependency_chain(graph: nx.DiGraph, chain: list[str]) -> str:
    """Format a dependency chain list into an arrow string with package versions."""
    parts: list[str] = []
    for pkg in chain:
        ver = graph.nodes.get(pkg, {}).get("version")
        if ver:
            parts.append(f"{pkg}=={ver}")
        else:
            parts.append(pkg)
    return " -> ".join(parts)


def scan_dependencies(
    path: str,
    offline: bool = False,
    show_transitive: bool = False,
) -> tuple[list[Finding], int]:
    """
    Scan dependencies in `path` for known CVEs.

    If offline=True, directly uses the bundled offline database.
    Otherwise, tries live OSV.dev lookups with fallback to offline DB.
    If show_transitive=True, builds lockfile dependency graph and annotates findings
    with root-to-leaf dependency chains.
    Returns (findings, checks_run) where checks_run = number of dependencies parsed.
    """
    deps = _parse_dependencies(path)
    checks_run = len(deps)
    if not deps:
        return [], 0

    findings = _scan_offline(deps) if offline else asyncio.run(_scan_live_or_fallback(deps))

    if show_transitive and findings:
        graph = build_dependency_graph(path)
        if graph.number_of_nodes() > 0:
            updated_findings: list[Finding] = []
            for f in findings:
                pkg = str(f.metadata.get("package", "")).lower()
                chain = find_dependency_chain(graph, pkg)
                if chain and len(chain) > 1:
                    chain_str = format_dependency_chain(graph, chain)
                    meta = dict(f.metadata)
                    meta["transitive_chain"] = chain
                    meta["transitive_path_str"] = chain_str
                    f = f.model_copy(
                        update={
                            "evidence": f"{f.evidence} [chain: {chain_str}]",
                            "metadata": meta,
                        }
                    )
                updated_findings.append(f)
            findings = updated_findings

    return findings, checks_run
