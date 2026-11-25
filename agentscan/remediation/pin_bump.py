# agentscan/remediation/pin_bump.py
#
# Auto-bumping for vulnerable package pins (SC-001).
# Targets requirements.txt and pyproject.toml based on OSV.dev fix versions.

from __future__ import annotations

import re
from pathlib import Path

from agentscan.core.models import Finding
from agentscan.remediation.models import FixAction
from agentscan.remediation.paths import contained_path


def _extract_pkg_and_fix(finding: Finding) -> tuple[str, str] | None:
    """Extract package name and recommended fixed version from an SC-001 finding."""
    pkg = finding.metadata.get("package")
    fix = finding.metadata.get("fix_version")
    if pkg and fix:
        return str(pkg).strip(), str(fix).strip()

    # Fallback to regex parsing on description
    m_pkg = re.search(
        r"Dependency ['\"]?([a-zA-Z0-9_\-\.]+)==([a-zA-Z0-9_\-\.]+)", finding.description
    )
    m_fix = re.search(r"Upgrade to >=([a-zA-Z0-9_\-\.]+)", finding.description)
    if m_pkg and m_fix:
        return m_pkg.group(1).strip(), m_fix.group(1).strip()
    return None


def _preserved_operator(op: str) -> str:
    """Keep the operator the manifest author chose where it can express the fix."""
    # `<`, `<=` and `!=` cannot state "install at least the fixed version", so the
    # bound is deliberately widened to `>=`. That conversion is documented in the
    # PR body and covered by tests.
    return ">=" if op in {"<", "<=", "!="} else op


def _bump_requirements_txt(content: str, pkg: str, fix: str) -> str:
    """Replace a pinned package version in requirements.txt, preserving the operator."""
    pattern = re.compile(
        rf"^(?P<prefix>\s*)(?P<name>{re.escape(pkg)})(?P<gap1>\s*)"
        rf"(?P<op>==|>=|<=|~=|!=|<|>)(?P<gap2>\s*)(?P<ver>[^\s#;]+)",
        re.IGNORECASE | re.MULTILINE,
    )

    def _repl(m: re.Match[str]) -> str:
        return (
            f"{m.group('prefix')}{m.group('name')}{m.group('gap1')}"
            f"{_preserved_operator(m.group('op'))}{m.group('gap2')}{fix}"
        )

    return pattern.sub(_repl, content)


def _bump_pyproject_toml(content: str, pkg: str, fix: str) -> str:
    """Replace a pinned version in pyproject.toml, preserving the operator and markers."""
    pattern = re.compile(
        rf"(?P<quote>['\"])(?P<name>{re.escape(pkg)})(?P<gap1>\s*)"
        rf"(?P<op>==|>=|<=|~=|!=|<|>)(?P<gap2>\s*)(?P<ver>[^'\"\s;,]+)",
        re.IGNORECASE,
    )

    def _repl(m: re.Match[str]) -> str:
        return (
            f"{m.group('quote')}{m.group('name')}{m.group('gap1')}"
            f"{_preserved_operator(m.group('op'))}{m.group('gap2')}{fix}"
        )

    return pattern.sub(_repl, content)


def plan_pin_bumps(findings: list[Finding], root_path: Path) -> list[FixAction]:
    """Scan root_path for requirements manifests and generate pin_bump FixActions."""
    sc001_findings = [f for f in findings if f.attack_id == "SC-001"]
    if not sc001_findings or not root_path.exists():
        return []

    # Map target manifests
    manifest_paths: list[Path] = []
    if root_path.is_file():
        if root_path.name.endswith(".txt") or root_path.name == "pyproject.toml":
            manifest_paths.append(root_path)
    else:
        manifest_paths.extend(root_path.glob("requirements*.txt"))
        pyproject = root_path / "pyproject.toml"
        if pyproject.exists():
            manifest_paths.append(pyproject)

    actions: list[FixAction] = []

    for manifest in manifest_paths:
        manifest = contained_path(root_path, manifest)
        try:
            content = manifest.read_text(encoding="utf-8")
        except Exception:
            continue

        updated = content
        for finding in sc001_findings:
            info = _extract_pkg_and_fix(finding)
            if not info:
                continue
            pkg, fix = info
            if manifest.name == "pyproject.toml":
                new_text = _bump_pyproject_toml(updated, pkg, fix)
            else:
                new_text = _bump_requirements_txt(updated, pkg, fix)

            if new_text != updated:
                actions.append(
                    FixAction(
                        path=str(manifest.resolve()),
                        kind="pin_bump",
                        finding_id=finding.attack_id,
                        before=updated,
                        after=new_text,
                        applied=False,
                    )
                )
                updated = new_text

    return actions
