"""Reject private files and missing runtime assets before distribution installation."""

from __future__ import annotations

import json
import stat
import sys
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

# Hatch always adds the root .gitignore to keep rebuilding a wheel from the
# sdist reproducible; it cannot be excluded. It contains build selection rules.
# https://hatch.pypa.io/latest/plugins/builder/sdist/#default-file-selection
_TOP_LEVEL_SOURCE_FILES = {
    "pyproject.toml",
    "README.md",
    "LICENSE",
    "CHANGELOG.md",
    "PKG-INFO",
    ".gitignore",
}
_PRIVATE_PARTS = {
    "codex audit",
    "internal_docs",
    ".test-tmp",
    ".agentscan",
    ".agentscan-recovery",
    ".git",
    ".venv",
    "__pycache__",
    "tests",
}
_PRIVATE_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".pyc"}
_REQUIRED_RUNTIME = {
    "agentscan/__init__.py",
    "agentscan/cli.py",
    "agentscan/reporting/templates/scan_report.html.j2",
    "agentscan/identity/policies/roles.yaml",
    "agentscan/supply_chain/known_vulnerabilities.yaml",
    "agentscan/ui/static/index.html",
    "agentscan/ui/static/dashboard.js",
    "agentscan/ui/static/scan-analytics.js",
    "agentscan/ui/static/dashboard.css",
    "agentscan/ui/static/form-validation.js",
    "agentscan/ui/static/vendor/tailwind-browser.js",
    "agentscan/ui/static/fonts/IBM_Plex_Mono/IBMPlexMono-Regular.woff2",
}


def validate_names(names: list[str], *, source: bool) -> dict[str, int | str]:
    """Inspect member names only; private file contents are never opened."""
    paths: set[str] = set()
    source_root: str | None = None
    for name in names:
        is_directory = name.endswith("/")
        path = PurePosixPath(name)
        if path.is_absolute() or "\\" in name or ".." in path.parts or not path.parts:
            raise ValueError("Distribution contains an unsafe archive path")
        if source:
            if source_root is None:
                source_root = path.parts[0]
            if path.parts[0] != source_root or not source_root.startswith("agentscan-"):
                raise ValueError("Source distribution must have one AgentScan archive root")
            path = PurePosixPath(*path.parts[1:])
        if str(path) == ".":
            continue
        lower_parts = {part.lower() for part in path.parts}
        basename = path.name.lower()
        if (
            lower_parts & _PRIVATE_PARTS
            or basename == "audit_phase2.md"
            or basename == ".env"
            or basename.startswith(".env.")
            or basename.startswith(
                (".agentscan-fix-", ".agentscan-recover-", ".agentscan-rollback-")
            )
            or basename in {"id_rsa", "id_ed25519"}
            or path.suffix.lower() in _PRIVATE_SUFFIXES
        ):
            raise ValueError(f"Private or operational file found in distribution: {path}")
        normalized = path.as_posix()
        if source:
            allowed = (
                normalized in _TOP_LEVEL_SOURCE_FILES
                or normalized == "rules/ai_rules.yaml"
                or (is_directory and normalized == "rules")
                or path.parts[0] == "agentscan"
            )
        else:
            allowed = path.parts[0] == "agentscan" or (
                path.parts[0].startswith("agentscan-") and path.parts[0].endswith(".dist-info")
            )
        if not allowed:
            raise ValueError(f"File outside the distribution allowlist: {path}")
        if not is_directory:
            paths.add(normalized)
    required = _REQUIRED_RUNTIME | (
        {"rules/ai_rules.yaml", "pyproject.toml", "README.md", "LICENSE"}
        if source
        else {"agentscan/rules/ai_rules.yaml"}
    )
    missing = sorted(required - paths)
    if missing:
        raise ValueError(f"Required runtime assets are missing: {', '.join(missing)}")
    return {
        "kind": "sdist" if source else "wheel",
        "files_checked": len(paths),
        "required_assets_checked": len(required),
    }


def check_archive(path: Path) -> dict[str, int | str]:
    if path.name.endswith(".whl"):
        with zipfile.ZipFile(path) as archive:
            members = archive.infolist()
            if any(
                stat.S_IFMT(member.external_attr >> 16) not in (0, stat.S_IFREG, stat.S_IFDIR)
                for member in members
            ):
                raise ValueError("Wheel contains unsupported archive links or special files")
            return validate_names([member.filename for member in members], source=False)
    if path.name.endswith(".tar.gz"):
        with tarfile.open(path, "r:gz") as archive:
            members = archive.getmembers()
            if any(not (member.isfile() or member.isdir()) for member in members):
                raise ValueError(
                    "Source distribution contains unsupported archive links or special files"
                )
            return validate_names(
                [member.name + ("/" if member.isdir() else "") for member in members], source=True
            )
    raise ValueError("Expected a wheel or gzipped source distribution")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("Usage: check_artifact_contents.py WHEEL SDIST")
    print(json.dumps([check_archive(Path(arg)) for arg in sys.argv[1:]], indent=2))
