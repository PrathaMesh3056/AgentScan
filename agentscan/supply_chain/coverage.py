"""Per-check provenance; skipped and failed inputs never imply a clean audit."""

from __future__ import annotations

import os
from fnmatch import fnmatch
from pathlib import Path
from typing import Any


def collect_inputs(
    root: Path,
    pattern: str,
    issues: list[str],
    *,
    ignored_dirs: set[str] | frozenset[str] = frozenset(),
    skip_hidden_dirs: bool = False,
) -> list[Path]:
    """Select supported files and retain missing/unreadable input failures."""
    if not root.exists():
        issues.append("Selected audit path does not exist.")
        return []
    if root.is_file():
        if fnmatch(root.name, pattern) and not root.is_symlink():
            return [root]
        issues.append("Selected file is unsupported or a symbolic link.")
        return []
    if not root.is_dir() or root.is_symlink():
        issues.append("Selected audit path is not a supported directory.")
        return []

    def onerror(exc: OSError) -> None:
        issues.append(f"Directory enumeration failed: {type(exc).__name__}.")

    selected: list[Path] = []
    for parent, directories, names in os.walk(root, onerror=onerror, followlinks=False):
        directories[:] = [
            name
            for name in directories
            if name not in ignored_dirs and not (skip_hidden_dirs and name.startswith("."))
        ]
        for name in names:
            if fnmatch(name, pattern):
                candidate = Path(parent) / name
                if candidate.is_symlink():
                    issues.append(f"{name}: symbolic links are not assessed.")
                else:
                    selected.append(candidate)
    return sorted(selected)


def record_coverage(
    records: list[dict] | None,
    module: str,
    checks: int,
    *,
    source: str = "static_declarations",
    issues: list[str] | None = None,
    selected: int | None = None,
) -> None:
    if records is None:
        return
    problems = list(issues or [])
    status = "INCONCLUSIVE" if problems else "COMPLETE" if checks else "NOT_ASSESSED"
    entry: dict[str, Any] = {
        "module": module,
        "status": status,
        "source": source,
        "scope": "Selected supported inputs and implemented rules only; ignored directories and other formats are excluded.",
        "checks_run": checks,
        "inputs_selected": checks if selected is None else selected,
        "limitations": problems or ([] if checks else ["No supported inputs were assessed."]),
    }
    records.append(entry)
