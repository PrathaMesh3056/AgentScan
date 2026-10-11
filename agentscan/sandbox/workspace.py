"""Disposable workspace preparation and content-based mutation telemetry."""

from __future__ import annotations

import hashlib
import os
import shutil
from pathlib import Path

EXCLUDED_DIRS = {
    ".git",
    ".venv",
    "node_modules",
    "__pycache__",
    ".aws",
    ".ssh",
    ".agentscan-recovery",
}
MAX_BYTES = 128 * 1024 * 1024
MAX_FILES = 10000


def prepare_workspace(source: Path, destination: Path) -> None:
    """Copy regular inputs without links, credentials, or direct writes to the original."""
    destination.mkdir()
    total = 0
    files = 0
    for directory, dirs, names in os.walk(source, followlinks=False):
        dirs[:] = [name for name in dirs if name not in EXCLUDED_DIRS]
        for name in dirs:
            path = Path(directory) / name
            if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
                raise PermissionError(
                    f"Sandbox inputs must not contain links: {path.relative_to(source)}"
                )
            target_dir = destination / path.relative_to(source)
            target_dir.mkdir(exist_ok=True)
            target_dir.chmod(0o777)
        for name in names:
            path = Path(directory) / name
            relative = path.relative_to(source)
            if path.name.startswith(
                (".env", ".agentscan-fix-", ".agentscan-rollback-", ".agentscan-recover-")
            ) or path.suffix in (".pem", ".key"):
                continue
            if path.is_symlink() or not path.is_file():
                raise PermissionError(
                    f"Sandbox inputs must be regular files without links: {relative}"
                )
            target = destination / relative
            files += 1
            total += path.stat().st_size
            if files > MAX_FILES or total > MAX_BYTES:
                raise ValueError("Sandbox workspace exceeds the configured copy limit")
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
            target.chmod(0o777 if path.stat().st_mode & 0o111 else 0o666)
    destination.chmod(0o777)


def snapshot(workspace: Path) -> dict[str, str]:
    state: dict[str, str] = {}
    for path in workspace.rglob("*"):
        if path.is_symlink():
            state[path.relative_to(workspace).as_posix()] = "symlink:" + str(path.readlink())
        elif path.is_file():
            with path.open("rb") as stream:
                state[path.relative_to(workspace).as_posix()] = hashlib.file_digest(
                    stream, "sha256"
                ).hexdigest()
    return state


def content_diff(before: dict[str, str], after: dict[str, str]) -> list[dict[str, str]]:
    return [
        {
            "kind": "A" if name not in before else "D" if name not in after else "C",
            "path": f"/workspace/{name}",
        }
        for name in sorted(before.keys() | after.keys())
        if before.get(name) != after.get(name)
    ]
