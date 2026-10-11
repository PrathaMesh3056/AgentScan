"""Filesystem boundaries shared by remediation planners and writers."""

from __future__ import annotations

from pathlib import Path

from agentscan.guard.path import CanonicalPathGuard, PathSecurityError


def contained_path(root: Path, requested: str | Path) -> Path:
    """Resolve beneath a trusted root, rejecting links on the requested path."""
    root = root.resolve(strict=True)
    guard = CanonicalPathGuard(root)
    path = Path(requested)
    if not path.is_absolute():
        path = (root.parent if root.is_file() else root) / path
    resolved = guard.resolve_safe(path)
    # Reject even in-root links so planning and application address the same file.
    for part in (path, *path.parents):
        if part == root or part == root.parent:
            break
        if part.is_symlink() or (hasattr(part, "is_junction") and part.is_junction()):
            raise PathSecurityError(f"Remediation paths must not contain links: {part}")
    return resolved
