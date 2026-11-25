# agentscan/remediation/patch_text.py
#
# Patch text shared by the remediation CLI and PR generation:
#   - LF-normalize file contents before diffing, so patches generated on Windows
#     apply on Linux and inside GitHub's diff viewers
#   - resolve repository-relative POSIX paths, so artifacts and PR bodies never
#     expose the operator's filesystem layout

from __future__ import annotations

import difflib
from pathlib import Path


def normalize_newlines(text: str) -> str:
    """Return text with CRLF and lone CR line endings converted to LF."""
    return text.replace("\r\n", "\n").replace("\r", "\n")


def repo_relative_path(path: str | Path, root: str | Path | None) -> str:
    """Return a repository-relative POSIX path for patch headers and artifacts.

    Absolute paths outside ``root`` fall back to the file name and relative paths
    outside ``root`` fall back to a cleaned POSIX form: a generated artifact must
    never leak host-specific directories.
    """
    candidate = Path(path)
    if root is not None:
        root_path = Path(root).resolve()
        try:
            resolved = (
                candidate.resolve()
                if candidate.is_absolute()
                else (root_path / candidate).resolve()
            )
            return resolved.relative_to(root_path).as_posix()
        except (OSError, ValueError):
            pass
    if candidate.is_absolute():
        return candidate.name
    text = candidate.as_posix()
    while text.startswith("./"):
        text = text[2:]
    return text


def unified_diff(before: str, after: str, relative_path: str) -> str:
    """Return an LF-normalized unified diff for one repository-relative path."""
    diff_lines = difflib.unified_diff(
        normalize_newlines(before).splitlines(keepends=True),
        normalize_newlines(after).splitlines(keepends=True),
        fromfile=f"a/{relative_path}",
        tofile=f"b/{relative_path}",
    )
    text = "".join(diff_lines)
    if text and not text.endswith("\n"):
        text += "\n"
    return text
