"""Regression checks for public Markdown documentation links."""

from __future__ import annotations

import re
import subprocess
import urllib.parse
from pathlib import Path

import pytest

_LINK_RE = re.compile(r"!?\[[^\]]*\]\(\s*(?:<([^>]*)>|([^)\s]+))(?:\s+['\"][^'\"]*['\"])?\s*\)")
_REF_RE = re.compile(r"^\s*\[[^\]]+\]:\s*(?:<([^>]*)>|(\S+))", re.MULTILINE)
_HTML_RE = re.compile(r"(?:href|src)\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
_EXTERNAL_SCHEMES = {"http", "https", "mailto", "tel", "ftp", "ftps", "javascript", "data"}


def tracked_markdown_files(repo_root: Path) -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-z", "*.md"],
        cwd=repo_root,
        check=True,
        capture_output=True,
        text=True,
    )
    files = [entry for entry in result.stdout.split("\0") if entry]
    return [repo_root / entry for entry in files]


def tracked_file_set(repo_root: Path) -> set[str]:
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=repo_root,
        check=True,
        capture_output=True,
        text=True,
    )
    return {entry.replace("\\", "/") for entry in result.stdout.split("\0") if entry}


def extract_local_links(text: str) -> list[str]:
    links: list[str] = []
    for match in _LINK_RE.finditer(text):
        raw = match.group(1) if match.group(1) is not None else match.group(2)
        if raw:
            links.append(raw.strip())
    for match in _REF_RE.finditer(text):
        raw = match.group(1) if match.group(1) is not None else match.group(2)
        if raw:
            links.append(raw.strip())
    for match in _HTML_RE.finditer(text):
        links.append(match.group(1).strip())
    return links


def normalize_target(raw: str) -> str | None:
    """Return a repository-relative target path, or None for non-local links."""
    raw = raw.strip()
    if raw.startswith("<") and raw.endswith(">"):
        raw = raw[1:-1].strip()
    parsed = urllib.parse.urlsplit(raw)
    scheme = parsed.scheme.lower()
    if scheme in _EXTERNAL_SCHEMES:
        return None
    if scheme == "file":
        return "__broken_file_uri__"
    if scheme and scheme not in ("",):
        return None
    if parsed.netloc:
        return None

    target = urllib.parse.unquote(parsed.path)
    if not target or target.startswith("#"):
        # Anchor-only links resolve to the containing file; handled by caller.
        return ""

    # Root-relative links are resolved against the repository root.
    if target.startswith("/"):
        return target.lstrip("/")

    # Collapse any drive-letter or absolute filesystem path into a broken target.
    if re.match(r"^[A-Za-z]:", target) or target.startswith("/"):
        return target.lstrip("/")

    return target


def check_docs_links(repo_root: Path | None = None) -> list[str]:
    root = (repo_root or Path.cwd()).resolve()
    tracked_files = tracked_file_set(root)
    broken: list[str] = []

    for md_file in tracked_markdown_files(root):
        relative_source = md_file.relative_to(root).as_posix()
        try:
            text = md_file.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            text = md_file.read_text(encoding="utf-8", errors="replace")

        for raw in extract_local_links(text):
            target = normalize_target(raw)
            if target is None:
                continue
            if target == "":
                # Anchor-only link: resolves to the source file.
                resolved = relative_source
            elif target == "__broken_file_uri__":
                resolved = "__broken_file_uri__"
            else:
                source_dir = str(Path(relative_source).parent).replace("\\", "/")
                if source_dir == ".":
                    source_dir = ""
                resolved = (Path(source_dir) / target).as_posix() if source_dir else target
                resolved = str(Path(resolved)).replace("\\", "/")
                # Normalize '..' segments without leaving the repository.
                parts: list[str] = []
                for part in resolved.split("/"):
                    if part in ("", "."):
                        continue
                    if part == "..":
                        if parts:
                            parts.pop()
                        else:
                            parts.append(part)
                    else:
                        parts.append(part)
                resolved = "/".join(parts)

            if resolved == "__broken_file_uri__":
                broken.append(f"{relative_source}: {raw} -> (non-repository file URI)")
                continue

            exists = resolved in tracked_files or any(
                tracked.startswith(resolved.rstrip("/") + "/") for tracked in tracked_files
            )
            if not exists:
                broken.append(f"{relative_source}: {raw} -> {resolved}")

    if broken:
        raise AssertionError("Broken tracked Markdown links:\n" + "\n".join(broken))
    return []


def test_tracked_markdown_links_resolve():
    check_docs_links()


def test_broken_link_is_detected(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
    (repo / "README.md").write_text("# Test\n\n[broken](does-not-exist.md)\n", encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=repo, check=True)

    with pytest.raises(AssertionError, match="Broken tracked Markdown links"):
        check_docs_links(repo)


def test_no_stale_pdf_claims():
    import tomllib

    root = Path(__file__).resolve().parents[1]
    pyproject = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    has_pdf = "pdf" in pyproject["project"].get("optional-dependencies", {})
    if not has_pdf:
        return
    stale_markers = ("PDF export is unsupported", "PDF reports are disabled", "PDF is disabled")
    offenders = []
    for md_file in tracked_markdown_files(root):
        text = md_file.read_text(encoding="utf-8", errors="replace")
        if any(marker in text for marker in stale_markers):
            offenders.append(md_file.relative_to(root).as_posix())
    assert not offenders, f"Stale PDF claims in: {offenders}"
