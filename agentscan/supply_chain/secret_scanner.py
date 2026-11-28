# agentscan/supply_chain/secret_scanner.py
#
# Hardcoded secret detector using format-aware parsing + regex + Shannon entropy.
#
# Explicitly parses dotenv (.env*), YAML (.yaml/.yml), JSON (.json), and TOML
# (.toml) inputs so quoted and unquoted assignments are both assessed. Python
# and plain-text files use assignment heuristics. Formats that are not parsed
# are reported as INCONCLUSIVE rather than silently treated as clean.
#
# Uses stdlib json/tomllib and the already-declared PyYAML dependency. If
# PyYAML is unavailable, a conservative line parser handles simple YAML.
#
# Entropy gate: only flag values with Shannon entropy > 3.5 — this filters
#               out low-entropy human-typed strings like "password123" while
#               catching high-entropy generated secrets like "sk-proj-aB3xK9...".

from __future__ import annotations

import json
import math
import re
import tomllib
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from loguru import logger

from agentscan.core.models import Finding, Severity
from agentscan.supply_chain.coverage import collect_inputs, record_coverage

try:  # PyYAML is a declared dependency; keep a line-parser fallback for robustness.
    import yaml
except ImportError:  # pragma: no cover - only exercised when PyYAML is absent
    yaml = None  # type: ignore[assignment]

# ── Constants ─────────────────────────────────────────────────────────────────

# Matches:  SOME_KEY = "value"  or  SOME_SECRET = 'value'
# Group 1 = variable name, Group 2 = value string
_SECRET_RE = re.compile(
    r'\b(\w*(?:KEY|SECRET|TOKEN)\w*)\s*=\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)

# Line-oriented assignment used for dotenv and plain-text fallbacks.
# Matches both `KEY=value` and `KEY: value`, with an optional `export` prefix.
_ASSIGNMENT_RE = re.compile(
    r"^\s*(?:-\s+)?(?:export\s+)?"
    r"[\"']?([A-Za-z_][\w.-]*(?:KEY|SECRET|TOKEN)[\w.-]*)[\"']?"
    r"\s*[:=]\s*(.+?)\s*$",
    re.IGNORECASE | re.MULTILINE,
)

_SECRET_NAME_RE = re.compile(r"(?:KEY|SECRET|TOKEN)", re.IGNORECASE)
_ENTROPY_THRESHOLD = 3.5  # bits; below this → likely human-typed, not a real secret

_YAML_SUFFIXES = frozenset({".yaml", ".yml"})
_JSON_SUFFIXES = frozenset({".json"})
_TOML_SUFFIXES = frozenset({".toml"})
_PYTHON_SUFFIXES = frozenset({".py", ".pyw"})

# Plain-text/code formats the heuristic scanner can assess directly. Structured
# formats are parsed above; any other extension is unsupported and must not be
# counted as a clean assessment.
_TEXT_SUFFIXES = frozenset(
    {
        ".txt",
        ".text",
        ".md",
        ".markdown",
        ".rst",
        ".adoc",
        ".asciidoc",
        ".log",
        ".js",
        ".jsx",
        ".mjs",
        ".cjs",
        ".ts",
        ".tsx",
        ".vue",
        ".svelte",
        ".java",
        ".kt",
        ".kts",
        ".scala",
        ".groovy",
        ".go",
        ".rs",
        ".rb",
        ".php",
        ".cs",
        ".fs",
        ".vb",
        ".c",
        ".h",
        ".cc",
        ".cpp",
        ".cxx",
        ".hpp",
        ".hh",
        ".m",
        ".mm",
        ".swift",
        ".dart",
        ".lua",
        ".pl",
        ".pm",
        ".r",
        ".jl",
        ".ex",
        ".exs",
        ".erl",
        ".hrl",
        ".clj",
        ".cljs",
        ".cljc",
        ".edn",
        ".sh",
        ".bash",
        ".zsh",
        ".fish",
        ".ps1",
        ".psm1",
        ".bat",
        ".cmd",
        ".sql",
        ".graphql",
        ".gql",
        ".proto",
        ".gradle",
        ".lock",
        ".patch",
        ".diff",
    }
)

# Skip tool/VCS directories. Dotfiles are skipped except .env / .env.* (common secret files).
_SKIP_DIR_NAMES = frozenset(
    {
        "__pycache__",
        "node_modules",
        ".git",
        ".venv",
        "venv",
        ".tox",
        ".mypy_cache",
        ".ruff_cache",
        ".idea",
        ".vscode",
    }
)


def _should_scan_file(filepath: Path, root: Path) -> bool:
    """True if this file should be searched for hardcoded secrets."""
    try:
        parts = filepath.relative_to(root).parts
    except ValueError:
        parts = filepath.parts
    for part in parts[:-1]:
        if part in _SKIP_DIR_NAMES or part.startswith("."):
            return False
    name = parts[-1] if parts else filepath.name
    if name in _SKIP_DIR_NAMES:
        return False
    if name.startswith("."):
        return name == ".env" or name.startswith(".env.")
    return True


def _detect_format(filepath: Path) -> str:
    """Return the parser to use for this input, or ``unsupported``."""
    name = filepath.name.lower()
    suffix = filepath.suffix.lower()
    if name == ".env" or name.startswith(".env.") or suffix == ".env":
        return "dotenv"
    if suffix in _YAML_SUFFIXES:
        return "yaml"
    if suffix in _JSON_SUFFIXES:
        return "json"
    if suffix in _TOML_SUFFIXES:
        return "toml"
    if suffix in _PYTHON_SUFFIXES:
        return "python"
    if not suffix or suffix in _TEXT_SUFFIXES:
        return "text"
    return "unsupported"


# ── Value helpers ─────────────────────────────────────────────────────────────


def _strip_inline_comment(value: str) -> str:
    """Remove a trailing ``#`` comment while preserving quoted ``#`` characters."""
    quote: str | None = None
    escaped = False
    for index, char in enumerate(value):
        if escaped:
            escaped = False
            continue
        if char == "\\" and quote is not None:
            escaped = True
            continue
        if quote is not None:
            if char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
            continue
        if char == "#" and (index == 0 or value[index - 1].isspace()):
            return value[:index].rstrip()
    return value.rstrip()


def _unquote(value: str) -> str:
    """Strip one matching pair of single or double quotes."""
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def _is_secret_name(name: str) -> bool:
    return bool(_SECRET_NAME_RE.search(name))


def _line_for_key(text: str, key: str) -> int:
    """Best-effort line lookup for formats whose parser does not expose positions."""
    pattern = re.compile(rf"(?<![\w.-])[\"']?{re.escape(key)}[\"']?\s*[:=]")
    for line_no, line in enumerate(text.splitlines(), 1):
        if pattern.search(line):
            return line_no
    return 1


# ── Format parsers ────────────────────────────────────────────────────────────


def _iter_dotenv_pairs(text: str) -> Iterator[tuple[str, str, int]]:
    for line_no, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        match = re.match(r"^([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*(.*)$", line)
        if not match:
            continue
        key, value = match.groups()
        yield key, _unquote(_strip_inline_comment(value)), line_no


def _iter_yaml_pairs(text: str) -> Iterator[tuple[str, str, int]]:
    if yaml is None:
        yield from _iter_yaml_lines(text)
        return

    root = yaml.compose(text, Loader=yaml.SafeLoader)
    if root is None:
        return

    visited: set[int] = set()

    def walk(node: Any) -> Iterator[tuple[str, str, int]]:
        node_id = id(node)
        if node_id in visited:
            return
        visited.add(node_id)
        if isinstance(node, yaml.MappingNode):
            for key_node, value_node in node.value:
                if isinstance(key_node, yaml.ScalarNode):
                    key = str(key_node.value)
                    if isinstance(value_node, yaml.ScalarNode):
                        yield key, str(value_node.value), value_node.start_mark.line + 1
                    else:
                        yield from walk(value_node)
                else:
                    yield from walk(value_node)
        elif isinstance(node, yaml.SequenceNode):
            for item in node.value:
                yield from walk(item)

    yield from walk(root)


def _iter_yaml_lines(text: str) -> Iterator[tuple[str, str, int]]:
    """Conservative fallback for simple ``key: value`` YAML when PyYAML is absent."""
    line_re = re.compile(r"^(?:-\s+)?([A-Za-z0-9_.-]+)\s*:\s*(.*)$")
    for line_no, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = line_re.match(line)
        if not match:
            continue
        key, value = match.groups()
        if not value or value[0] in "|>":
            continue
        yield key, _unquote(_strip_inline_comment(value)), line_no


def _walk_data(value: Any, line_for: Any) -> Iterator[tuple[str, str, int]]:
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(key, str) and isinstance(item, str) and _is_secret_name(key):
                yield key, item, line_for(key)
            else:
                yield from _walk_data(item, line_for)
    elif isinstance(value, list):
        for item in value:
            yield from _walk_data(item, line_for)


def _iter_json_pairs(text: str) -> Iterator[tuple[str, str, int]]:
    data = json.loads(text)
    yield from _walk_data(data, lambda key: _line_for_key(text, key))


def _iter_toml_pairs(text: str) -> Iterator[tuple[str, str, int]]:
    data = tomllib.loads(text)
    yield from _walk_data(data, lambda key: _line_for_key(text, key))


def _iter_python_pairs(text: str) -> Iterator[tuple[str, str, int]]:
    for match in _SECRET_RE.finditer(text):
        yield match.group(1), match.group(2), text[: match.start()].count("\n") + 1


def _iter_text_pairs(text: str) -> Iterator[tuple[str, str, int]]:
    seen: set[tuple[str, str, int]] = set()
    for match in _ASSIGNMENT_RE.finditer(text):
        value = _unquote(_strip_inline_comment(match.group(2)))
        if not value:
            continue
        token = (match.group(1), value, text[: match.start()].count("\n") + 1)
        if token not in seen:
            seen.add(token)
            yield token
    for match in _SECRET_RE.finditer(text):
        token = (match.group(1), match.group(2), text[: match.start()].count("\n") + 1)
        if token not in seen:
            seen.add(token)
            yield token


def _iter_pairs(text: str, fmt: str) -> Iterator[tuple[str, str, int]]:
    if fmt == "dotenv":
        pairs = _iter_dotenv_pairs(text)
    elif fmt == "yaml":
        pairs = _iter_yaml_pairs(text)
    elif fmt == "json":
        pairs = _iter_json_pairs(text)
    elif fmt == "toml":
        pairs = _iter_toml_pairs(text)
    elif fmt == "python":
        pairs = _iter_python_pairs(text)
    else:
        pairs = _iter_text_pairs(text)
    for key, value, line_no in pairs:
        if _is_secret_name(key):
            yield key, value.strip(), line_no


# ── Shannon entropy ───────────────────────────────────────────────────────────


def _shannon_entropy(s: str) -> float:
    """
    Compute the Shannon entropy (bits) of a string.

    Standard formula: -∑ p(c) * log2(p(c)) for each distinct character c.
    Returns 0.0 for empty strings.
    """
    if not s:
        return 0.0
    length = len(s)
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


# ── Public scanner ────────────────────────────────────────────────────────────


def scan_secrets(path: str, *, coverage: list[dict] | None = None) -> tuple[list[Finding], int]:
    """
    Scan all files under `path` for hardcoded high-entropy secrets.

    Dotenv, YAML, JSON, and TOML files are parsed explicitly so quoted and
    unquoted assignments are both assessed. Python and plain-text files use
    assignment heuristics. Unsupported or unparsable formats are reported as
    INCONCLUSIVE coverage instead of being counted as clean.

    Returns:
        (findings, checks_run) where checks_run = number of fully assessed files.
    """
    root = Path(path)
    issues: list[str] = []
    candidates = collect_inputs(
        root, "*", issues, ignored_dirs=_SKIP_DIR_NAMES, skip_hidden_dirs=True
    )
    relative_root = root if root.is_dir() else root.parent
    all_files = [f for f in candidates if _should_scan_file(f, relative_root)]
    checks_run = 0

    findings: list[Finding] = []
    for filepath in all_files:
        fmt = _detect_format(filepath)
        supported = fmt != "unsupported"
        if not supported:
            issues.append(
                f"{filepath.name}: unsupported format '{filepath.suffix or 'none'}'; "
                "file was not assessed."
            )

        try:
            text = filepath.read_text(encoding="utf-8-sig")
            if "\x00" in text:
                raise ValueError("Binary file is unsupported")
        except Exception as e:
            issues.append(f"{filepath.name}: {type(e).__name__}; file was not assessed.")
            logger.warning(f"Skipping {filepath}: {type(e).__name__}")
            continue

        fully_assessed = supported
        if supported:
            try:
                pairs = list(_iter_pairs(text, fmt))
            except Exception as e:
                fully_assessed = False
                issues.append(
                    f"{filepath.name}: {type(e).__name__}; {fmt} input was not fully assessed."
                )
                logger.warning(f"Partially parsing {filepath}: {type(e).__name__}")
                # Keep the conservative text heuristic so malformed configs still
                # surface obvious assignments while coverage stays INCONCLUSIVE.
                pairs = list(_iter_text_pairs(text))
        else:
            logger.warning(f"Partially scanning {filepath}: unsupported secret-scan format")
            pairs = list(_iter_text_pairs(text))

        if fully_assessed:
            checks_run += 1

        for var_name, secret_value, line_no in pairs:
            if not _is_secret_name(var_name):
                continue
            entropy = _shannon_entropy(secret_value)

            if entropy < _ENTROPY_THRESHOLD:
                # Low entropy → almost certainly a placeholder or human-typed value
                continue

            findings.append(
                Finding(
                    attack_id="SC-015",
                    attack_name="Hardcoded secret detected",
                    severity=Severity.CRITICAL,
                    owasp_id="LLM02",
                    description=(
                        f"High-entropy value assigned to '{var_name}' in "
                        f"'{filepath.name}' ({fmt}, entropy={entropy:.2f} bits). "
                        f"Hardcoded secrets are exposed to anyone with repository access "
                        f"and cannot be rotated without a code change."
                    ),
                    evidence=(
                        f"file={filepath}, line={line_no}, "
                        f"variable={var_name}, entropy={entropy:.2f}"
                    ),
                    remediation=(
                        f"Remove the hardcoded value for '{var_name}'. "
                        f"Load it from an environment variable (os.environ.get('{var_name}')) "
                        f"or a secrets manager (AWS Secrets Manager, HashiCorp Vault, etc.)."
                    ),
                    metadata={
                        "file": str(filepath),
                        "line": line_no,
                        "variable": var_name,
                        "entropy": round(entropy, 4),
                        "format": fmt,
                    },
                )
            )

    record_coverage(
        coverage,
        "secrets",
        checks_run,
        source="text_secret_heuristics",
        issues=issues,
        selected=len(all_files),
    )
    return findings, checks_run
