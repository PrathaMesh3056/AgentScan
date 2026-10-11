# agentscan/supply_chain/secret_scanner.py
#
# Hardcoded secret detector using regex + Shannon entropy.
#
# Regex: finds assignment patterns where the variable name contains
#        KEY, SECRET, or TOKEN (case-insensitive).
# Entropy gate: only flag values with Shannon entropy > 3.5 — this filters
#               out low-entropy human-typed strings like "password123" while
#               catching high-entropy generated secrets like "sk-proj-aB3xK9...".
#
# Uses stdlib re and math only — no external dependencies.

from __future__ import annotations

import math
import re
from pathlib import Path

from loguru import logger

from agentscan.core.models import Finding, Severity
from agentscan.supply_chain.coverage import collect_inputs, record_coverage

# ── Constants ─────────────────────────────────────────────────────────────────

# Matches:  SOME_KEY = "value"  or  SOME_SECRET = 'value'
# Group 1 = variable name, Group 2 = value string
_SECRET_RE = re.compile(
    r'\b(\w*(?:KEY|SECRET|TOKEN)\w*)\s*=\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)

_ENTROPY_THRESHOLD = 3.5  # bits; below this → likely human-typed, not a real secret

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

    Checks every file (not just .py) so it catches .env files, config YAMLs, etc.
    Skips binary files gracefully.

    Returns:
        (findings, checks_run) where checks_run = number of files scanned.
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
        try:
            text = filepath.read_text(encoding="utf-8")
            if "\x00" in text:
                raise ValueError("Binary file is unsupported")
            checks_run += 1
        except Exception as e:
            issues.append(f"{filepath.name}: {type(e).__name__}; file was not assessed.")
            logger.warning(f"Skipping {filepath}: {type(e).__name__}")
            continue

        for match in _SECRET_RE.finditer(text):
            var_name = match.group(1)
            secret_value = match.group(2)
            entropy = _shannon_entropy(secret_value)

            if entropy < _ENTROPY_THRESHOLD:
                # Low entropy → almost certainly a placeholder or human-typed value
                continue

            # Compute approximate line number
            line_no = text[: match.start()].count("\n") + 1

            findings.append(
                Finding(
                    attack_id="SC-015",
                    attack_name="Hardcoded secret detected",
                    severity=Severity.CRITICAL,
                    owasp_id="LLM02",
                    description=(
                        f"High-entropy value assigned to '{var_name}' in "
                        f"'{filepath.name}' (entropy={entropy:.2f} bits). "
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
