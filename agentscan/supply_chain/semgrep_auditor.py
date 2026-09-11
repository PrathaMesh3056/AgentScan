# agentscan/supply_chain/semgrep_auditor.py
#
# Optional Semgrep-backed code auditor (additive to AST config_auditor.py).
#
# Requires the `semgrep` binary (pip extra: agentscan[semgrep]). When Semgrep
# is missing, scan_semgrep() logs a warning and returns no findings.

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from loguru import logger

from agentscan.core.models import Finding, Severity

_SEVERITY_MAP: dict[str, Severity] = {
    "ERROR": Severity.CRITICAL,
    "WARNING": Severity.HIGH,
    "INFO": Severity.MEDIUM,
}

_CHECK_DEFAULTS: dict[str, tuple[str, str, str]] = {
    "agentscan.unsafe-pickle-loads": ("SC-015", "Unsafe pickle deserialisation", "LLM05"),
    "agentscan.unsafe-torch-load": ("SC-011", "Unsafe model deserialisation", "LLM05"),
    "agentscan.subprocess-popen-shell": ("SC-016", "Unsafe shell subprocess", "LLM05"),
    "agentscan.os-system": ("SC-016", "Unsafe os.system call", "LLM05"),
    "agentscan.prompt-fstring-user-input": (
        "SC-017",
        "Prompt interpolation of untrusted input",
        "LLM01",
    ),
    "agentscan.prompt-format-user-input": (
        "SC-017",
        "Prompt interpolation of untrusted input",
        "LLM01",
    ),
}


def default_rules_path() -> Path:
    """Locate rules/ai_rules.yaml (editable checkout or packaged wheel)."""
    here = Path(__file__).resolve()
    candidates = [
        here.parents[1] / "rules" / "ai_rules.yaml",
        here.parents[2] / "rules" / "ai_rules.yaml",
        Path.cwd() / "rules" / "ai_rules.yaml",
    ]
    for path in candidates:
        if path.is_file():
            return path
    return candidates[0]


def scan_semgrep(
    path: str,
    *,
    rules_path: Path | str | None = None,
    semgrep_bin: str | None = None,
) -> tuple[list[Finding], int]:
    """
    Run Semgrep against `path` using AgentScan AI rules.

    Returns (findings, checks_run). checks_run is the number of files Semgrep
    reported as scanned, or 0 when the binary/rules are unavailable.
    """
    binary = semgrep_bin or shutil.which("semgrep")
    if not binary:
        logger.warning(
            "semgrep not found on PATH; skipping Semgrep audit. "
            "Install with: pip install 'agentscan[semgrep]'"
        )
        return [], 0

    rules = Path(rules_path) if rules_path is not None else default_rules_path()
    if not rules.is_file():
        logger.warning(f"Semgrep rules file not found at {rules}; skipping Semgrep audit.")
        return [], 0

    target = Path(path)
    cmd = [
        binary,
        "--config",
        str(rules),
        "--json",
        "--quiet",
        str(target),
    ]
    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.warning(f"Semgrep invocation failed ({exc}); skipping Semgrep audit.")
        return [], 0

    # Semgrep: 0 = clean, 1 = findings, 2+ = error
    if completed.returncode not in (0, 1):
        err = (completed.stderr or completed.stdout or "").strip()[:400]
        logger.warning(f"Semgrep exited {completed.returncode}; skipping. {err}")
        return [], 0

    payload = (completed.stdout or "").strip()
    if not payload:
        return [], 0

    try:
        data = json.loads(payload)
    except json.JSONDecodeError as exc:
        logger.warning(f"Semgrep returned invalid JSON ({exc}); skipping.")
        return [], 0

    scanned = data.get("paths", {}).get("scanned") or []
    checks_run = len(scanned) if isinstance(scanned, list) else 0
    findings = [_finding_from_result(item) for item in data.get("results") or [] if item]
    return findings, checks_run


def _finding_from_result(item: dict[str, Any]) -> Finding:
    check_id = str(item.get("check_id") or "agentscan.unknown")
    extra = item.get("extra") or {}
    metadata = extra.get("metadata") or {}
    defaults = _CHECK_DEFAULTS.get(check_id, ("SC-018", "Semgrep AI rule match", "LLM05"))
    attack_id = str(metadata.get("agentscan_id") or defaults[0])
    owasp_id = str(metadata.get("owasp_id") or defaults[2])
    name = defaults[1]
    semgrep_sev = str(extra.get("severity") or "WARNING").upper()
    severity = _SEVERITY_MAP.get(semgrep_sev, Severity.HIGH)
    path = item.get("path") or ""
    line = (item.get("start") or {}).get("line")
    message = str(extra.get("message") or check_id).strip()
    evidence = f"file={path}"
    if line is not None:
        evidence = f"{evidence}, line={line}"
    description = message if len(message) >= 10 else f"Semgrep rule {check_id} matched in {path}."
    return Finding(
        attack_id=attack_id,
        attack_name=name,
        severity=severity,
        owasp_id=owasp_id,
        description=description,
        evidence=evidence,
        remediation="Review the flagged code and apply the safer API or sanitise untrusted input.",
        metadata={
            "file": str(path),
            "line": line,
            "semgrep_check_id": check_id,
        },
    )
