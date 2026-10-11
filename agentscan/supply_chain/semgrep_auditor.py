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

import yaml

from agentscan.core.models import Finding, Severity
from agentscan.supply_chain.coverage import record_coverage

_SEVERITY_MAP: dict[str, Severity] = {
    "ERROR": Severity.CRITICAL,
    "WARNING": Severity.HIGH,
    "INFO": Severity.MEDIUM,
}

_CHECK_DEFAULTS: dict[str, tuple[str, str, str]] = {
    "agentscan.unsafe-pickle-loads": ("SC-015", "Unsafe pickle deserialisation", "LLM03"),
    "agentscan.unsafe-torch-load": ("SC-011", "Unsafe model deserialisation", "LLM03"),
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
    "agentscan.dangerous-eval-exec": (
        "SC-019",
        "Dangerous dynamic code execution (eval/exec)",
        "LLM05",
    ),
    "agentscan.unsafe-numpy-load": (
        "SC-011",
        "Unsafe numpy model deserialisation with pickle",
        "LLM03",
    ),
    "agentscan.unsafe-joblib-load": (
        "SC-011",
        "Unsafe joblib model deserialisation",
        "LLM03",
    ),
    "agentscan.insecure-sqlite-tool": (
        "SC-020",
        "Insecure SQL query interpolation in tool",
        "LLM05",
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
    fallback_to_native: bool = False,
    coverage: list[dict] | None = None,
) -> tuple[list[Finding], int]:
    """Run Semgrep and retain explicit failed, partial and fallback coverage."""

    def unavailable(reason: str, *, fallback: bool = False) -> tuple[list[Finding], int]:
        record_coverage(coverage, "semgrep", 0, source="semgrep", issues=[reason])
        if fallback and fallback_to_native:
            from agentscan.supply_chain.native_semgrep import scan_native_rules

            findings, checks = scan_native_rules(path, rules_path=rules_path, coverage=coverage)
            if coverage is not None and coverage[-1]["module"] == "native_rules":
                coverage[-1]["status"] = "INCONCLUSIVE"
                coverage[-1]["limitations"].append(
                    "Native fallback is a heuristic subset and does not establish Semgrep equivalence."
                )
            return findings, checks
        return [], 0

    target = Path(path)
    if not target.exists():
        return unavailable("Selected audit path does not exist.")
    rules = Path(rules_path) if rules_path is not None else default_rules_path()
    try:
        rule_data = yaml.safe_load(rules.read_text(encoding="utf-8"))
        if (
            not isinstance(rule_data, dict)
            or not isinstance(rule_data.get("rules"), list)
            or not rule_data["rules"]
            or any(not isinstance(rule, dict) or not rule.get("id") for rule in rule_data["rules"])
        ):
            return unavailable("Rules are empty or malformed.")
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        return unavailable(f"Rules are unavailable: {type(exc).__name__}.")

    binary = semgrep_bin or shutil.which("semgrep")
    if not binary:
        return unavailable("Semgrep is not installed.", fallback=True)
    cmd = [binary, "--config", str(rules), "--json", "--quiet", str(target)]
    try:
        completed = subprocess.run(cmd, capture_output=True, text=True, timeout=180, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return unavailable(f"Semgrep invocation failed: {type(exc).__name__}.", fallback=True)
    if completed.returncode not in (0, 1):
        return unavailable(
            f"Semgrep exited unsuccessfully ({completed.returncode}).", fallback=True
        )
    try:
        data = json.loads(completed.stdout or "")
    except (json.JSONDecodeError, TypeError):
        return unavailable("Semgrep returned invalid JSON.", fallback=True)
    if not isinstance(data, dict):
        return unavailable("Semgrep returned an unsupported result structure.", fallback=True)

    issues: list[str] = []
    paths = data.get("paths")
    scanned = paths.get("scanned") if isinstance(paths, dict) else None
    if not isinstance(scanned, list) or any(
        not isinstance(item, str) or not item for item in scanned
    ):
        scanned = []
        issues.append("Semgrep did not provide valid scanned-file coverage.")
    errors = data.get("errors", [])
    if not isinstance(errors, list):
        issues.append("Semgrep returned malformed error metadata.")
    elif errors:
        issues.append(f"Semgrep reported {len(errors)} scan or rule errors.")
    skipped = paths.get("skipped", []) if isinstance(paths, dict) else []
    if not isinstance(skipped, list):
        issues.append("Semgrep returned malformed skipped-file metadata.")
    elif skipped:
        issues.append(f"Semgrep reported {len(skipped)} skipped inputs.")

    results = data.get("results")
    findings: list[Finding] = []
    if not isinstance(results, list):
        issues.append("Semgrep did not provide a valid results list.")
    else:
        for item in results:
            if (
                not isinstance(item, dict)
                or not isinstance(item.get("check_id"), str)
                or not isinstance(item.get("path"), str)
                or not isinstance(item.get("extra", {}), dict)
                or not isinstance(item.get("start", {}), dict)
                or not isinstance(item.get("extra", {}).get("metadata", {}), dict)
            ):
                issues.append("A malformed Semgrep finding was not assessed.")
                continue
            try:
                finding = _finding_from_result(item)
                findings.append(finding)
                if not finding.metadata["severity_assessed"]:
                    issues.append("A Semgrep finding has an unavailable severity.")
            except (TypeError, ValueError):
                issues.append("A Semgrep finding failed validation.")
    checks = len(set(scanned))
    record_coverage(coverage, "semgrep", checks, source="semgrep", issues=issues, selected=checks)
    return findings, checks


def _finding_from_result(item: dict[str, Any]) -> Finding:
    check_id = str(item.get("check_id") or "agentscan.unknown")
    extra = item.get("extra") or {}
    metadata = extra.get("metadata") or {}
    defaults = _CHECK_DEFAULTS.get(check_id, ("SC-018", "Semgrep AI rule match", "UNMAPPED"))
    attack_id = str(metadata.get("agentscan_id") or defaults[0])
    owasp_id = str(metadata.get("owasp_id") or defaults[2])
    name = defaults[1]
    semgrep_sev = str(extra.get("severity") or "").upper()
    severity = _SEVERITY_MAP.get(semgrep_sev, Severity.INFO)
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
            "severity_assessed": semgrep_sev in _SEVERITY_MAP,
        },
    )
