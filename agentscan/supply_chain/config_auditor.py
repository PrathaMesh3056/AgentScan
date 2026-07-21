# agentscan/supply_chain/config_auditor.py
#
# Static AST-based configuration auditor.
#
# Walks every .py file in a directory tree and checks for:
#   SC-011 — torch.load() without weights_only=True
#   SC-011 — any function called with allow_dangerous_deserialization=True
#   SC-014 — module-level DEBUG = True assignment
#
# Uses stdlib ast only — no external dependencies.

from __future__ import annotations

import ast
from pathlib import Path

from loguru import logger

from agentscan.core.models import Finding, Severity

# ── AST helpers ───────────────────────────────────────────────────────────────


def _has_keyword(call: ast.Call, name: str, value: object) -> bool:
    """Return True if `call` has keyword `name` with boolean value `value`."""
    for kw in call.keywords:
        if kw.arg == name and isinstance(kw.value, ast.Constant) and kw.value.value == value:
            return True
    return False


def _is_torch_load(call: ast.Call) -> bool:
    """Return True if this call is torch.load(...)."""
    func = call.func
    if isinstance(func, ast.Attribute):
        return func.attr == "load" and isinstance(func.value, ast.Name) and func.value.id == "torch"
    return False


def _check_file(filepath: Path) -> list[Finding]:
    """Parse one .py file and return all SC-* findings for it."""
    findings: list[Finding] = []
    try:
        source = filepath.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source, filename=str(filepath))
    except SyntaxError as e:
        logger.warning(f"Skipping {filepath}: syntax error — {e}")
        return findings
    except Exception as e:
        logger.error(f"Failed to read {filepath}: {e}")
        return findings

    for node in ast.walk(tree):
        # ── torch.load without weights_only=True ──────────────────────────────
        if (
            isinstance(node, ast.Call)
            and _is_torch_load(node)
            and not _has_keyword(node, "weights_only", True)
        ):
            findings.append(
                Finding(
                    attack_id="SC-011",
                    attack_name="Unsafe model deserialisation",
                    severity=Severity.CRITICAL,
                    owasp_id="LLM05",
                    description=(
                        f"Call to torch.load() in '{filepath.name}' is missing "
                        f"weights_only=True. Loading untrusted model files without "
                        f"this flag allows arbitrary code execution via pickle."
                    ),
                    evidence=f"file={filepath}, line={node.lineno}",
                    remediation=(
                        "Add weights_only=True to torch.load(). "
                        "If the file is a full checkpoint (optimizer state etc.), "
                        "ensure the source is fully trusted before loading."
                    ),
                    metadata={"file": str(filepath), "line": node.lineno},
                )
            )

        # ── allow_dangerous_deserialization=True ──────────────────────────────
        if isinstance(node, ast.Call) and _has_keyword(
            node, "allow_dangerous_deserialization", True
        ):
            findings.append(
                Finding(
                    attack_id="SC-011",
                    attack_name="Unsafe model deserialisation",
                    severity=Severity.CRITICAL,
                    owasp_id="LLM05",
                    description=(
                        f"Call in '{filepath.name}' uses "
                        f"allow_dangerous_deserialization=True, which permits loading "
                        f"arbitrary pickled objects. This can execute attacker-controlled code."
                    ),
                    evidence=f"file={filepath}, line={node.lineno}",
                    remediation=(
                        "Remove allow_dangerous_deserialization=True. "
                        "Load only from sources you fully control and trust."
                    ),
                    metadata={"file": str(filepath), "line": node.lineno},
                )
            )

        # ── Module-level DEBUG = True ──────────────────────────────────────────
        if (
            isinstance(node, ast.Assign)
            and isinstance(node.value, ast.Constant)
            and node.value.value is True
        ):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "DEBUG":
                    findings.append(
                        Finding(
                            attack_id="SC-014",
                            attack_name="Debug mode enabled in production code",
                            severity=Severity.HIGH,
                            owasp_id="LLM05",
                            description=(
                                f"'DEBUG = True' found in '{filepath.name}'. "
                                f"Leaving debug mode enabled in production exposes "
                                f"stack traces, internal state, and may weaken security controls."
                            ),
                            evidence=f"file={filepath}, line={node.lineno}",
                            remediation=(
                                "Set DEBUG = False (or read from an environment variable) "
                                "before deploying to production."
                            ),
                            metadata={"file": str(filepath), "line": node.lineno},
                        )
                    )

    return findings


# ── Public scanner ────────────────────────────────────────────────────────────


def scan_config(path: str) -> tuple[list[Finding], int]:
    """
    Walk all .py files under `path` and check for dangerous configuration patterns.

    Returns:
        (findings, checks_run) where checks_run = number of .py files parsed.
    """
    root = Path(path)
    py_files = list(root.rglob("*.py"))
    checks_run = len(py_files)

    all_findings: list[Finding] = []
    for py_file in py_files:
        all_findings.extend(_check_file(py_file))

    return all_findings, checks_run
