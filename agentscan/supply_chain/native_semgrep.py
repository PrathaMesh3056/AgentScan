# agentscan/supply_chain/native_semgrep.py
#
# Native Python AST implementation of Semgrep AI security rules.
# Provides a zero-external-dependency fallback runner when the external
# `semgrep` binary is not installed on PATH.

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from loguru import logger

from agentscan.core.models import Finding, Severity

_SEVERITY_MAP: dict[str, Severity] = {
    "ERROR": Severity.CRITICAL,
    "WARNING": Severity.HIGH,
    "INFO": Severity.MEDIUM,
}

_PROMPT_VAR_KEYWORDS = {
    "user_input",
    "user_msg",
    "user_message",
    "user_prompt",
    "input_text",
    "untrusted",
    "query",
    "prompt",
    "message",
    "payload",
}

_PROMPT_TEXT_INDICATORS = {
    "user said",
    "system:",
    "human:",
    "user:",
    "assistant:",
    "you are a",
    "instructions:",
    "prompt:",
}


@dataclass(frozen=True)
class SemgrepRule:
    """Parsed representation of a Semgrep rule."""

    id: str
    severity: Severity
    message: str
    agentscan_id: str
    owasp_id: str
    category: str
    pattern_kind: str


def default_rules_path() -> Path:
    """Locate rules/ai_rules.yaml."""
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


def _detect_pattern_kind(rule_id: str, item: dict[str, Any]) -> str:
    """Classify the rule into a supported AST inspection kind."""
    pattern_str = (
        str(item.get("pattern") or "")
        + " "
        + str(item.get("pattern-either") or "")
        + " "
        + str(item.get("patterns") or "")
    ).lower()
    rule_id_lower = rule_id.lower()

    if "pickle.loads" in pattern_str or "pickle" in rule_id_lower:
        return "pickle"
    if "torch.load" in pattern_str or "torch" in rule_id_lower:
        return "torch"
    if "subprocess" in pattern_str or "shell=true" in pattern_str:
        return "subprocess_shell"
    if "os.system" in pattern_str:
        return "os_system"
    if (
        "eval(" in pattern_str
        or "exec(" in pattern_str
        or "eval" in rule_id_lower
        or "exec" in rule_id_lower
    ):
        return "eval_exec"
    if "numpy.load" in pattern_str or "allow_pickle" in pattern_str:
        return "numpy_pickle"
    if "joblib.load" in pattern_str or "joblib" in rule_id_lower:
        return "joblib"
    if "execute(" in pattern_str or "sql" in rule_id_lower:
        return "sql"
    if "fstring" in rule_id_lower or 'f"' in pattern_str:
        return "prompt_fstring"
    if "format" in rule_id_lower or ".format(" in pattern_str:
        return "prompt_format"
    return "generic"


def load_rules(rules_path: Path | str | None = None) -> dict[str, SemgrepRule]:
    """Load and index Semgrep rules from YAML file."""
    path = Path(rules_path) if rules_path is not None else default_rules_path()
    if not path.is_file():
        logger.warning(f"Semgrep rules file not found at {path}; using empty rule set.")
        return {}

    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning(f"Failed to parse Semgrep rules YAML from {path}: {exc}")
        return {}

    rules: dict[str, SemgrepRule] = {}
    for item in data.get("rules", []) if isinstance(data, dict) else []:
        rule_id = str(item.get("id") or "").strip()
        if not rule_id:
            continue
        sev_str = str(item.get("severity") or "WARNING").upper()
        severity = _SEVERITY_MAP.get(sev_str, Severity.HIGH)
        message = str(item.get("message") or rule_id).strip()
        metadata = item.get("metadata") or {}
        kind = _detect_pattern_kind(rule_id, item)
        rules[rule_id] = SemgrepRule(
            id=rule_id,
            severity=severity,
            message=message,
            agentscan_id=str(metadata.get("agentscan_id") or "SC-018"),
            owasp_id=str(metadata.get("owasp_id") or "LLM05"),
            category=str(metadata.get("category") or "security"),
            pattern_kind=kind,
        )
    return rules


# ── AST Pattern Inspection Helpers ────────────────────────────────────────────


def _has_keyword(call: ast.Call, name: str, value: Any) -> bool:
    """Return True if `call` has keyword argument `name` with exact value `value`."""
    for kw in call.keywords:
        if kw.arg == name and isinstance(kw.value, ast.Constant) and kw.value.value == value:
            return True
    return False


def _get_call_name(func: ast.AST) -> str:
    """Extract dotted function call name from AST node."""
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        parent = _get_call_name(func.value)
        return f"{parent}.{func.attr}" if parent else func.attr
    return ""


def _contains_prompt_keyword(name: str) -> bool:
    """Return True if the variable name matches a prompt/user input keyword."""
    name_lower = name.lower()
    return any(kw in name_lower for kw in _PROMPT_VAR_KEYWORDS)


def _is_prompt_fstring(node: ast.JoinedStr) -> bool:
    """Check if an f-string interpolates user/prompt variables."""
    has_user_var = False
    has_prompt_indicator = False

    # Check text parts
    for val in node.values:
        if isinstance(val, ast.Constant) and isinstance(val.value, str):
            text = val.value.lower()
            if any(ind in text for ind in _PROMPT_TEXT_INDICATORS):
                has_prompt_indicator = True
        elif isinstance(val, ast.FormattedValue):
            expr = val.value
            if (
                (isinstance(expr, ast.Name) and _contains_prompt_keyword(expr.id))
                or (isinstance(expr, ast.Attribute) and _contains_prompt_keyword(expr.attr))
                or (
                    isinstance(expr, ast.Subscript)
                    and isinstance(expr.slice, ast.Constant)
                    and isinstance(expr.slice.value, str)
                    and _contains_prompt_keyword(expr.slice.value)
                )
            ):
                has_user_var = True

    return has_user_var or (
        has_prompt_indicator and any(isinstance(v, ast.FormattedValue) for v in node.values)
    )


def _is_prompt_format_call(node: ast.Call) -> bool:
    """Check if a .format() call interpolates untrusted user variables into prompts."""
    if not (isinstance(node.func, ast.Attribute) and node.func.attr == "format"):
        return False

    caller = node.func.value
    is_prompt_template = False
    if isinstance(caller, ast.Constant) and isinstance(caller.value, str):
        text = caller.value.lower()
        is_prompt_template = any(ind in text for ind in _PROMPT_TEXT_INDICATORS)
    elif isinstance(caller, ast.Name) and _contains_prompt_keyword(caller.id):
        is_prompt_template = True

    has_user_arg = False
    for arg in node.args:
        if isinstance(arg, ast.Name) and _contains_prompt_keyword(arg.id):
            has_user_arg = True
            break
    for kw in node.keywords:
        if kw.arg and _contains_prompt_keyword(kw.arg):
            has_user_arg = True
            break
        if isinstance(kw.value, ast.Name) and _contains_prompt_keyword(kw.value.id):
            has_user_arg = True
            break

    return has_user_arg and (is_prompt_template or True)


def _is_sql_interpolation(node: ast.Call) -> bool:
    """Check if a database/cursor .execute() call uses string interpolation."""
    if not (isinstance(node.func, ast.Attribute) and node.func.attr in ("execute", "executemany")):
        return False
    if not node.args:
        return False

    first_arg = node.args[0]
    # JoinedStr (f-string): cursor.execute(f"SELECT ...")
    if isinstance(first_arg, ast.JoinedStr):
        return True
    # BinOp with %: cursor.execute("SELECT ... %s" % var)
    if isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, ast.Mod):
        return True
    # Call to .format(): cursor.execute("SELECT ... {}".format(var))
    return (
        isinstance(first_arg, ast.Call)
        and isinstance(first_arg.func, ast.Attribute)
        and first_arg.func.attr == "format"
    )


# ── Native AST File Auditor ───────────────────────────────────────────────────


class NativeSemgrepEngine:
    """Inspects Python source AST using Semgrep rule definitions."""

    def __init__(self, rules_path: Path | str | None = None) -> None:
        self.rules = load_rules(rules_path)
        self._rules_by_kind: dict[str, list[SemgrepRule]] = {}
        for rule in self.rules.values():
            self._rules_by_kind.setdefault(rule.pattern_kind, []).append(rule)

    def _get_rules(self, kind: str) -> list[SemgrepRule]:
        return self._rules_by_kind.get(kind, [])

    def scan_file(self, filepath: Path) -> list[Finding]:
        """Scan a single Python file against all registered rules."""
        findings: list[Finding] = []
        try:
            source = filepath.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source, filename=str(filepath))
        except SyntaxError as exc:
            logger.warning(f"Syntax error parsing {filepath}: {exc}")
            return []
        except Exception as exc:
            logger.error(f"Failed to read {filepath}: {exc}")
            return []

        lines = source.splitlines()

        def get_line_snippet(lineno: int) -> str:
            if 1 <= lineno <= len(lines):
                return lines[lineno - 1].strip()
            return ""

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                call_name = _get_call_name(node.func)
                lineno = getattr(node, "lineno", 1)
                snippet = get_line_snippet(lineno)

                # 1. pickle.loads / _pickle.loads (pattern_kind: pickle)
                if call_name in ("pickle.loads", "_pickle.loads"):
                    for rule in self._get_rules("pickle"):
                        findings.append(
                            self._build_finding(
                                rule=rule,
                                filepath=filepath,
                                lineno=lineno,
                                snippet=snippet,
                                description=f"Call to {call_name}() in '{filepath.name}' deserializes untrusted bytes with pickle.",
                                remediation="Replace with safe serialization (e.g., json.loads or pydantic).",
                            )
                        )

                # 2. torch.load without weights_only=True (pattern_kind: torch)
                elif call_name == "torch.load":
                    if not _has_keyword(node, "weights_only", True):
                        for rule in self._get_rules("torch"):
                            findings.append(
                                self._build_finding(
                                    rule=rule,
                                    filepath=filepath,
                                    lineno=lineno,
                                    snippet=snippet,
                                    description=f"torch.load() in '{filepath.name}' is missing weights_only=True.",
                                    remediation="Add weights_only=True to torch.load() to prevent arbitrary pickle execution.",
                                )
                            )

                # 3. subprocess.* with shell=True (pattern_kind: subprocess_shell)
                elif call_name in (
                    "subprocess.Popen",
                    "subprocess.run",
                    "subprocess.call",
                    "subprocess.check_call",
                    "subprocess.check_output",
                ) and _has_keyword(node, "shell", True):
                    for rule in self._get_rules("subprocess_shell"):
                        findings.append(
                            self._build_finding(
                                rule=rule,
                                filepath=filepath,
                                lineno=lineno,
                                snippet=snippet,
                                description=f"{call_name}(..., shell=True) in '{filepath.name}' executes via shell metacharacters.",
                                remediation="Pass command as a sequence (list) and set shell=False.",
                            )
                        )

                # 4. os.system (pattern_kind: os_system)
                elif call_name == "os.system":
                    for rule in self._get_rules("os_system"):
                        findings.append(
                            self._build_finding(
                                rule=rule,
                                filepath=filepath,
                                lineno=lineno,
                                snippet=snippet,
                                description=f"os.system() call in '{filepath.name}' executes commands in a shell.",
                                remediation="Use subprocess.run(args, shell=False, check=True) instead of os.system.",
                            )
                        )

                # 5. eval / exec (pattern_kind: eval_exec)
                elif call_name in ("eval", "exec"):
                    for rule in self._get_rules("eval_exec"):
                        findings.append(
                            self._build_finding(
                                rule=rule,
                                filepath=filepath,
                                lineno=lineno,
                                snippet=snippet,
                                description=f"Dangerous dynamic code execution '{call_name}()' in '{filepath.name}'.",
                                remediation="Avoid eval/exec; use safe parsers like ast.literal_eval or structured handlers.",
                            )
                        )

                # 6. numpy.load allow_pickle=True (pattern_kind: numpy_pickle)
                elif call_name in ("numpy.load", "np.load") and _has_keyword(
                    node, "allow_pickle", True
                ):
                    for rule in self._get_rules("numpy_pickle"):
                        findings.append(
                            self._build_finding(
                                rule=rule,
                                filepath=filepath,
                                lineno=lineno,
                                snippet=snippet,
                                description=f"{call_name}(..., allow_pickle=True) in '{filepath.name}' permits pickle execution.",
                                remediation="Set allow_pickle=False or use safetensors/npy array files without pickled objects.",
                            )
                        )

                # 7. joblib.load (pattern_kind: joblib)
                elif call_name == "joblib.load":
                    for rule in self._get_rules("joblib"):
                        findings.append(
                            self._build_finding(
                                rule=rule,
                                filepath=filepath,
                                lineno=lineno,
                                snippet=snippet,
                                description=f"joblib.load() in '{filepath.name}' deserializes untrusted model files with pickle.",
                                remediation="Verify model integrity using cryptographic hashes or migrate to ONNX/safetensors.",
                            )
                        )

                # 8. SQL query string interpolation (pattern_kind: sql)
                elif _is_sql_interpolation(node):
                    for rule in self._get_rules("sql"):
                        findings.append(
                            self._build_finding(
                                rule=rule,
                                filepath=filepath,
                                lineno=lineno,
                                snippet=snippet,
                                description=f"SQL query execution with string interpolation in '{filepath.name}'.",
                                remediation="Use parameterized queries (e.g. cursor.execute('SELECT ... WHERE x = ?', (val,))) instead of f-strings.",
                            )
                        )

                # 9. Prompt format call (pattern_kind: prompt_format)
                elif _is_prompt_format_call(node):
                    for rule in self._get_rules("prompt_format"):
                        findings.append(
                            self._build_finding(
                                rule=rule,
                                filepath=filepath,
                                lineno=lineno,
                                snippet=snippet,
                                description=f"str.format() interpolates untrusted input into prompt in '{filepath.name}'.",
                                remediation="Sanitize input or use structured chat messages (roles user/system) instead of raw string templates.",
                            )
                        )

            # 10. Prompt f-string interpolation (pattern_kind: prompt_fstring)
            elif isinstance(node, ast.JoinedStr) and _is_prompt_fstring(node):
                lineno = getattr(node, "lineno", 1)
                snippet = get_line_snippet(lineno)
                for rule in self._get_rules("prompt_fstring"):
                    findings.append(
                        self._build_finding(
                            rule=rule,
                            filepath=filepath,
                            lineno=lineno,
                            snippet=snippet,
                            description=f"f-string interpolates user input into prompt in '{filepath.name}'.",
                            remediation="Avoid concatenating user input directly into system prompt instructions.",
                        )
                    )

        return findings

    def _build_finding(
        self,
        rule: SemgrepRule,
        filepath: Path,
        lineno: int,
        snippet: str,
        description: str,
        remediation: str,
    ) -> Finding:
        evidence = f"file={filepath}, line={lineno}"
        if snippet:
            evidence = f"{evidence}: {snippet}"
        return Finding(
            attack_id=rule.agentscan_id,
            attack_name=rule.category.replace("-", " ").title(),
            severity=rule.severity,
            owasp_id=rule.owasp_id,
            description=description,
            evidence=evidence,
            remediation=remediation,
            metadata={
                "file": str(filepath),
                "line": lineno,
                "semgrep_check_id": rule.id,
                "engine": "native_ast",
            },
        )


# ── Public API ────────────────────────────────────────────────────────────────


def scan_native_rules(
    path: str,
    rules_path: Path | str | None = None,
) -> tuple[list[Finding], int]:
    """
    Run the native AST Semgrep rule engine against a file or directory tree.

    Returns:
        (findings, checks_run) where checks_run is the number of Python files analyzed.
    """
    engine = NativeSemgrepEngine(rules_path)
    target = Path(path)

    if target.is_file() and target.suffix == ".py":
        findings = engine.scan_file(target)
        return findings, 1

    if not target.is_dir():
        return [], 0

    ignored_dirs = {
        ".git",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        ".pytest_cache",
        "build",
        "dist",
    }
    py_files = sorted(
        p for p in target.rglob("*.py") if not any(part in ignored_dirs for part in p.parts)
    )
    all_findings: list[Finding] = []
    for py_file in py_files:
        all_findings.extend(engine.scan_file(py_file))

    return all_findings, len(py_files)
