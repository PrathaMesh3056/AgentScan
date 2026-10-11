# tests/test_supply_chain/test_native_semgrep.py
#
# Comprehensive tests for AgentScan's Native AST Semgrep Rule Engine.

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from agentscan.core.models import Severity
from agentscan.supply_chain.native_semgrep import (
    NativeSemgrepEngine,
    default_rules_path,
    load_rules,
    scan_native_rules,
)
from agentscan.supply_chain.semgrep_auditor import scan_semgrep

_FIXTURE_DIR = Path("tests/fixtures/supply_chain")
_FIXTURE_FILE = _FIXTURE_DIR / "native_semgrep_samples.py"


class TestNativeSemgrepEngine:
    def test_load_default_rules(self) -> None:
        rules_path = default_rules_path()
        assert rules_path.is_file()
        rules = load_rules(rules_path)

        assert len(rules) >= 10
        assert "agentscan.unsafe-pickle-loads" in rules
        assert "agentscan.unsafe-torch-load" in rules
        assert "agentscan.subprocess-popen-shell" in rules
        assert "agentscan.os-system" in rules
        assert "agentscan.prompt-fstring-user-input" in rules
        assert "agentscan.prompt-format-user-input" in rules
        assert "agentscan.dangerous-eval-exec" in rules
        assert "agentscan.unsafe-numpy-load" in rules
        assert "agentscan.unsafe-joblib-load" in rules
        assert "agentscan.insecure-sqlite-tool" in rules

        pickle_rule = rules["agentscan.unsafe-pickle-loads"]
        assert pickle_rule.agentscan_id == "SC-015"
        assert pickle_rule.owasp_id == "LLM03"
        assert pickle_rule.severity == Severity.CRITICAL

    def test_scan_fixture_file_detects_all_vulnerabilities(self) -> None:
        findings, checks = scan_native_rules(str(_FIXTURE_FILE))
        assert checks == 1
        assert len(findings) >= 10

        rule_ids = {f.metadata.get("semgrep_check_id") for f in findings}
        assert "agentscan.unsafe-pickle-loads" in rule_ids
        assert "agentscan.unsafe-torch-load" in rule_ids
        assert "agentscan.subprocess-popen-shell" in rule_ids
        assert "agentscan.os-system" in rule_ids
        assert "agentscan.dangerous-eval-exec" in rule_ids
        assert "agentscan.unsafe-numpy-load" in rule_ids
        assert "agentscan.unsafe-joblib-load" in rule_ids
        assert "agentscan.insecure-sqlite-tool" in rule_ids
        assert "agentscan.prompt-fstring-user-input" in rule_ids
        assert "agentscan.prompt-format-user-input" in rule_ids

        # Verify finding attributes
        torch_finding = next(
            f
            for f in findings
            if f.metadata.get("semgrep_check_id") == "agentscan.unsafe-torch-load"
        )
        assert torch_finding.attack_id == "SC-011"
        assert torch_finding.severity == Severity.CRITICAL
        assert "weights_only=True" in torch_finding.remediation
        assert torch_finding.metadata.get("line") is not None
        assert "torch.load" in torch_finding.evidence

        eval_finding = next(
            f
            for f in findings
            if f.metadata.get("semgrep_check_id") == "agentscan.dangerous-eval-exec"
        )
        assert eval_finding.attack_id == "SC-019"
        assert eval_finding.severity == Severity.CRITICAL

        sql_finding = next(
            f
            for f in findings
            if f.metadata.get("semgrep_check_id") == "agentscan.insecure-sqlite-tool"
        )
        assert sql_finding.attack_id == "SC-020"
        assert sql_finding.severity == Severity.HIGH

    def test_directory_scan(self) -> None:
        findings, checks = scan_native_rules(str(_FIXTURE_DIR))
        assert checks >= 2
        assert len(findings) >= 10

    def test_syntax_error_resilience(self, tmp_path: Path) -> None:
        broken_file = tmp_path / "broken.py"
        broken_file.write_text("def broken_syntax(:\n    pass\n", encoding="utf-8")
        findings, checks = scan_native_rules(str(broken_file))
        assert checks == 0
        assert findings == []

    def test_semgrep_auditor_fallback_integration(self) -> None:
        # 1. Fallback disabled: returns empty when semgrep binary missing
        with patch("agentscan.supply_chain.semgrep_auditor.shutil.which", return_value=None):
            findings, checks = scan_semgrep(str(_FIXTURE_FILE), fallback_to_native=False)
            assert findings == []
            assert checks == 0

        # 2. Fallback enabled: delegates to native AST engine when semgrep binary missing
        with patch("agentscan.supply_chain.semgrep_auditor.shutil.which", return_value=None):
            findings, checks = scan_semgrep(str(_FIXTURE_FILE), fallback_to_native=True)
            assert checks == 1
            assert len(findings) >= 10
            assert any(
                f.metadata.get("semgrep_check_id") == "agentscan.unsafe-pickle-loads"
                for f in findings
            )

    def test_custom_rules_file(self, tmp_path: Path) -> None:
        custom_yaml = tmp_path / "custom_rules.yaml"
        custom_yaml.write_text(
            """
rules:
  - id: custom.eval-only
    severity: ERROR
    message: Disallowed eval
    metadata:
      agentscan_id: SC-999
      owasp_id: LLM05
      category: code-injection
    pattern: eval(...)
""",
            encoding="utf-8",
        )

        engine = NativeSemgrepEngine(rules_path=custom_yaml)
        assert len(engine.rules) == 1
        assert "custom.eval-only" in engine.rules

        test_code = tmp_path / "test_eval.py"
        test_code.write_text("def foo(x):\n    return eval(x)\n", encoding="utf-8")
        findings = engine.scan_file(test_code)
        assert len(findings) == 1
        assert findings[0].attack_id == "SC-999"
