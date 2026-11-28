"""Regression tests for QA-046: format-aware secret scanning.

The scanner previously only matched quoted ``KEY = "value"`` assignments, so a
YAML ``api_key: "sk-..."`` and an unquoted ``.env`` line were both reported as
COMPLETE/SAFE with zero findings.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentscan.supply_chain.secret_scanner import scan_secrets

_FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "secret_formats"

_DOTENV_SECRET = "sk-proj-QA046FakeDotenvSecret1234567890abcdef"
_DOTENV_QUOTED_SECRETS = {
    "sk-proj-QA046FakeQuotedDotenvSecret1234567890abcdef",
    "sk-ant-QA046FakeSingleQuotedDotenvSecret1234567890abcdef",
}
_YAML_QUOTED_SECRET = "sk-proj-QA046FakeYamlQuotedSecret1234567890abcdef"
_YAML_UNQUOTED_SECRET = "sk-proj-QA046FakeYamlUnquotedSecret1234567890abcdef"
_JSON_SECRET = "sk-proj-QA046FakeJsonSecret1234567890abcdef"
_TOML_SECRET = "sk-proj-QA046FakeTomlSecret1234567890abcdef"
_INI_SECRET = "sk-proj-QA046FakeIniSecret1234567890abcdef"


def _scan(directory: str) -> tuple[list, int, list[dict]]:
    coverage: list[dict] = []
    findings, checks = scan_secrets(str(_FIXTURES / directory), coverage=coverage)
    return findings, checks, coverage


def _serialized(findings: list) -> str:
    return json.dumps([finding.model_dump(mode="json") for finding in findings], default=str)


class TestFormatAwareSecretScanning:
    @pytest.mark.parametrize(
        ("directory", "expected_variables", "secret_values"),
        [
            ("dotenv_unquoted", {"OPENAI_API_KEY"}, {_DOTENV_SECRET}),
            (
                "yaml",
                {"api_key", "client_secret"},
                {_YAML_QUOTED_SECRET, _YAML_UNQUOTED_SECRET},
            ),
            ("json", {"api_key"}, {_JSON_SECRET}),
            ("toml", {"api_key"}, {_TOML_SECRET}),
        ],
    )
    def test_supported_formats_produce_findings(
        self,
        directory: str,
        expected_variables: set[str],
        secret_values: set[str],
    ) -> None:
        findings, checks, coverage = _scan(directory)

        assert checks == 1
        assert coverage[-1]["status"] == "COMPLETE"
        assert {finding.metadata["variable"] for finding in findings} >= expected_variables
        assert all(finding.attack_id == "SC-015" for finding in findings)

        rendered = _serialized(findings)
        for secret in secret_values:
            assert secret not in rendered

    def test_unquoted_dotenv_reports_the_assignment_line(self) -> None:
        findings, _checks, coverage = _scan("dotenv_unquoted")

        assert coverage[-1]["status"] == "COMPLETE"
        assert len(findings) == 1
        assert findings[0].metadata["variable"] == "OPENAI_API_KEY"
        assert findings[0].metadata["line"] == 2
        assert findings[0].metadata["format"] == "dotenv"
        assert _DOTENV_SECRET not in _serialized(findings)

    def test_quoted_dotenv_values_produce_findings(self) -> None:
        findings, checks, coverage = _scan("dotenv_quoted")

        assert checks == 1
        assert coverage[-1]["status"] == "COMPLETE"
        assert {finding.metadata["variable"] for finding in findings} == {
            "OPENAI_API_KEY",
            "ANTHROPIC_API_KEY",
        }
        assert all(finding.metadata["format"] == "dotenv" for finding in findings)
        rendered = _serialized(findings)
        for secret in _DOTENV_QUOTED_SECRETS:
            assert secret not in rendered

    def test_yaml_quoted_and_unquoted_assignments_both_produce_findings(self) -> None:
        findings, _checks, coverage = _scan("yaml")

        assert coverage[-1]["status"] == "COMPLETE"
        by_variable = {finding.metadata["variable"]: finding for finding in findings}
        assert by_variable["api_key"].metadata["line"] == 2
        assert by_variable["client_secret"].metadata["line"] == 4
        assert all(finding.metadata["format"] == "yaml" for finding in findings)

    def test_unsupported_format_is_inconclusive_not_clean(self) -> None:
        findings, checks, coverage = _scan("unsupported")

        # The heuristic still surfaces the obvious assignment, but the format
        # was not parsed and therefore can never count as a clean assessment.
        assert checks == 0
        assert coverage[-1]["status"] == "INCONCLUSIVE"
        assert coverage[-1]["inputs_selected"] == 1
        assert len(findings) == 1
        assert findings[0].metadata["variable"] == "api_key"
        assert _INI_SECRET not in _serialized(findings)
        limitations = " ".join(coverage[-1]["limitations"]).lower()
        assert "unsupported" in limitations
        assert "not assessed" in limitations

    @pytest.mark.parametrize(
        ("filename", "content"),
        [
            ("broken.yaml", "api_key: [unclosed\n"),
            ("broken.json", '{\n  "api_key": "sk-proj-QA046BrokenJson1234567890abcdef",\n}\n'),
            ("broken.toml", '[service\napi_key = "sk-proj-QA046BrokenToml1234567890abcdef"\n'),
        ],
    )
    def test_unparsable_format_is_inconclusive(
        self, tmp_path: Path, filename: str, content: str
    ) -> None:
        (tmp_path / filename).write_text(content, encoding="utf-8")
        coverage: list[dict] = []

        scan_secrets(str(tmp_path), coverage=coverage)

        assert coverage[-1]["status"] == "INCONCLUSIVE"
        assert any("not fully assessed" in issue for issue in coverage[-1]["limitations"])

    def test_yaml_line_parser_fallback_when_pyyaml_unavailable(self, monkeypatch) -> None:
        import agentscan.supply_chain.secret_scanner as secret_scanner

        monkeypatch.setattr(secret_scanner, "yaml", None)
        findings, checks, coverage = _scan("yaml")

        assert checks == 1
        assert coverage[-1]["status"] == "COMPLETE"
        assert {finding.metadata["variable"] for finding in findings} == {
            "api_key",
            "client_secret",
        }

    def test_clean_fixture_stays_clean(self) -> None:
        findings, checks, coverage = _scan("clean")

        assert findings == []
        assert checks == 6
        assert coverage[-1]["status"] == "COMPLETE"
        assert coverage[-1]["limitations"] == []


class TestSecretScanningCliRegression:
    def test_cli_yaml_secret_is_not_false_clean(self) -> None:
        from typer.testing import CliRunner

        from agentscan.cli import app

        result = CliRunner().invoke(
            app, ["audit", str(_FIXTURES / "yaml"), "--scan-secrets"]
        )

        assert result.exit_code == 0, result.output
        assert "SC-015" in result.output
        assert "100/100" not in result.output
        assert "[SAFE]" not in result.output
        assert _YAML_QUOTED_SECRET not in result.output
        assert _YAML_UNQUOTED_SECRET not in result.output

    def test_cli_unquoted_dotenv_is_not_false_clean(self) -> None:
        from typer.testing import CliRunner

        from agentscan.cli import app

        result = CliRunner().invoke(
            app, ["audit", str(_FIXTURES / "dotenv_unquoted"), "--scan-secrets"]
        )

        assert result.exit_code == 0, result.output
        assert "SC-015" in result.output
        assert "100/100" not in result.output
        assert _DOTENV_SECRET not in result.output

    def test_cli_unsupported_format_is_not_safe(self) -> None:
        from typer.testing import CliRunner

        from agentscan.cli import app

        result = CliRunner().invoke(
            app, ["audit", str(_FIXTURES / "unsupported"), "--scan-secrets"]
        )

        assert result.exit_code == 0, result.output
        assert "SC-015" in result.output
        assert "INCONCLUSIVE" in result.output
        assert "100/100" not in result.output
        assert "[SAFE]" not in result.output
        assert _INI_SECRET not in result.output
