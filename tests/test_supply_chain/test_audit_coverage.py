"""Unavailable and partially parsed inputs cannot become a clean static score."""

from __future__ import annotations

import json
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

import pytest

from agentscan.identity.manifest_loader import load_manifests
from agentscan.identity.orchestrator import run_identity_audit
from agentscan.supply_chain.config_auditor import scan_config
from agentscan.supply_chain.dep_scanner import scan_dependencies
from agentscan.supply_chain.framework_auditor import scan_frameworks
from agentscan.supply_chain.mcp_auditor import scan_mcp_configs
from agentscan.supply_chain.native_semgrep import scan_native_rules
from agentscan.supply_chain.secret_scanner import scan_secrets
from agentscan.supply_chain.semgrep_auditor import scan_semgrep
from agentscan.supply_chain.typosquat_detector import scan_typosquats


@pytest.mark.parametrize("scanner", [scan_config, scan_frameworks, scan_native_rules])
def test_failed_python_input_preserves_partial_coverage(tmp_path, scanner):
    (tmp_path / "good.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "broken.py").write_text("def broken(:\n", encoding="utf-8")
    coverage = []
    findings, checks = scanner(str(tmp_path), coverage=coverage)
    assert findings == []
    assert checks == 1
    assert coverage[-1]["inputs_selected"] == 2
    assert coverage[-1]["status"] == "INCONCLUSIVE"
    assert "SyntaxError" in " ".join(coverage[-1]["limitations"])


@pytest.mark.parametrize(
    "scanner",
    [
        scan_config,
        scan_frameworks,
        scan_native_rules,
        scan_mcp_configs,
        scan_secrets,
        scan_typosquats,
        scan_semgrep,
    ],
)
def test_missing_selected_path_is_not_assessed_as_clean(tmp_path, scanner):
    coverage = []
    findings, checks = scanner(str(tmp_path / "missing"), coverage=coverage)
    assert findings == []
    assert checks == 0
    assert coverage[-1]["status"] == "INCONCLUSIVE"


def test_native_empty_and_unsupported_rules_cannot_count_clean_checks(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("danger()\n", encoding="utf-8")
    rules = tmp_path / "rules.yaml"
    for content in [
        "rules: []\n",
        "rules: [broken]\n",
        "rules:\n- id: custom\n  severity: ERROR\n  pattern: danger(...)\n",
    ]:
        rules.write_text(content, encoding="utf-8")
        coverage = []
        findings, checks = scan_native_rules(str(source), rules_path=rules, coverage=coverage)
        assert findings == []
        assert checks == 0
        assert coverage[-1]["status"] == "INCONCLUSIVE"


def test_semgrep_missing_fallback_retains_both_provenances(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("import torch\nx = torch.load('weights')\n", encoding="utf-8")
    coverage = []
    with patch("agentscan.supply_chain.semgrep_auditor.shutil.which", return_value=None):
        findings, checks = scan_semgrep(str(source), fallback_to_native=True, coverage=coverage)
    assert checks == 1
    assert findings
    assert [entry["source"] for entry in coverage] == ["semgrep", "native_ast_subset"]
    assert all(entry["status"] == "INCONCLUSIVE" for entry in coverage)


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {},
        {"paths": {"scanned": "bad"}, "results": []},
        {"paths": {"scanned": ["a.py"]}, "results": ["bad"]},
    ],
)
def test_malformed_semgrep_output_is_explicitly_incomplete(tmp_path, payload):
    completed = CompletedProcess(["semgrep"], 0, json.dumps(payload), "")
    coverage = []
    with patch("agentscan.supply_chain.semgrep_auditor.subprocess.run", return_value=completed):
        findings, _checks = scan_semgrep(str(tmp_path), semgrep_bin="semgrep", coverage=coverage)
    assert findings == []
    assert coverage[-1]["status"] == "INCONCLUSIVE"


def test_semgrep_partial_errors_retain_real_findings_and_withhold_complete_status(tmp_path):
    payload = {
        "paths": {"scanned": ["good.py", "good.py"], "skipped": [{"path": "large.py"}]},
        "errors": [{"type": "PartialParsing", "path": "broken.py"}],
        "results": [
            {
                "check_id": "agentscan.unsafe-torch-load",
                "path": "good.py",
                "extra": {"severity": "ERROR"},
            }
        ],
    }
    completed = CompletedProcess(["semgrep"], 0, json.dumps(payload), "")
    coverage = []
    with patch("agentscan.supply_chain.semgrep_auditor.subprocess.run", return_value=completed):
        findings, checks = scan_semgrep(str(tmp_path), semgrep_bin="semgrep", coverage=coverage)
    assert checks == 1
    assert findings[0].attack_id == "SC-011"
    assert coverage[-1]["status"] == "INCONCLUSIVE"
    assert len(coverage[-1]["limitations"]) == 2


@pytest.mark.parametrize("severity", [None, "FUTURE_UNKNOWN"])
def test_semgrep_unknown_severity_is_unscored_instead_of_invented_high(tmp_path, severity):
    payload = {
        "paths": {"scanned": ["app.py"]},
        "results": [
            {
                "check_id": "agentscan.unsafe-torch-load",
                "path": "app.py",
                "extra": {"severity": severity},
            }
        ],
    }
    completed = CompletedProcess(["semgrep"], 0, json.dumps(payload), "")
    coverage = []
    with patch("agentscan.supply_chain.semgrep_auditor.subprocess.run", return_value=completed):
        findings, checks = scan_semgrep(str(tmp_path), semgrep_bin="semgrep", coverage=coverage)
    assert checks == 1
    assert findings[0].severity.value == "INFO"
    assert findings[0].metadata["severity_assessed"] is False
    assert coverage[-1]["status"] == "INCONCLUSIVE"


def test_secret_reader_failure_is_not_counted(tmp_path):
    failed = tmp_path / "failed.env"
    failed.write_text("SECRET = 'abc'", encoding="utf-8")
    (tmp_path / "good.py").write_text("x = 1", encoding="utf-8")
    original = Path.read_text

    def read_text(self, *args, **kwargs):
        if self == failed:
            raise PermissionError("unreadable")
        return original(self, *args, **kwargs)

    coverage = []
    with patch.object(Path, "read_text", read_text):
        findings, checks = scan_secrets(str(tmp_path), coverage=coverage)
    assert findings == []
    assert checks == 1
    assert coverage[-1]["status"] == "INCONCLUSIVE"


def test_binary_secret_input_is_unassessed(tmp_path):
    (tmp_path / "binary.dat").write_bytes(b"\xff\x00")
    coverage = []
    _, checks = scan_secrets(str(tmp_path), coverage=coverage)
    assert checks == 0
    assert coverage[-1]["status"] == "INCONCLUSIVE"


def test_malformed_identity_manifest_withholds_score_and_records_declaration_scope(tmp_path):
    (tmp_path / "good.agent.json").write_text(
        json.dumps({"agent_id": "good", "tools": []}), encoding="utf-8"
    )
    (tmp_path / "bad.agent.json").write_text("[]", encoding="utf-8")
    report = run_identity_audit(str(tmp_path))
    assert len(report.agents_found) == 1
    assert report.identity_score is None
    assert report.status == "INCONCLUSIVE"
    assert report.audit_coverage[0]["runtime_permissions_verified"] is False
    assert report.audit_coverage[0]["inputs_selected"] == 2


def test_identity_supports_explicit_manifest_file_without_claiming_deployed_permissions(tmp_path):
    manifest = tmp_path / "one.agent.json"
    manifest.write_text(json.dumps({"agent_id": "one", "tools": []}), encoding="utf-8")
    coverage = []
    assert len(load_manifests(manifest, coverage=coverage)) == 1
    assert coverage[0]["status"] == "COMPLETE"
    assert coverage[0]["runtime_permissions_verified"] is False


@pytest.mark.parametrize(
    "data",
    [{"tools": [{"name": "tool", "scopes": None}]}, {"mcpServers": {"remote": {}}}, {"auth": None}],
)
def test_unsupported_mcp_config_is_not_clean(tmp_path, data):
    (tmp_path / "tool.mcp.json").write_text(json.dumps(data), encoding="utf-8")
    coverage = []
    findings, checks = scan_mcp_configs(str(tmp_path), coverage=coverage)
    assert findings == []
    assert checks == 0
    assert coverage[-1]["status"] == "INCONCLUSIVE"


def test_typosquat_missing_database_cannot_count_clean_dependencies(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.32.4\n", encoding="utf-8")
    coverage = []
    with patch(
        "agentscan.supply_chain.typosquat_detector._TYPOSQUAT_DB", tmp_path / "missing.yaml"
    ):
        findings, checks = scan_typosquats(str(tmp_path), coverage=coverage)
    assert findings == []
    assert checks == 0
    assert coverage[-1]["status"] == "INCONCLUSIVE"


def test_malformed_dependency_declaration_is_retained_as_incomplete(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\ndependencies = ["requests==2.32.4", "broken ???", 7]\n', encoding="utf-8"
    )
    coverage = []
    _, checks = scan_dependencies(str(tmp_path), offline=True, coverage=coverage)
    assert checks == 1
    assert coverage[0]["status"] == "INCONCLUSIVE"
    assert len(coverage[0]["limitations"]) == 3


def test_cli_partial_static_audit_exports_null_score(tmp_path):
    from typer.testing import CliRunner

    from agentscan.cli import app

    (tmp_path / "good.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "broken.py").write_text("def broken(:\n", encoding="utf-8")
    output = tmp_path / "report.json"
    result = CliRunner().invoke(
        app, ["audit", str(tmp_path), "--scan-config", "--output", str(output)]
    )
    assert result.exit_code == 0, result.output
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["identity_score"] is None
    assert report["status"] == "INCONCLUSIVE"
    assert report["audit_coverage"][0]["checks_run"] == 1


def test_dashboard_partial_static_audit_exports_null_score(tmp_path):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from agentscan.ui.app import create_app

    (tmp_path / "good.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "broken.py").write_text("def broken(:\n", encoding="utf-8")
    client = TestClient(create_app(project_root=tmp_path))
    client.get("/")
    response = client.post(
        "/api/audit",
        json={
            "path": str(tmp_path),
            "scan_config": True,
            "scan_deps": False,
            "scan_secrets": False,
            "scan_typo": False,
            "scan_mcp": False,
            "scan_identity": False,
            "scan_frameworks": False,
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["score"] is None
    assert response.json()["status"] == "INCONCLUSIVE"
