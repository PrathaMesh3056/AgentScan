"""Copy-paste documentation tests for issue #41 (QA-086/108/120/121/122/175).

These tests treat the documentation as executable interface: commands, flags,
environment variables, endpoints and links must exist in the shipped code, and
the documented synthetic fixture must actually run. They do not prove deployed
certification, compliance or production readiness.
"""

from __future__ import annotations

import json
import re
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
API_DOC = ROOT / "docs" / "api.md"
MANUAL = ROOT / "docs" / "AgentScan_Manual.md"
FEATURE_MATRIX = ROOT / "docs" / "dashboard_feature_matrix.md"
DASHBOARD_JS = ROOT / "agentscan" / "ui" / "static" / "dashboard-app-core.js"
RUNBOOK = ROOT / "docs" / "RUNTIME_GATEWAY_RUNBOOK.md"
PLAN = ROOT / "docs" / "qa" / "issue-041-docs-claims.md"


def _section(text: str, heading: str, next_pattern: str) -> str:
    start = text.index(heading)
    rest = text[start + len(heading) :]
    match = re.search(next_pattern, rest)
    return rest[: match.start()] if match else rest


def _quickstart() -> str:
    return _section(
        API_DOC.read_text(encoding="utf-8"), "## Local quickstart (copy-paste)", r"\n## "
    )


def _heal_section() -> str:
    return _section(MANUAL.read_text(encoding="utf-8"), "### 3.11. ", r"\n### 3\.12\.")


def _api_source() -> str:
    return "\n".join(
        path.read_text(encoding="utf-8") for path in (ROOT / "agentscan" / "api").glob("*.py")
    )


def _server_routes() -> set[str]:
    source = (ROOT / "agentscan" / "api" / "server.py").read_text(encoding="utf-8")
    routes = set(re.findall(r'@app\.(?:get|post|delete|put)\("([^"]+)"', source))
    return {route for route in routes if route != "/"}


def test_quickstart_exports_every_required_variable() -> None:
    section = _quickstart()
    exported = set(re.findall(r"export (AGENTSCAN_[A-Z0-9_]+)=", section))
    required = {
        "AGENTSCAN_DATABASE_URL",
        "AGENTSCAN_REDIS_URL",
        "AGENTSCAN_JWT_PRIVATE_KEY_FILE",
        "AGENTSCAN_DATA_KEY_FILE",
        "AGENTSCAN_TENANT_CREDENTIALS_JSON",
        "AGENTSCAN_ALLOWED_TARGET_HOSTS",
        "AGENTSCAN_TENANT_POLICIES_JSON",
    }
    assert required <= exported, f"quickstart omits {sorted(required - exported)}"

    api_source = _api_source()
    compose = (ROOT / "docker-compose.api.yml").read_text(encoding="utf-8")
    for variable in sorted(exported):
        assert variable in api_source or variable in compose, (
            f"documented variable {variable} is not read by the shipped API or Compose file"
        )


def test_quickstart_does_not_use_retired_enrollment_variables() -> None:
    section = _quickstart()
    assert "AGENTSCAN_TOKEN_PSK" not in section
    assert "dev-psk" not in section


def test_quickstart_commands_and_flags_are_shipped() -> None:
    from typer.testing import CliRunner

    from agentscan.cli import app

    section = _quickstart()
    invocations = re.findall(r"agentscan api (serve|worker)([^\n```]*)", section)
    assert invocations, "quickstart does not document any agentscan api command"
    assert {command for command, _ in invocations} >= {"serve", "worker"}

    runner = CliRunner()
    help_by_command: dict[str, str] = {}
    for command, arguments in invocations:
        if command not in help_by_command:
            result = runner.invoke(app, ["api", command, "--help"])
            assert result.exit_code == 0, result.output
            help_by_command[command] = result.output
        for flag in re.findall(r"--[a-z0-9-]+", arguments):
            assert flag in help_by_command[command], (
                f"documented flag {flag} is not accepted by agentscan api {command}"
            )


def test_quickstart_endpoints_are_shipped() -> None:
    section = _quickstart()
    routes = _server_routes()
    assert {"/token", "/scans", "/health/ready"} <= routes

    documented = set()
    for raw in re.findall(r"http://127\.0\.0\.1:8081([^\s\"' ]*)", section):
        path = raw.split("?")[0].rstrip("\\")
        path = path.replace("$SCAN_ID", "{scan_id}")
        if path:
            documented.add(path)
    missing = documented - routes
    assert not missing, f"documented endpoints are not shipped: {sorted(missing)}"


def test_api_doc_relative_links_resolve() -> None:
    text = API_DOC.read_text(encoding="utf-8")
    for target in re.findall(r"\]\(([^)\s]+)\)", text):
        if target.startswith(("http://", "https://", "mailto:", "#")):
            continue
        relative = target.split("#", 1)[0]
        assert (API_DOC.parent / relative).exists(), f"broken documentation link: {target}"


def test_documented_fixture_target_runs(tmp_path: Path) -> None:
    section = _quickstart()
    blocks = re.findall(r"```python\n(.*?)```", section, re.DOTALL)
    assert len(blocks) == 1, "quickstart must contain exactly one Python fixture block"
    script = tmp_path / "fixture_target.py"
    script.write_text(blocks[0], encoding="utf-8")

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]

    process = subprocess.Popen(
        [sys.executable, str(script), str(port)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    break
            except OSError:
                time.sleep(0.05)
        else:
            raise AssertionError("documented fixture target did not start")

        request = urllib.request.Request(
            f"http://127.0.0.1:{port}/chat",
            data=b'{"message": "synthetic"}',
            headers={"content-type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            assert response.status == 200
            payload = json.loads(response.read())
        assert isinstance(payload, dict) and payload
    finally:
        process.terminate()
        process.wait(timeout=10)


def test_heal_runbook_lists_every_required_variable() -> None:
    section = _heal_section()
    documented = set(re.findall(r"AGENTSCAN_HEAL_[A-Z_]+", section))
    receiver = (ROOT / "agentscan" / "remediation" / "webhook_receiver.py").read_text(
        encoding="utf-8"
    )
    required = set(re.findall(r"AGENTSCAN_HEAL_[A-Z_]+", receiver))

    assert required == {
        "AGENTSCAN_HEAL_TOKEN",
        "AGENTSCAN_HEAL_ROOT",
        "AGENTSCAN_HEAL_ALLOW_APPLY",
    }
    assert documented == required, f"heal documentation is missing {sorted(required - documented)}"
    assert "503" in section
    assert "401" in section
    assert "AGENTSCAN_HEAL_ALLOW_APPLY" in section and "=1" in section


def test_gateway_copy_matches_shipped_command() -> None:
    dashboard = DASHBOARD_JS.read_text(encoding="utf-8")
    matrix = FEATURE_MATRIX.read_text(encoding="utf-8")
    runbook = RUNBOOK.read_text(encoding="utf-8")

    assert "Phase 5" not in dashboard, "dashboard still advertises the Phase 5 placeholder"
    assert "Phase 5" not in matrix, "feature matrix still advertises the Phase 5 placeholder"
    assert "agentscan-gateway serve" in dashboard
    assert "agentscan-gateway serve" in matrix

    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'agentscan-gateway = "agentscan.gateway.cli:main"' in pyproject

    assert "exits with a usage error" not in runbook
    assert "verify is not available yet" in runbook


def test_production_and_compliance_claims_are_qualified() -> None:
    manual = MANUAL.read_text(encoding="utf-8").lower()
    forbidden = (
        "certified audit report",
        "production-grade asynchronous rest api",
        "thousands of concurrent scans",
        "tamper-proof",
    )
    for phrase in forbidden:
        assert phrase not in manual, f"unqualified claim remains: {phrase}"

    assert "does not certify compliance" in manual
    assert "not a production deployment" in manual


def test_plan_records_the_blocked_frozen_spec() -> None:
    plan = PLAN.read_text(encoding="utf-8")
    assert "docs/RUNTIME_GATEWAY.md" in plan
    assert "frozen" in plan.lower()
    assert "not implemented" in plan
