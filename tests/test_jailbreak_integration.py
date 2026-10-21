"""ATK-002 reference evidence remains distinct from unverified action claims."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock

import pytest
import respx
import yaml
from click import unstyle
from typer.testing import CliRunner

from agentscan.attacks.base import AttackModule
from agentscan.attacks.registry import AttackRegistry
from agentscan.attacks.scan.jailbreak import JailbreakModule
from agentscan.cli import app
from agentscan.core import runner
from agentscan.core.models import Target
from agentscan.reporting.html_report import render_html_report

PRIVATE = "SYNTHETIC_ATK002_BOUNDARY_7Q82"
URL = "http://persona.test/chat"


@pytest.fixture
def selected(monkeypatch):
    registry = AttackRegistry()
    registry.register(JailbreakModule())
    registry._loaded = True
    monkeypatch.setattr(runner, "registry", registry)
    return registry


@pytest.mark.asyncio
@pytest.mark.parametrize("mixed", [False, True])
async def test_report_does_not_promote_reported_tools_into_actions(selected, mixed):
    if mixed:

        class OtherCheck(AttackModule):
            attack_id = "ATK-TEST-OTHER"
            attack_name = "Other bounded check"
            owasp_id = "LLM01"

            async def run(self, target):
                return []

        selected.register(OtherCheck())
    with respx.mock() as mock:
        route = mock.post(URL).respond(
            200,
            json={"response": PRIVATE, "tool_calls": [{"name": "shell", "arguments": "claimed"}]},
        )
        report = await runner.run_scan(Target(url=URL, canary_token=PRIVATE))
    assert route.call_count == 18
    assert len(report.findings) == 18
    assert all(f.metadata["tool_execution_verified"] is False for f in report.findings)
    assert report.ssp_class is None
    assert PRIVATE not in report.model_dump_json()
    html = render_html_report(report)
    assert "ATK-002 scope: complete known-reference disclosure" in html
    assert "tool execution are unassessed" in html
    assert PRIVATE not in html


def test_cli_retains_scope_and_private_config_without_provider_calls(tmp_path, monkeypatch):
    from agentscan import cli
    from agentscan.core.models import ScanMode, ScanReport

    report = ScanReport(target_url=URL, scan_mode=ScanMode.SCAN)
    report.tests_selected = 18
    report.module_outcomes = [
        {
            "module_id": "ATK-002",
            "module_name": "Jailbreak and Persona Adoption",
            "assessment_scope": "persona_complete_known_reference",
            "status": "INCONCLUSIVE",
            "selected_tests": 18,
            "executed_tests": 0,
            "reason": "A configured reference was not available in this synthetic result.",
        }
    ]
    report.complete(None, status="INCONCLUSIVE")
    execute = AsyncMock(return_value=report)
    monkeypatch.setattr(cli, "run_scan_multi", execute)
    profile = tmp_path / "target.yaml"
    profile.write_text(yaml.safe_dump({"url": URL, "canary_token": PRIVATE}), encoding="utf-8")
    output = tmp_path / "report.json"
    result = CliRunner().invoke(app, ["scan", "--config", str(profile), "--output", str(output)])
    assert result.exit_code == 3, result.output
    assert execute.await_args.args[0].canary_token == PRIVATE
    text = " ".join(unstyle(result.output).replace("│", " ").split())
    assert "ATK-002 scope: complete known-reference disclosure" in text
    assert "tool execution are unassessed" in text
    assert PRIVATE not in text
    saved = json.loads(output.read_text(encoding="utf-8"))
    assert saved["score"] is None and saved["status"] == "INCONCLUSIVE"
    assert PRIVATE not in json.dumps(saved)
