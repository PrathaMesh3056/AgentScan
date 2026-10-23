"""Production runner and CLI expose bounded multilingual evidence honestly."""

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
from agentscan.attacks.scan.multilingual import MultilingualModule
from agentscan.cli import app
from agentscan.core import runner
from agentscan.core.language_coverage import language_coverage
from agentscan.core.models import ScanMode, ScanReport, Target
from agentscan.reporting.html_report import render_html_report

PRIVATE = "SYNTHETIC_ATK011_PRIVATE_7Q82"
URL = "http://multilingual.test/chat"


@pytest.fixture
def selected(monkeypatch):
    registry = AttackRegistry()
    registry.register(MultilingualModule())
    registry._loaded = True
    monkeypatch.setattr(runner, "registry", registry)
    return registry


@pytest.mark.asyncio
@pytest.mark.parametrize("mixed", [False, True])
async def test_disclosure_preserves_language_coverage_without_promoting_tool_claims(
    selected, mixed
):
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
        value = await runner.run_scan(Target(url=URL, canary_token=PRIVATE))
    assert route.call_count == 18
    assert len(value.findings) == 18
    assert value.ssp_class is None
    assert all(f.metadata["tool_execution_verified"] is False for f in value.findings)
    record = next(row for row in value.module_outcomes if row["module_id"] == "ATK-011")
    rows = language_coverage(record)
    assert rows is not None
    assert sum(row["findings"] for row in rows) == 18
    assert sum(row["evaluated_tests"] for row in rows) == 18
    assert PRIVATE not in value.model_dump_json()
    html = render_html_report(value)
    assert "ATK-011 scope: complete known-reference disclosure" in html
    assert "no language safety ranking" in html
    assert PRIVATE not in html


@pytest.mark.asyncio
@pytest.mark.parametrize("mutate", [False, True])
async def test_missing_reference_leaves_language_probes_unrun(selected, mutate):
    with respx.mock(assert_all_called=False) as mock:
        route = mock.post(URL).respond(200, json={"response": "public marker"})
        value = await runner.run_scan(Target(url=URL, mutate=mutate, mutation_budget=2))
    assert route.call_count == 0
    assert value.status == "INCONCLUSIVE" and value.score is None and value.tests_run == 0
    rows = language_coverage(value.module_outcomes[0])
    assert rows is not None
    assert sum(row["not_run_tests"] for row in rows) == (54 if mutate else 18)
    assert sum(row["evaluated_tests"] for row in rows) == 0


def test_cli_private_configuration_scope_and_language_coverage(tmp_path, monkeypatch):
    from agentscan import cli

    value = ScanReport(target_url=URL, scan_mode=ScanMode.SCAN)
    value.tests_selected = 1
    value.module_outcomes = [
        {
            "module_id": "ATK-011",
            "module_name": "Multilingual reference checks",
            "assessment_scope": "multilingual_complete_known_reference",
            "status": "INCONCLUSIVE",
            "selected_tests": 1,
            "executed_tests": 0,
            "language_outcomes": [
                {
                    "language": "es",
                    "script": "Latn",
                    "selected_tests": 1,
                    "evaluated_tests": 0,
                    "findings": 0,
                    "inconclusive_tests": 0,
                    "error_tests": 0,
                    "not_run_tests": 1,
                }
            ],
        }
    ]
    value.complete(None, status="INCONCLUSIVE")
    execute = AsyncMock(return_value=value)
    monkeypatch.setattr(cli, "run_scan_multi", execute)
    profile = tmp_path / "target.yaml"
    profile.write_text(yaml.safe_dump({"url": URL, "canary_token": PRIVATE}), encoding="utf-8")
    output = tmp_path / "report.json"
    result = CliRunner().invoke(app, ["scan", "--config", str(profile), "--output", str(output)])
    assert result.exit_code == 3, result.output
    assert execute.await_args.args[0].canary_token == PRIVATE
    text = " ".join(unstyle(result.output).replace("│", " ").split())
    assert "ATK-011 scope: complete known-reference disclosure" in text
    assert "no language safety ranking" in text
    assert "es/Latn" in text
    assert PRIVATE not in text
    saved = json.loads(output.read_text(encoding="utf-8"))
    assert saved["status"] == "INCONCLUSIVE" and saved["score"] is None
    assert PRIVATE not in json.dumps(saved)
