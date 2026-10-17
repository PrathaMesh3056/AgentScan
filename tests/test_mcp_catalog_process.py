"""Actual subprocess discovery with an approval artifact fixed before contact."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from urllib.parse import urlencode

import pytest

from agentscan.core.mcp_inventory import fingerprint_mcp_tool
from agentscan.core.models import Target
from agentscan.core.runner import run_scan

# Independently declared approved artifact: never import or fetch the server's
# advertised definition to enroll it. The fixture only receives its mode/path.
APPROVED_TOOL = {
    "name": "approved_echo",
    "description": "Echo one explicitly supplied synthetic message.",
    "inputSchema": {
        "type": "object",
        "properties": {"message": {"type": "string"}},
        "required": ["message"],
        "additionalProperties": False,
    },
    "annotations": {"readOnlyHint": True},
}
APPROVED_DIGEST = fingerprint_mcp_tool(APPROVED_TOOL)
SERVER = Path(__file__).parent / "fixtures" / "mcp_catalog_server.py"


@pytest.mark.parametrize(
    ("mode", "status", "evaluated", "findings"),
    [
        ("match", "COMPLETE", 1, 0),
        ("changed", "COMPLETE", 1, 1),
        ("malformed", "INCONCLUSIVE", 0, 0),
    ],
)
async def test_real_stdio_catalog_round_trip_never_calls_a_tool(
    tmp_path: Path, mode: str, status: str, evaluated: int, findings: int
) -> None:
    journal_path = tmp_path / "methods.jsonl"
    endpoint = "mcp+stdio://stdio?" + urlencode(
        {
            "command": sys.executable,
            "arg": [
                "-u",
                "-B",
                str(SERVER.resolve()),
                "--journal",
                str(journal_path),
                "--catalog-mode",
                mode,
            ],
        },
        doseq=True,
    )
    # Enrollment is complete before opening the child process. Changed and
    # malformed modes receive the same approved definition, never an auto-pin.
    target = Target(
        url=endpoint,
        timeout=10,
        request_budget=8,
        mcp_inventory_baseline={
            "algorithm": "mcp-tool-json-sha256-v1",
            "endpoint": endpoint,
            "tools": {"approved_echo": APPROVED_DIGEST},
        },
    )

    report = await run_scan(target)

    journal = [json.loads(line) for line in journal_path.read_text(encoding="utf-8").splitlines()]
    assert [entry["method"] for entry in journal] == [
        "initialize",
        "notifications/initialized",
        "tools/list",
    ]
    assert len({entry["pid"] for entry in journal}) == 1
    assert journal[0]["pid"] != os.getpid()
    assert report.assessment_scope == "mcp_catalog_policy"
    assert report.status == status
    assert report.tests_selected == 1 and report.tests_run == evaluated
    assert report.score is None and report.findings == []
    assert report.ssp_class is None
    assert len(report.module_outcomes) == 1
    outcome = report.module_outcomes[0]
    assert outcome["module_id"] == "ATK-006"
    assert outcome["assessment_scope"] == "mcp_catalog_policy"
    assert outcome["selected_tests"] == 1 and outcome["executed_tests"] == evaluated
    assert outcome["status"] == status
    assert outcome["catalog_finding_count"] == findings
    assert len(outcome["catalog_findings"]) == findings
    if mode == "changed":
        finding = outcome["catalog_findings"][0]
        assert finding["severity"] == "MEDIUM"
        assert finding["metadata"]["tool_execution_verified"] is False
        assert finding["metadata"]["deviation_counts"]["metadata_changed"] == 1
        assert finding["metadata"]["deviations"] == [
            {
                "kind": "metadata_changed",
                "name": "approved_echo",
                "expected_sha256": APPROVED_DIGEST,
                "observed_sha256": fingerprint_mcp_tool(
                    {
                        **APPROVED_TOOL,
                        "description": "Description revised after operator review.",
                    }
                ),
            }
        ]
