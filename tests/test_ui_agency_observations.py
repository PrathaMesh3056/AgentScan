"""ATK-013 claims stay bounded, private and separate from verified effects."""

from __future__ import annotations

import copy
import json
import re
import shutil
import subprocess
from html import unescape
from pathlib import Path

import pytest

from agentscan.core.models import ScanMode, ScanReport
from agentscan.reporting.html_report import render_html_report

ROOT = Path(__file__).resolve().parents[1]
SCOPE = "agency_proposal_inventory"
PRIVATE = "SYNTHETIC_PRIVATE_RESPONSE_TOOL_ARGUMENTS"

RENDER_SCRIPT = r"""
const fs = require('node:fs');
const payload = JSON.parse(fs.readFileSync(0, 'utf8'));
class Element {
  constructor(tag) { this.tag=tag;this.children=[];this.attrs={};this.style={};this.dataset={};this._text=''; }
  append(...items) { this.children.push(...items); }
  replaceChildren(...items) { this.children=items; }
  setAttribute(k,v) { this.attrs[k]=v; }
  addEventListener() {}
  get textContent() { return this._text+this.children.map(item=>item.textContent).join(''); }
  set textContent(value) { this._text=String(value);this.children=[]; }
  set innerHTML(value) { throw new Error('Unsafe HTML rendering'); }
}
global.document={createElement:tag=>new Element(tag)};
const network=()=>{throw new Error('Unexpected network IO');};
global.fetch=network;global.XMLHttpRequest=network;global.WebSocket=network;
const analytics=require('./agentscan/ui/static/scan-analytics.js');
const before=JSON.stringify(payload), container=new Element('div');
const summary=analytics.render(payload,container);
if (JSON.stringify(payload)!==before) throw new Error('Report mutation');
const elements=[];
function walk(node) {elements.push(node);node.children.forEach(walk);}walk(container);
const panels=elements.filter(node=>Object.hasOwn(node.attrs,'data-agency-observation-panel'));
const rows=elements.filter(node=>Object.hasOwn(node.attrs,'data-agency-observation-row'));
console.log(JSON.stringify({summary,text:panels.map(node=>node.textContent).join(''),
  rows:rows.map(row=>row.children.map(cell=>cell.textContent)),tags:elements.map(node=>node.tag)}));
"""


def observation(**changes):
    return {
        "variant_id": "EXA-001",
        "criterion_version": "atk013-agency-observation-2026-10-18",
        "response_sha256": "a" * 64,
        "response_bytes": 123,
        "reported_proposal_count": 2,
        "malformed_proposal_count": 1,
        "reported_completion_claim_count": 3,
        "reported_approval_pending_count": 4,
        "proposal_scan_truncated": False,
        "proposal_scan_limit": 1000,
        "evidence_source": "target_reported_intent",
        "authorization_verified": False,
        "approval_verified": False,
        "tool_execution_verified": False,
        "downstream_impact": "unassessed",
        **changes,
    }


def report(observations, *, scope=SCOPE):
    return ScanReport(
        target_url="http://owned.invalid/chat",
        scan_mode=ScanMode.SCAN,
        assessment_scope=scope,
        status="INCONCLUSIVE",
        tests_selected=10,
        tests_run=0,
        score=None,
        ssp_class=None,
        module_outcomes=[
            {
                "module_id": "ATK-013",
                "module_name": "Excessive agency",
                "selected_tests": 10,
                "executed_tests": 0,
                "status": "INCONCLUSIVE",
                "assessment_scope": scope,
                "observations": observations,
            }
        ],
    )


def render_dashboard(value):
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is required for actual dashboard rendering contracts")
    completed = subprocess.run(
        [node, "-e", RENDER_SCRIPT],
        input=value.model_dump_json(),
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=20,
    )
    return json.loads(completed.stdout)


def render_html(value):
    before = copy.deepcopy(value.model_dump())
    html = render_html_report(value)
    assert value.model_dump() == before
    match = re.search(r"<section data-agency-observation-panel\b.*?</section>", html, re.S)
    panel = match.group() if match else ""
    rows = [
        [unescape(re.sub(r"<[^>]+>", "", cell)).strip() for cell in cells]
        for row in re.findall(r"<tr data-agency-observation-row>(.*?)</tr>", panel, re.S)
        if (cells := re.findall(r"<t[dh]\b[^>]*>(.*?)</t[dh]>", row, re.S))
    ]
    return panel, rows


def test_agency_claims_are_visible_without_becoming_effects_findings_or_scores():
    value = report([observation(proposal_scan_truncated=True)])
    rendered = render_dashboard(value)
    panel, rows = render_html(value)
    for row in (rendered["rows"][0], rows[0]):
        assert row == ["EXA-001", "2", "1", "3", "4", "Truncated · 1000 entries maximum"]
    for text in (rendered["text"], panel):
        assert "Target-reported intent only" in text
        assert "do not independently verify authorization, approval, tool execution" in text
        assert "A completion claim does not prove an action occurred" in text
        assert "A pending-approval claim does not prove" in text
    assert rendered["summary"]["severity"]["total"] == 0
    assert rendered["summary"]["coverage"]["evaluated"] == 0
    assert rendered["summary"]["coverage"]["remaining"] == 10
    assert not ({"score", "successRate", "resistance"} & rendered["summary"].keys())


def test_private_fields_are_discarded_and_probe_identity_uses_safe_text():
    hostile = "<img src=x onerror=alert(1)>"
    value = report(
        [
            observation(
                variant_id=hostile,
                raw_response=PRIVATE,
                tool_calls=[{"name": PRIVATE, "arguments": PRIVATE}],
                authorization_verified=True,
                approval_verified=True,
                tool_execution_verified=True,
                downstream_impact=PRIVATE,
            )
        ]
    )
    rendered = render_dashboard(value)
    panel, rows = render_html(value)
    assert rendered["rows"][0][0] == rows[0][0] == hostile
    assert "img" not in rendered["tags"]
    assert "&lt;img src=x onerror=alert(1)&gt;" in panel
    assert "<img" not in panel
    assert PRIVATE not in json.dumps(rendered)
    assert PRIVATE not in render_html_report(value)
    assert "do not independently verify" in rendered["text"]


@pytest.mark.parametrize("invalid", [None, "0", True, -1, 1.5, 1001, 2**53])
def test_invalid_metrics_show_unavailable_without_coercion(invalid):
    fields = (
        "reported_proposal_count",
        "malformed_proposal_count",
        "reported_completion_claim_count",
        "reported_approval_pending_count",
    )
    value = report([observation(**dict.fromkeys(fields, invalid))])
    rendered = render_dashboard(value)
    _, rows = render_html(value)
    assert rendered["rows"][0][1:5] == rows[0][1:5] == ["Unavailable"] * 4


def test_zero_is_recorded_and_missing_metrics_remain_unknown():
    row = observation(reported_proposal_count=0)
    del row["reported_completion_claim_count"]
    value = report([row])
    rendered = render_dashboard(value)
    _, rows = render_html(value)
    assert rendered["rows"][0] == rows[0]
    assert rows[0][1] == "0"
    assert rows[0][3] == "Unavailable"


@pytest.mark.parametrize("observations", [None, {}, "not records", []])
def test_missing_or_invalid_observation_collections_do_not_become_clean(observations):
    value = report(observations)
    rendered = render_dashboard(value)
    panel, rows = render_html(value)
    assert rendered["rows"] == rows == []
    assert "Missing records do not establish that the target is safe" in rendered["text"]
    assert "Missing records do not establish that the target is safe" in panel


@pytest.mark.parametrize(
    "row",
    [
        None,
        "not a record",
        observation(criterion_version="future-unrecognized"),
        observation(evidence_source="independently_verified"),
    ],
)
def test_unrecognized_or_malformed_records_cannot_invent_claim_counts(row):
    value = report([row])
    rendered = render_dashboard(value)
    _, rows = render_html(value)
    assert rendered["rows"][0] == rows[0]
    assert rows[0][1:] == ["Unavailable"] * 5


@pytest.mark.parametrize(
    "change",
    [{"proposal_scan_truncated": "false"}, {"proposal_scan_limit": "1000"}],
)
def test_missing_or_invalid_scan_bounds_are_unavailable(change):
    value = report([observation(**change)])
    rendered = render_dashboard(value)
    _, rows = render_html(value)
    assert rendered["rows"][0][-1] == rows[0][-1] == "Unavailable"


def test_observation_table_has_ten_rows_total_and_explicit_truncation_notice():
    value = report([observation(variant_id=f"EXA-{index:03}") for index in range(15)])
    value.module_outcomes.append(copy.deepcopy(value.module_outcomes[0]))
    rendered = render_dashboard(value)
    panel, rows = render_html(value)
    assert len(rendered["rows"]) == len(rows) == 10
    assert "EXA-010" not in rendered["text"]
    assert "EXA-010" not in panel
    assert "Only the first 10 observation records are shown" in rendered["text"]
    assert "Only the first 10 observation records are shown" in panel


def test_other_scopes_do_not_present_unrelated_observations_as_agency_claims():
    value = report([observation()], scope="mcp_tool_proposal_inventory")
    rendered = render_dashboard(value)
    panel, rows = render_html(value)
    assert rendered["text"] == panel == ""
    assert rendered["rows"] == rows == []
