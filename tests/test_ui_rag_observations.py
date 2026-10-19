"""ATK-008 remote observations and owned RAG effects stay scoped and redacted."""

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
SCOPE = "rag_document_observation"
PRIVATE = "SYNTHETIC_PRIVATE_DOCUMENT_RECEIPT_RESPONSE"

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
const panels=elements.filter(node=>Object.hasOwn(node.attrs,'data-rag-observation-panel'));
const rows=elements.filter(node=>Object.hasOwn(node.attrs,'data-rag-observation-row'));
const ownedPanels=elements.filter(node=>Object.hasOwn(node.attrs,'data-owned-rag-panel'));
const ownedRows=elements.filter(node=>Object.hasOwn(node.attrs,'data-owned-rag-row'));
console.log(JSON.stringify({summary,text:panels.map(node=>node.textContent).join(''),
  rows:rows.map(row=>row.children.map(cell=>cell.textContent)),tags:elements.map(node=>node.tag),
  ownedText:ownedPanels.map(node=>node.textContent).join(''),
  ownedRows:ownedRows.map(row=>row.children.map(cell=>cell.textContent)),
  agencyPanelCount:elements.filter(node=>Object.hasOwn(node.attrs,'data-agency-observation-panel')).length}));
"""


def observation(**changes):
    return {
        "variant_id": "RAG-001",
        "criterion_version": "atk008-document-observation-2026-10-18",
        "evidence_source": "target_reported_document_response",
        "receipt_status": "correlated",
        "response_text_available": True,
        "seed_indicator_present": True,
        "source_sha256": "a" * 64,
        "response_sha256": "b" * 64,
        "response_bytes": 123,
        "corpus_poisoning_verified": False,
        "causal_attribution_verified": False,
        "retrieval_ranking_verified": False,
        "source_authenticity_verified": False,
        "downstream_impact": "unassessed",
        **changes,
    }


def report(observations, *, scope=SCOPE):
    return ScanReport(
        target_url="http://owned.invalid/chat",
        scan_mode=ScanMode.SCAN,
        assessment_scope=scope,
        status="INCONCLUSIVE",
        tests_selected=8,
        tests_run=0,
        score=None,
        ssp_class=None,
        module_outcomes=[
            {
                "module_id": "ATK-008",
                "module_name": "RAG document observations",
                "selected_tests": 8,
                "executed_tests": 0,
                "status": "INCONCLUSIVE",
                "assessment_scope": scope,
                "observations": observations,
            }
        ],
    )


def owned_observation(**changes):
    value = observation(
        assessment_scope="owned_rag_lab",
        local_profile="atk008-fts-v1",
        witness_disposition="forbidden_effect",
        local_effect="answer_integrity_violation",
        independent_evidence_sha256="c" * 64,
    )
    value.update(changes)
    return value


def owned_report(observations, *, finding_count=1):
    value = report(observations, scope="owned_rag_lab")
    value.module_outcomes[0]["rag_finding_count"] = finding_count
    value.module_outcomes[0]["rag_findings"] = (
        [
            {"module_id": "ATK-008", "description": "Owned fixture effect", "severity": "HIGH"}
            for _ in range(finding_count)
        ]
        if isinstance(finding_count, int)
        else []
    )
    return value


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
    match = re.search(r"<section data-rag-observation-panel\b.*?</section>", html, re.S)
    panel = match.group() if match else ""
    rows = [
        [unescape(re.sub(r"<[^>]+>", "", cell)).strip() for cell in cells]
        for row in re.findall(r"<tr data-rag-observation-row>(.*?)</tr>", panel, re.S)
        if (cells := re.findall(r"<t[dh]\b[^>]*>(.*?)</t[dh]>", row, re.S))
    ]
    return panel, rows


def render_owned_html(value):
    before = copy.deepcopy(value.model_dump())
    html = render_html_report(value)
    assert value.model_dump() == before
    match = re.search(r"<section data-owned-rag-panel\b.*?</section>", html, re.S)
    panel = match.group() if match else ""
    rows = [
        [unescape(re.sub(r"<[^>]+>", "", cell)).strip() for cell in cells]
        for row in re.findall(r"<tr data-owned-rag-row>(.*?)</tr>", panel, re.S)
        if (cells := re.findall(r"<t[dh]\b[^>]*>(.*?)</t[dh]>", row, re.S))
    ]
    return panel, rows


@pytest.mark.parametrize("receipt", ["correlated", "missing", "invalid", "mismatched"])
def test_receipts_are_visible_as_correlation_only_without_scoring(receipt):
    value = report([observation(receipt_status=receipt)])
    rendered = render_dashboard(value)
    panel, rows = render_html(value)
    assert rendered["rows"] == rows == [["RAG-001", receipt, "Yes", "Yes"]]
    for text in (rendered["text"], panel):
        assert "A receipt is target-reported correlation only" in text
        assert "cannot prove corpus insertion, retrieval ranking, source authenticity" in text
        assert "false-fact endorsement" in text
        assert "causal attribution and downstream impact remain unassessed" in text
        assert "does not prove the target accepted a false fact" in text
    assert rendered["summary"]["severity"]["total"] == 0
    assert rendered["summary"]["coverage"]["evaluated"] == 0
    assert rendered["summary"]["coverage"]["remaining"] == 8
    assert not ({"score", "successRate", "resistance"} & rendered["summary"].keys())


def test_private_fields_are_discarded_and_probe_identity_is_safe_text():
    hostile = "<img src=x onerror=alert(1)>"
    value = report(
        [
            observation(
                variant_id=hostile,
                raw_response=PRIVATE,
                raw_source=PRIVATE,
                receipt={"nonce": PRIVATE},
                tool_calls=[{"name": PRIVATE, "arguments": PRIVATE}],
                source_sha256=PRIVATE,
                corpus_poisoning_verified=True,
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


@pytest.mark.parametrize("readable", [None, "true", 0, 1, {}, []])
def test_invalid_readability_cannot_imply_marker_absence(readable):
    value = report([observation(response_text_available=readable, seed_indicator_present=False)])
    rendered = render_dashboard(value)
    _, rows = render_html(value)
    assert rendered["rows"] == rows == [["RAG-001", "correlated", "Unavailable", "Unavailable"]]


@pytest.mark.parametrize("marker", [None, "false", 0, 1, {}, []])
def test_invalid_marker_is_unavailable_without_coercion(marker):
    value = report([observation(seed_indicator_present=marker)])
    rendered = render_dashboard(value)
    _, rows = render_html(value)
    assert rendered["rows"] == rows == [["RAG-001", "correlated", "Unavailable", "Yes"]]


def test_unreadable_response_cannot_assert_marker_presence_or_absence():
    value = report([observation(response_text_available=False, seed_indicator_present=False)])
    rendered = render_dashboard(value)
    _, rows = render_html(value)
    assert rendered["rows"] == rows == [["RAG-001", "correlated", "Unavailable", "No"]]


def test_readable_marker_absence_is_distinct_from_unavailable():
    value = report([observation(seed_indicator_present=False)])
    rendered = render_dashboard(value)
    _, rows = render_html(value)
    assert rendered["rows"] == rows == [["RAG-001", "correlated", "No", "Yes"]]


@pytest.mark.parametrize("receipt", [None, "verified", 1, True, {}, []])
def test_missing_or_invalid_receipt_status_does_not_become_correlated(receipt):
    value = report([observation(receipt_status=receipt)])
    rendered = render_dashboard(value)
    _, rows = render_html(value)
    assert rendered["rows"] == rows == [["RAG-001", "Unavailable", "Yes", "Yes"]]


@pytest.mark.parametrize("observations", [None, {}, "not records", []])
def test_missing_or_invalid_collections_cannot_become_clean(observations):
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
def test_unrecognized_or_malformed_records_cannot_invent_observation_metrics(row):
    value = report([row])
    rendered = render_dashboard(value)
    _, rows = render_html(value)
    assert rendered["rows"][0] == rows[0]
    assert rows[0][1:] == ["Unavailable"] * 3


def test_missing_fields_are_unavailable_and_probe_identity_is_bounded():
    value = report([{"variant_id": "  " + "X" * 83 + "  "}])
    rendered = render_dashboard(value)
    _, rows = render_html(value)
    assert rendered["rows"] == rows == [["X" * 80] + ["Unavailable"] * 3]


def test_eight_rows_total_with_explicit_truncation_notice():
    value = report([observation(variant_id=f"RAG-{index:03}") for index in range(12)])
    value.module_outcomes.append(copy.deepcopy(value.module_outcomes[0]))
    rendered = render_dashboard(value)
    panel, rows = render_html(value)
    assert len(rendered["rows"]) == len(rows) == 8
    assert "RAG-008" not in rendered["text"]
    assert "RAG-008" not in panel
    assert "Only the first 8 observation records are shown" in rendered["text"]
    assert "Only the first 8 observation records are shown" in panel


def test_other_scopes_do_not_present_unrelated_observations_as_document_evidence():
    value = report([observation()], scope="agency_proposal_inventory")
    rendered = render_dashboard(value)
    panel, rows = render_html(value)
    assert rendered["text"] == panel == ""
    assert rendered["rows"] == rows == []
    assert rendered["agencyPanelCount"] == 1


@pytest.mark.parametrize(
    ("disposition", "effect", "label"),
    [
        ("forbidden_effect", "answer_integrity_violation", "Answer integrity violation"),
        ("forbidden_effect", "citation_policy_violation", "Citation policy violation"),
        ("assessed_no_effect", None, "No forbidden effect recorded"),
        ("policy_rejected", None, "No forbidden effect recorded"),
    ],
)
def test_independently_witnessed_owned_effects_are_separate_from_customer_findings(
    disposition, effect, label
):
    value = owned_report(
        [
            owned_observation(
                receipt_status="missing", witness_disposition=disposition, local_effect=effect
            )
        ],
        finding_count=int(effect is not None),
    )
    rendered = render_dashboard(value)
    panel, rows = render_owned_html(value)
    assert rendered["rows"] == []
    assert (
        rendered["ownedRows"]
        == rows
        == [
            [
                "RAG-001",
                "atk008-fts-v1",
                {
                    "forbidden_effect": "Forbidden effect recorded",
                    "assessed_no_effect": "No forbidden effect observed",
                    "policy_rejected": "Rejected by fixture policy",
                }[disposition],
                label,
                "c" * 12,
            ]
        ]
    )
    for text in (rendered["ownedText"], panel):
        assert "excluded from customer findings and the customer security score" in text
        assert "Missing remote receipts do not invalidate a valid local witness" in text
        assert "customer-agent efficacy remains unassessed" in text
    assert rendered["summary"]["severity"]["total"] == 0
    assert rendered["summary"]["coverage"]["evaluated"] == 0


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("assessment_scope", "target"),
        ("criterion_version", "unrecognized"),
        ("evidence_source", "remote_attestation"),
        ("local_profile", "<script>private</script>"),
        ("local_profile", ""),
        ("source_sha256", "SECRET"),
        ("response_sha256", "B" * 64),
        ("independent_evidence_sha256", "C" * 64),
        ("witness_disposition", "unknown"),
        ("local_effect", "arbitrary_claim"),
        ("local_effect", None),
    ],
)
def test_invalid_owned_witness_fields_cannot_be_displayed_as_verified(field, invalid):
    value = owned_report([owned_observation(**{field: invalid})])
    rendered = render_dashboard(value)
    panel, rows = render_owned_html(value)
    assert rendered["ownedRows"] == rows == [["RAG-001"] + ["Unavailable"] * 4]
    assert "<script" not in panel


@pytest.mark.parametrize(
    ("disposition", "effect"),
    [
        ("assessed_no_effect", "answer_integrity_violation"),
        ("policy_rejected", "citation_policy_violation"),
    ],
)
def test_inconsistent_owned_effect_and_disposition_is_unavailable(disposition, effect):
    value = owned_report([owned_observation(witness_disposition=disposition, local_effect=effect)])
    rendered = render_dashboard(value)
    _, rows = render_owned_html(value)
    assert rendered["ownedRows"] == rows == [["RAG-001"] + ["Unavailable"] * 4]


def test_owned_panel_drops_private_fields_and_escapes_case_identifier():
    hostile = "<img src=x onerror=alert(1)>"
    value = owned_report(
        [
            owned_observation(
                variant_id=hostile,
                raw_response=PRIVATE,
                raw_document=PRIVATE,
                raw_journal=PRIVATE,
            )
        ]
    )
    rendered = render_dashboard(value)
    panel, rows = render_owned_html(value)
    assert rendered["ownedRows"][0][0] == rows[0][0] == hostile
    assert "img" not in rendered["tags"]
    assert "&lt;img src=x onerror=alert(1)&gt;" in panel
    assert "<img" not in panel
    assert PRIVATE not in json.dumps(rendered)
    assert PRIVATE not in render_html_report(value)


def test_owned_and_remote_panels_have_independent_caps_and_scope():
    value = owned_report(
        [owned_observation(variant_id=f"OWN-{index:03}") for index in range(70)],
        finding_count=2,
    )
    value.assessment_scope = "mixed"
    remote = report([observation(variant_id=f"REMOTE-{index:03}") for index in range(10)])
    value.module_outcomes.extend(remote.module_outcomes)
    rendered = render_dashboard(value)
    remote_panel, remote_rows = render_html(value)
    owned_panel, owned_rows = render_owned_html(value)
    assert len(rendered["ownedRows"]) == len(owned_rows) == 64
    assert len(rendered["rows"]) == len(remote_rows) == 8
    assert "OWN-064" not in rendered["ownedText"]
    assert "REMOTE-008" not in rendered["text"]
    assert "Only the first 64 owned fixture records are shown" in owned_panel
    assert "Only the first 8 observation records are shown" in remote_panel


@pytest.mark.parametrize("records", [None, {}, "not records", []])
def test_missing_owned_records_remain_unavailable(records):
    value = owned_report(records, finding_count="invalid")
    rendered = render_dashboard(value)
    panel, rows = render_owned_html(value)
    assert rendered["ownedRows"] == rows == []
    assert "No owned fixture evidence records are available" in rendered["ownedText"]
    assert "No owned fixture evidence records are available" in panel
    assert "Unavailable owned fixture effect finding(s)" in rendered["ownedText"]
    assert "Unavailable owned fixture effect finding(s)" in panel


def test_owned_only_unavailable_score_has_neutral_report_styling():
    html = render_html_report(owned_report([owned_observation()]))
    assert "border-left: 5px solid #64748b;" in html
    assert "margin: 10px 0; color: #475569;" in html
    assert re.search(
        r'<span class="badge badge-neutral" style="font-size: 8\.5pt; padding: 4px 12px;">\s+INCONCLUSIVE',
        html,
    )
