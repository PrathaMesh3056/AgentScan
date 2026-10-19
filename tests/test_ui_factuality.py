"""Approved-answer inputs and ATK-009 displays keep policy evidence scoped."""

from __future__ import annotations

import copy
import json
import re
import shutil
import subprocess
import threading
from html import unescape
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

from agentscan.core.models import ScanMode, ScanReport
from agentscan.reporting.html_report import render_html_report
from agentscan.ui.app import create_app
from agentscan.ui.state import state

ROOT = Path(__file__).resolve().parents[1]
ENDPOINT = "http://owned.invalid/chat"
PRIVATE = "SYNTHETIC_PRIVATE_APPROVED_FACT"


def approved_baseline():
    return {
        "schema_version": "agentscan.factuality.v1",
        "target_url": ENDPOINT,
        "cases": [
            {
                "id": "SYNTH-01",
                "question": f"What is the {PRIVATE} project code?",
                "expected_answer": "ALPHA",
                "false_answer": "BETA",
            }
        ],
    }


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.delenv("AGENTSCAN_UI_TOKEN", raising=False)
    for name, value in (
        ("active_scan", None),
        ("sentinel_task", None),
        ("scan_status", {"status": "idle"}),
        ("report", None),
    ):
        monkeypatch.setattr(state, name, value)
    with TestClient(
        create_app(project_root=tmp_path), base_url="http://127.0.0.1:8765"
    ) as instance:
        assert instance.get("/").status_code == 200
        yield instance


INVALID_BASELINES = [
    "",
    "{}",
    [],
    True,
    1,
    {},
    {**approved_baseline(), "schema_version": "future"},
    {key: value for key, value in approved_baseline().items() if key != "schema_version"},
    {**approved_baseline(), PRIVATE: True},
    {**approved_baseline(), "cases": None},
    {**approved_baseline(), "cases": {}},
    {**approved_baseline(), "cases": []},
    {**approved_baseline(), "cases": [True]},
    {**approved_baseline(), "cases": approved_baseline()["cases"] * 2},
    {
        **approved_baseline(),
        "cases": [{**approved_baseline()["cases"][0], "id": str(n)} for n in range(17)],
    },
]
for field, values in {
    "id": ["", "x" * 65, "non ASCII é", "bad\n", True],
    "question": ["", "   ", "x" * 2049, None, True],
    "expected_answer": ["", "\t", "x" * 513, [], True],
    "false_answer": ["", "\n", "x" * 513, {}, True, "ALPHA"],
}.items():
    INVALID_BASELINES.extend(
        {**approved_baseline(), "cases": [{**approved_baseline()["cases"][0], field: value}]}
        for value in values
    )
INVALID_BASELINES.extend(
    [
        {**approved_baseline(), "cases": [{"id": "MISSING"}]},
        {
            **approved_baseline(),
            "cases": [{**approved_baseline()["cases"][0], PRIVATE: True}],
        },
    ]
)


@pytest.mark.parametrize("baseline", INVALID_BASELINES)
def test_invalid_approved_answers_do_not_start_or_echo_input(client, monkeypatch, baseline):
    run = AsyncMock()
    monkeypatch.setattr("agentscan.core.runner.run_scan_multi", run)
    response = client.post(
        "/api/scan", json={"target_url": ENDPOINT, "factuality_baseline": baseline}
    )
    assert response.status_code == 400
    assert "factuality_baseline" in response.json()["field_errors"]
    assert PRIVATE not in response.text
    run.assert_not_called()
    assert state.active_scan is None


@pytest.mark.parametrize(
    "overrides",
    [
        {"target_url": "http://other.invalid/chat"},
        {"target_url": "ws://owned.invalid/chat"},
        {"mode": "ACTIVE"},
        {"mode": "DEEP"},
        {"exploit": True},
        {"deep": True},
        {"mutate": True},
        {"indirect_adapter": "document_v1"},
        {"analysis_mode": "local", "local_model": "ollama/example"},
        {"attacker_model": "ollama/example"},
        {"attacker_goal": PRIVATE},
        {"judge_model": "ollama/example"},
        {"attacker_turns": 2},
        {"browser": {}},
        {"request_template": {}},
        {"retry_state_changing_requests": True},
        {"mcp_inventory_baseline": {"endpoint": "mcp+sses://owned.invalid/mcp", "tools": {}}},
    ],
)
def test_approved_answer_workflow_conflicts_are_field_specific(client, monkeypatch, overrides):
    run = AsyncMock()
    monkeypatch.setattr("agentscan.core.runner.run_scan_multi", run)
    response = client.post(
        "/api/scan",
        json={"target_url": ENDPOINT, "factuality_baseline": approved_baseline(), **overrides},
    )
    assert response.status_code == 400
    assert "factuality_baseline" in response.json()["field_errors"]
    assert PRIVATE not in response.text
    run.assert_not_called()


@pytest.mark.parametrize("nested", [False, True])
def test_duplicate_json_keys_are_rejected_before_typed_baseline(client, monkeypatch, nested):
    run = AsyncMock()
    monkeypatch.setattr("agentscan.core.runner.run_scan_multi", run)
    body = json.dumps({"target_url": ENDPOINT, "factuality_baseline": approved_baseline()})
    if nested:
        body = body.replace('"id": "SYNTH-01"', '"id": "SYNTH-01", "\\u0069d": "OTHER"')
    else:
        body = body.replace(
            '"schema_version":', '"schema_version":"agentscan.factuality.v1", "schema_version":'
        )
    response = client.post("/api/scan", content=body, headers={"Content-Type": "application/json"})
    assert response.status_code == 400
    assert "factuality_baseline" in response.json()["field_errors"]
    assert PRIVATE not in response.text
    run.assert_not_called()


@pytest.mark.parametrize("baseline", [approved_baseline(), None, "omitted"])
def test_optional_baseline_reaches_typed_scan_without_retention(client, monkeypatch, baseline):
    called = threading.Event()

    async def complete(target, modes):
        assert modes == [ScanMode.SCAN]
        if isinstance(baseline, dict):
            assert target.factuality_baseline.model_dump() == baseline
        else:
            assert target.factuality_baseline is None
        called.set()
        return ScanReport(
            target_url=ENDPOINT,
            scan_mode=ScanMode.SCAN,
            score=None,
            assessment_scope="factuality_policy" if isinstance(baseline, dict) else "target",
        )

    monkeypatch.setattr("agentscan.core.runner.run_scan_multi", AsyncMock(side_effect=complete))
    payload = {"target_url": ENDPOINT}
    if baseline != "omitted":
        payload["factuality_baseline"] = baseline
    response = client.post("/api/scan", json=payload)
    assert response.status_code == 200
    assert called.wait(5)
    status = client.get("/api/scan/status")
    assert PRIVATE not in response.text + status.text
    assert "factuality_baseline" not in status.json()


def node_run(script, data=None):
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is required for dashboard JavaScript contracts")
    return subprocess.run(
        [node, "-e", script],
        cwd=ROOT,
        input=json.dumps(data) if data is not None else None,
        text=True,
        capture_output=True,
        check=True,
        timeout=20,
    ).stdout


def test_frontend_factuality_schema_conflicts_and_nested_errors():
    node_run(r"""
const assert=require('node:assert/strict'), elements={};
const element=id=>({id,value:'',checked:false,options:[],attrs:{},dataset:{},
parentElement:{append(node){elements[node.id]=node;}},setAttribute(k,v){this.attrs[k]=v;},
getAttribute(k){return this.attrs[k]||null;},removeAttribute(k){delete this.attrs[k];},focus(){}});
global.document={getElementById:id=>elements[id]||null,createElement:()=>element('')};
const forms=require('./agentscan/ui/static/form-validation.js');
for(const spec of forms.inventory().filter(item=>item.workflow==='scan')){
 const field=elements[spec.id]=element(spec.id);field.value=spec.type==='choice'?spec.choices[0]:spec.type==='integer'?'4':'';
}
const endpoint='http://owned.invalid/chat';elements['scan-target-url'].value=endpoint;
const spec=forms.inventory().find(item=>item.field==='factuality_baseline'),field=elements[spec.id];
const value={schema_version:'agentscan.factuality.v1',target_url:endpoint,cases:[{id:'SYNTH-01',question:'Question?',expected_answer:'ALPHA',false_answer:'BETA'}]};
assert.deepEqual(forms.checkField(spec,JSON.stringify(value)).value,value);
assert.equal(forms.checkField(spec,'').value,null);
const invalid=['null','true','[]','{}','{',JSON.stringify({...value,schema_version:'future'}),
JSON.stringify({...value,secret:'do-not-echo'}),JSON.stringify({...value,cases:[]}),JSON.stringify({...value,cases:[true]}),
JSON.stringify({...value,cases:[...value.cases,...value.cases]}),JSON.stringify({...value,cases:Array.from({length:17},(_,i)=>({...value.cases[0],id:'C'+i}))}),
' '.repeat(262145)+'{}',JSON.stringify(value).replace('"id":"SYNTH-01"','"id":"SYNTH-01","\\u0069d":"OTHER"')];
for(const [key,values] of Object.entries({id:['','x'.repeat(65),'non ASCII é',true],question:['',' ',true,'x'.repeat(2049),'\uD800'],expected_answer:['',' ',[],true,'x'.repeat(513)],false_answer:['','ALPHA',false,'x'.repeat(513)]}))
for(const entry of values)invalid.push(JSON.stringify({...value,cases:[{...value.cases[0],[key]:entry}]}));
for(const item of invalid){const result=forms.checkField(spec,item);assert.ok(result.error,item);assert.ok(!result.error.includes('do-not-echo'));}
const multiline={...value,cases:[{...value.cases[0],question:'Two\nlines?',expected_answer:'😀'}]};
assert.deepEqual(forms.checkField(spec,JSON.stringify(multiline)).value,multiline);
field.value=JSON.stringify(value);assert.equal(forms.validate('scan',{render:false}).valid,true);
for(const [id,entry] of [['scan-mode','ACTIVE'],['scan-analysis-mode','local'],['scan-indirect-adapter','document_v1'],['scan-target-url','http://other.invalid/chat'],['scan-mcp-inventory-baseline',JSON.stringify({endpoint:'mcp+sses://owned.invalid/mcp',tools:{}})]]){
 const prior=elements[id].value;elements[id].value=entry;assert.ok(forms.validate('scan',{render:false}).errors.factuality_baseline);elements[id].value=prior;
}
forms.applyServer('scan',{field_errors:{'factuality_baseline.cases.0.expected_answer':'Use an approved answer.'}});
assert.equal(field.attrs['aria-invalid'],'true');assert.ok(elements[field.id+'-error'].textContent.includes('approved answer'));
""")


def policy_observation(**changes):
    return {
        "case_id": "SYNTH-01",
        "arm": "neutral",
        "criterion_version": "atk009-factuality-exact-v1",
        "assessment_scope": "factuality_policy",
        "evidence_source": "operator_approved_exact_answer_comparison",
        "baseline_sha256": "a" * 64,
        "question_sha256": "b" * 64,
        "request_sha256": "c" * 64,
        "response_sha256": "d" * 64,
        "response_bytes": 123,
        "outcome": "answer_mismatch",
        "security_impact": "unassessed",
        "causal_attribution_verified": False,
        **changes,
    }


def inventory_observation(**changes):
    return {
        "variant_id": "OR-001",
        "criterion_version": "atk009-response-inventory-v1",
        "evidence_source": "target_reported_response",
        "response_text_available": True,
        "seed_indicator_present": True,
        "reported_tool_proposal_count": 1,
        "tool_execution_verified": False,
        "causal_attribution_verified": False,
        "downstream_impact": "unassessed",
        **changes,
    }


def report(observations, scope="factuality_policy", **changes):
    return ScanReport(
        target_url=ENDPOINT,
        scan_mode=ScanMode.SCAN,
        score=None,
        status="INCONCLUSIVE",
        assessment_scope=scope,
        tests_selected=2,
        tests_run=0,
        module_outcomes=[
            {
                "module_id": "ATK-009",
                "assessment_scope": scope,
                "observations": observations,
                "policy_finding_count": 1,
                **changes,
            }
        ],
    )


RENDER_SCRIPT = r"""
const fs=require('node:fs'),payload=JSON.parse(fs.readFileSync(0,'utf8'));
class Element{constructor(tag){this.tag=tag;this.children=[];this.attrs={};this.style={};this.dataset={};this._text='';}
append(...items){this.children.push(...items);}replaceChildren(...items){this.children=items;}
setAttribute(k,v){this.attrs[k]=v;}addEventListener(){}
get textContent(){return this._text+this.children.map(item=>item.textContent).join('');}
set textContent(value){this._text=String(value);this.children=[];}set innerHTML(value){throw Error('Unsafe HTML');}}
global.document={createElement:tag=>new Element(tag)};
const network=()=>{throw Error('Unexpected network');};global.fetch=network;global.XMLHttpRequest=network;
const before=JSON.stringify(payload),container=new Element('div'),analytics=require('./agentscan/ui/static/scan-analytics.js');
const summary=analytics.render(payload,container);if(JSON.stringify(payload)!==before)throw Error('Report mutation');
const all=[];function walk(node){all.push(node);node.children.forEach(walk);}walk(container);
const get=name=>all.filter(node=>Object.hasOwn(node.attrs,'data-'+name));
const rows=name=>get(name).map(row=>row.children.map(cell=>cell.textContent));
console.log(JSON.stringify({summary,policyText:get('factuality-policy-panel').map(n=>n.textContent).join(''),
inventoryText:get('overreliance-inventory-panel').map(n=>n.textContent).join(''),policyRows:rows('factuality-policy-row'),inventoryRows:rows('overreliance-inventory-row'),tags:all.map(n=>n.tag)}));
"""


def render(value, panel="factuality-policy"):
    dashboard = json.loads(node_run(RENDER_SCRIPT, value.model_dump(mode="json")))
    before = copy.deepcopy(value.model_dump())
    html = render_html_report(value)
    assert value.model_dump() == before
    match = re.search(rf"<section data-{panel}-panel\b.*?</section>", html, re.S)
    section = match.group() if match else ""
    rows = [
        [
            unescape(re.sub(r"<[^>]+>", "", cell)).strip()
            for cell in re.findall(r"<t[dh]\b[^>]*>(.*?)</t[dh]>", row, re.S)
        ]
        for row in re.findall(rf"<tr data-{panel}-row>(.*?)</tr>", section, re.S)
    ]
    return dashboard, section, rows, html


@pytest.mark.parametrize(
    ("outcome", "expected"),
    [
        ("expected_answer", "Matches approved answer"),
        ("answer_mismatch", "Approved-answer mismatch"),
        ("inconclusive", "Inconclusive"),
    ],
)
def test_exact_answer_results_are_separate_and_redacted(outcome, expected):
    value = report(
        [
            policy_observation(
                outcome=outcome, raw_response=PRIVATE, question=PRIVATE, expected_answer=PRIVATE
            )
        ]
    )
    dashboard, section, rows, html = render(value)
    assert dashboard["policyRows"] == rows == [["SYNTH-01", "Neutral question", expected, "d" * 12]]
    assert (
        "factual truth, causal attribution and downstream security impact remain unassessed"
        in section
    )
    assert "1 approved-answer policy mismatch(es)" in section
    assert PRIVATE not in html + json.dumps(dashboard)
    assert dashboard["summary"]["severity"]["total"] == 0


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("case_id", "<img src=x onerror=alert(1)>"),
        ("case_id", "x" * 65),
        ("arm", "other"),
        ("criterion_version", "future"),
        ("assessment_scope", "target"),
        ("evidence_source", "self_reported"),
        ("baseline_sha256", "A" * 64),
        ("question_sha256", None),
        ("request_sha256", True),
        ("response_sha256", PRIVATE),
        ("response_bytes", True),
        ("response_bytes", -1),
        ("outcome", "secure"),
        ("security_impact", "verified"),
        ("causal_attribution_verified", True),
    ],
)
def test_unrecognized_policy_metadata_cannot_become_a_verified_comparison(field, value):
    dashboard, section, rows, html = render(report([policy_observation(**{field: value})]))
    assert dashboard["policyRows"] == rows == [["Unavailable"] * 4]
    assert PRIVATE not in html + json.dumps(dashboard)
    assert "<img" not in section and "img" not in dashboard["tags"]


def test_missing_response_for_inconclusive_stays_visible():
    dashboard, _, rows, _ = render(
        report(
            [policy_observation(outcome="inconclusive", response_sha256=None, response_bytes=None)]
        )
    )
    assert (
        dashboard["policyRows"]
        == rows
        == [["SYNTH-01", "Neutral question", "Inconclusive", "Unavailable"]]
    )


@pytest.mark.parametrize("records", [None, {}, "records", []])
def test_missing_policy_records_and_invalid_counts_are_unavailable(records):
    dashboard, section, rows, _ = render(report(records, policy_finding_count=True))
    assert dashboard["policyRows"] == rows == []
    for text in (dashboard["policyText"], section):
        assert "No approved-answer observation records are available" in text
        assert "Unavailable approved-answer policy mismatch(es)" in text


def test_policy_rows_are_capped_across_modules_and_wrong_module_is_ignored():
    value = report([policy_observation(case_id=f"C{n}") for n in range(40)])
    value.module_outcomes.append(copy.deepcopy(value.module_outcomes[0]))
    dashboard, section, rows, _ = render(value)
    assert len(dashboard["policyRows"]) == len(rows) == 32
    assert "Only the first 32 approved-answer records are shown" in section
    value.module_outcomes = [{**value.module_outcomes[0], "module_id": "ATK-001"}]
    dashboard, section, rows, _ = render(value)
    assert dashboard["policyText"] == section == ""
    assert rows == []


@pytest.mark.parametrize("readable", [True, False, None, 1, "true"])
def test_inventory_claims_remain_unassessed_with_strict_tristate(readable):
    value = report(
        [inventory_observation(response_text_available=readable, raw_response=PRIVATE)],
        "overreliance_response_inventory",
    )
    dashboard, section, rows, html = render(value, "overreliance-inventory")
    reading = "Yes" if readable is True else "No" if readable is False else "Unavailable"
    marker = "Yes" if readable is True else "Unavailable"
    assert dashboard["inventoryRows"] == rows == [["OR-001", reading, marker, "1"]]
    assert "A text indicator does not prove hallucination or a security violation" in section
    assert PRIVATE not in html + json.dumps(dashboard)
    assert dashboard["policyRows"] == []


def test_inventory_drops_private_tool_data_and_escapes_probe_identity():
    hostile = "<img src=x onerror=alert(1)>"
    value = report(
        [inventory_observation(variant_id=hostile, tool_calls=PRIVATE, raw_response=PRIVATE)],
        "overreliance_response_inventory",
    )
    dashboard, section, rows, html = render(value, "overreliance-inventory")
    assert dashboard["inventoryRows"][0][0] == rows[0][0] == hostile
    assert "&lt;img" in section and "<img" not in section and "img" not in dashboard["tags"]
    assert PRIVATE not in html + json.dumps(dashboard)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("criterion_version", "future"),
        ("evidence_source", "independently_verified"),
        ("tool_execution_verified", True),
        ("causal_attribution_verified", 0),
        ("downstream_impact", "verified"),
    ],
)
def test_unrecognized_inventory_records_cannot_assert_observation_counts(field, value):
    value = report([inventory_observation(**{field: value})], "overreliance_response_inventory")
    dashboard, _, rows, _ = render(value, "overreliance-inventory")
    assert dashboard["inventoryRows"] == rows == [["OR-001"] + ["Unavailable"] * 3]


@pytest.mark.parametrize("count", [True, -1, 101, "1", None])
def test_inventory_proposal_counts_are_strict_bounded_integers(count):
    value = report(
        [inventory_observation(reported_tool_proposal_count=count)],
        "overreliance_response_inventory",
    )
    dashboard, _, rows, _ = render(value, "overreliance-inventory")
    assert dashboard["inventoryRows"] == rows == [["OR-001", "Yes", "Yes", "Unavailable"]]


def test_inventory_and_policy_panels_have_independent_caps():
    value = report([policy_observation(case_id=f"C{n}") for n in range(40)])
    inventory = report(
        [inventory_observation(variant_id=f"OR-{n:03}") for n in range(12)],
        "overreliance_response_inventory",
    )
    value.module_outcomes.extend(inventory.module_outcomes)
    value.assessment_scope = "mixed"
    dashboard, section, rows, _ = render(value, "overreliance-inventory")
    assert len(dashboard["inventoryRows"]) == len(rows) == 8
    assert len(dashboard["policyRows"]) == 32
    assert "Only the first 8 response inventory records are shown" in section


def test_baseline_form_is_empty_optional_and_not_persisted():
    html = (ROOT / "agentscan/ui/static/index.html").read_text(encoding="utf-8")
    assert re.search(r'<textarea id="scan-factuality-baseline"[^>]*></textarea>', html, re.S)
    assert "two requests per case (1–16 cases)" in html
    assert "expected answers stay in the scanner" in html
    assert "No analysis-provider judge is used" in html
    assert "factuality_baseline" not in "\n".join(
        line for line in html.splitlines() if "localStorage" in line or "console." in line
    )


@pytest.mark.parametrize("scope", ["factuality_policy", "overreliance_response_inventory"])
def test_dashboard_scope_never_displays_a_forged_security_score(scope):
    result = node_run(
        """
const fs=require('node:fs'),report=JSON.parse(fs.readFileSync(0,'utf8'));
const dashboard=require('./agentscan/ui/static/dashboard.js');
console.log(JSON.stringify(dashboard.summarize(report)));
""",
        {
            "status": "COMPLETE",
            "assessment_scope": scope,
            "score": 100,
            "tests_selected": 2,
            "tests_run": 2,
        },
    )
    assert json.loads(result)["score"] is None
    value = report([], scope)
    value.score = 100
    html = render_html_report(value)
    assert "UNSCORED SCOPE" in html
    assert "border-left: 5px solid #64748b;" in html
    assert "margin: 10px 0; color: #475569;" in html
