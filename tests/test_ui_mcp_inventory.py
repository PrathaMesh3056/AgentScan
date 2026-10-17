"""Catalog-only dashboard checks validate before work and preserve honest scope."""

from __future__ import annotations

import shutil
import subprocess
import threading
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

from agentscan.core.models import ScanMode, ScanReport
from agentscan.ui.app import create_app
from agentscan.ui.state import state

ENDPOINT = "mcp+sses://agent.example/mcp"
MARKER = "synthetic-secret-must-not-be-reflected"


def approved_catalog():
    return {"endpoint": ENDPOINT, "tools": {}, "algorithm": "mcp-tool-json-sha256-v1"}


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


@pytest.mark.parametrize(
    "baseline",
    [
        "",
        "{}",
        [],
        1,
        True,
        {},
        {"endpoint": ENDPOINT},
        {"endpoint": ENDPOINT, "tools": []},
        {"endpoint": ENDPOINT, "tools": {MARKER: "invalid"}},
        {"endpoint": ENDPOINT, "tools": {"tool name": "a" * 64}},
        {"endpoint": ENDPOINT, "tools": {"tool\n": "a" * 64}},
        {"endpoint": ENDPOINT, "tools": {"töol": "a" * 64}},
        {"endpoint": ENDPOINT, "tools": {"tool": "A" * 64}},
        {"endpoint": ENDPOINT, "tools": {"tool": True}},
        {"endpoint": ENDPOINT, "tools": {}, "algorithm": MARKER},
        {"endpoint": ENDPOINT, "tools": {}, MARKER: "unexpected"},
        {"endpoint": ENDPOINT, "tools": {f"tool{n}": "a" * 64 for n in range(1001)}},
        {"endpoint": ENDPOINT + "x" * 262144, "tools": {}},
    ],
)
def test_invalid_catalog_never_starts_or_echoes_input(client, monkeypatch, baseline):
    run = AsyncMock()
    monkeypatch.setattr("agentscan.core.runner.run_scan_multi", run)
    response = client.post(
        "/api/scan", json={"target_url": ENDPOINT, "mcp_inventory_baseline": baseline}
    )
    assert response.status_code == 400
    assert "mcp_inventory_baseline" in response.json()["field_errors"]
    assert MARKER not in response.text
    run.assert_not_called()
    assert state.active_scan is None


@pytest.mark.parametrize(
    "overrides",
    [
        {"target_url": "https://agent.example/mcp"},
        {"target_url": "mcp+sses://other.example/mcp"},
        {"target_url": "mcp+stdio://server"},
        {"mode": "ACTIVE"},
        {"mode": "DEEP"},
        {"exploit": True},
        {"deep": True},
        {"mutate": True},
        {"indirect_adapter": "document_v1"},
        {"analysis_mode": "local", "local_model": "ollama/example"},
        {"attacker_model": "ollama/example"},
        {"attacker_goal": MARKER},
        {"judge_model": "ollama/example"},
        {"attacker_turns": 2},
    ],
)
def test_catalog_rejects_conflicting_workflows_before_execution(client, monkeypatch, overrides):
    run = AsyncMock()
    monkeypatch.setattr("agentscan.core.runner.run_scan_multi", run)
    response = client.post(
        "/api/scan",
        json={"target_url": ENDPOINT, "mcp_inventory_baseline": approved_catalog(), **overrides},
    )
    assert response.status_code == 400
    assert response.json()["field_errors"]
    assert MARKER not in response.text
    run.assert_not_called()
    assert state.active_scan is None


@pytest.mark.parametrize("tools", [{}, {"Read": "a" * 64, "read": "b" * 64}])
def test_approved_catalog_reaches_typed_target_and_scope_is_visible(client, monkeypatch, tools):
    called = threading.Event()
    report = ScanReport(
        target_url=ENDPOINT,
        scan_mode=ScanMode.SCAN,
        status="COMPLETE",
        score=None,
        assessment_scope="mcp_catalog_policy",
        tests_selected=1,
        tests_run=1,
        module_outcomes=[
            {
                "module_id": "ATK-006",
                "status": "COMPLETE",
                "assessment_scope": "mcp_catalog_policy",
                "selected_tests": 1,
                "executed_tests": 1,
                "catalog_finding_count": 1,
                "catalog_findings": [{"description": "Approved catalog mismatch"}],
            }
        ],
    )

    async def complete(target, modes):
        assert target.mcp_inventory_baseline is not None
        assert target.mcp_inventory_baseline.tools == tools
        assert target.mcp_inventory_baseline.endpoint == target.url == ENDPOINT
        assert target.analysis_mode == "deterministic"
        assert modes == [ScanMode.SCAN]
        called.set()
        return report

    run = AsyncMock(side_effect=complete)
    monkeypatch.setattr("agentscan.core.runner.run_scan_multi", run)
    response = client.post(
        "/api/scan",
        json={
            "target_url": ENDPOINT,
            "mcp_inventory_baseline": {"endpoint": ENDPOINT, "tools": tools},
        },
    )
    assert response.status_code == 200
    assert called.wait(5)
    status = client.get("/api/scan/status").json()
    assert status["assessment_scope"] == "mcp_catalog_policy"
    assert status["score"] is None
    assert status["findings_count"] == 0
    assert status["module_outcomes"][0]["catalog_finding_count"] == 1
    assert "mcp_inventory_baseline" not in status


@pytest.mark.parametrize("baseline", [None, "omitted"])
def test_regular_scan_remains_available_without_catalog(client, monkeypatch, baseline):
    called = threading.Event()

    async def complete(target, modes):
        assert target.mcp_inventory_baseline is None
        called.set()
        return ScanReport(target_url=target.url, scan_mode=ScanMode.SCAN)

    monkeypatch.setattr("agentscan.core.runner.run_scan_multi", AsyncMock(side_effect=complete))
    payload = {"target_url": "http://agent.example/chat"}
    if baseline is None:
        payload["mcp_inventory_baseline"] = None
    assert client.post("/api/scan", json=payload).status_code == 200
    assert called.wait(5)


def test_feature_manifest_distinguishes_exported_and_target_catalogs(client):
    workflows = {item["id"]: item for item in client.get("/api/features").json()["workflows"]}
    assert workflows["mcp_inventory"]["action"] == "scan"
    assert "without invoking" in workflows["mcp_inventory"]["note"]
    assert "own tools" in workflows["mcp"]["note"]


def test_frontend_catalog_schema_cross_fields_and_nested_server_errors():
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is required for dashboard JavaScript validation")
    root = Path(__file__).resolve().parents[1]
    script = r"""
    const assert = require('node:assert/strict');
    const elements = {};
    const element = id => ({id,value:'',checked:false,options:[],attrs:{},dataset:{},
      parentElement:{append(node){elements[node.id]=node;}},
      setAttribute(k,v){this.attrs[k]=v;},getAttribute(k){return this.attrs[k] || null;},
      removeAttribute(k){delete this.attrs[k];},focus(){this.focused=true;}});
    global.document = {getElementById:id=>elements[id] || null,createElement:()=>element('')};
    const forms = require('./agentscan/ui/static/form-validation.js');
    for(const spec of forms.inventory().filter(spec=>spec.workflow==='scan')) {
      const field = elements[spec.id] = element(spec.id);
      field.value = spec.type === 'choice' ? spec.choices[0] : spec.type === 'integer' ? '4' : '';
    }
    const endpoint = 'mcp+sses://agent.example/mcp';
    elements['scan-target-url'].value = endpoint;
    const catalog = elements['scan-mcp-inventory-baseline'];
    const spec = forms.inventory().find(spec=>spec.field==='mcp_inventory_baseline');
    const valid = {endpoint,tools:{Read:'a'.repeat(64),read:'b'.repeat(64)}};
    assert.deepEqual(forms.checkField(spec,JSON.stringify(valid)).value,valid);
    for(const value of ['null','[]','true','{}','{"endpoint":"x","tools":[]}',JSON.stringify({...valid,algorithm:'other'}),JSON.stringify({...valid,secret:'do-not-echo'}),JSON.stringify({...valid,tools:{Read:'A'.repeat(64)}}),JSON.stringify({...valid,tools:{'tool name':'a'.repeat(64)}}),JSON.stringify({...valid,tools:Object.fromEntries(Array.from({length:1001},(_,i)=>['t'+i,'a'.repeat(64)]))}),' '.repeat(262145)+'{}']) {
      const result=forms.checkField(spec,value);
      assert.ok(result.error,'reject catalog shape');
      assert.ok(!result.error.includes('do-not-echo'));
    }
    assert.equal(forms.checkField(spec,'').value,null);
    catalog.value = JSON.stringify({endpoint,tools:{}});
    assert.equal(forms.validate('scan',{render:false}).valid,true);
    assert.deepEqual(forms.getValues('scan').mcp_inventory_baseline.tools,{});
    for(const [id,value] of [['scan-mode','ACTIVE'],['scan-analysis-mode','local'],['scan-indirect-adapter','document_v1'],['scan-target-url','https://agent.example/mcp']]) {
      const prior=elements[id].value;elements[id].value=value;
      assert.ok(forms.validate('scan',{render:false}).errors.mcp_inventory_baseline);
      elements[id].value=prior;
    }
    forms.applyServer('scan',{field_errors:{'mcp_inventory_baseline.tools.Read':'Provide an approved hash.'}});
    assert.equal(catalog.attrs['aria-invalid'],'true');
    assert.ok(elements['scan-mcp-inventory-baseline-error'].textContent.includes('approved hash'));
    assert.equal(elements['scan-target-url'].attrs['aria-invalid'],undefined);
    """
    subprocess.run(
        [node, "-e", script], cwd=root, check=True, capture_output=True, text=True, timeout=20
    )


def test_catalog_field_is_not_persisted_or_logged():
    root = Path(__file__).resolve().parents[1]
    html = (root / "agentscan/ui/static/index.html").read_text(encoding="utf-8")
    assert 'id="scan-mcp-inventory-baseline"' in html
    assert "Catalog deviations are separate" in html
    assert "without calling tools" in html
    assert "mcp_inventory_baseline" not in "\n".join(
        line for line in html.splitlines() if "localStorage" in line or "console." in line
    )


def test_catalog_analytics_separates_findings_and_renders_untrusted_names_as_text():
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is required for dashboard analytics")
    root = Path(__file__).resolve().parents[1]
    script = r"""
    const assert = require('node:assert/strict');
    class Element {
      constructor(tag){this.tag=tag;this.children=[];this.attrs={};this.style={};this.dataset={};this._text='';}
      append(...items){this.children.push(...items);}
      replaceChildren(...items){this.children=items;}
      setAttribute(k,v){this.attrs[k]=v;}
      addEventListener(){}
      get textContent(){return this._text+this.children.map(item=>item.textContent).join('');}
      set textContent(value){this._text=String(value);this.children=[];}
      set innerHTML(value){throw new Error('unsafe HTML rendering');}
    }
    global.document={createElement:tag=>new Element(tag)};
    global.fetch=()=>{throw new Error('unexpected network');};
    const analytics=require('./agentscan/ui/static/scan-analytics.js');
    const report={status:'COMPLETE',assessment_scope:'mcp_catalog_policy',tests_selected:1,tests_run:1,findings:[],module_outcomes:[{
      module_id:'ATK-006',status:'COMPLETE',assessment_scope:'mcp_catalog_policy',selected_tests:1,executed_tests:1,catalog_finding_count:1,
      catalog_findings:[{description:'Three catalog mismatches',metadata:{deviation_count:3,deviations:[{kind:'unexpected_tool',name:'<img src=x onerror=throw>'}]}}]
    }]};
    const before=JSON.stringify(report), container=new Element('div');
    const summary=analytics.render(report,container);
    assert.equal(summary.severity.total,0);
    assert.equal(summary.modules[0].catalogFindingCount,1);
    assert.equal(summary.modules[0].catalogFindings[0].deviationCount,3);
    assert.ok(container.textContent.includes('MCP catalog policy · excluded from target score'));
    assert.ok(container.textContent.includes('3 recorded catalog deviations'));
    assert.ok(container.textContent.includes('<img src=x onerror=throw>'));
    assert.ok(container.textContent.includes('do not prove tool execution'));
    const tags=[];function walk(item){tags.push(item.tag);item.children.forEach(walk);}walk(container);
    assert.ok(!tags.includes('img'));
    assert.equal(JSON.stringify(report),before);
    """
    subprocess.run(
        [node, "-e", script], cwd=root, check=True, capture_output=True, text=True, timeout=20
    )
