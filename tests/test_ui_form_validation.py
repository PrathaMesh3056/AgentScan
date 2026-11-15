"""Dashboard field contracts: rejected values never start work or echo secrets."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from html.parser import HTMLParser
from pathlib import Path
from unittest.mock import AsyncMock, Mock

import pytest
from fastapi.testclient import TestClient

from agentscan.ui.app import create_app
from agentscan.ui.state import state
from agentscan.ui.validation import Fields


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.delenv("AGENTSCAN_UI_TOKEN", raising=False)
    monkeypatch.setattr(state, "active_scan", None)
    monkeypatch.setattr(state, "sentinel_task", None)
    monkeypatch.setattr(state, "report", None)
    (tmp_path / "example.py").write_text("print('example')", encoding="utf-8")
    with TestClient(create_app(project_root=tmp_path), base_url="http://127.0.0.1:8765") as value:
        value.get("/")
        yield value


@pytest.mark.parametrize(
    "value",
    [
        "",
        "   ",
        None,
        1,
        True,
        [],
        {},
        "http://host:0/chat",
        "http://host:99999/chat",
        "ftp://host/chat",
        "https://user:secret@host/chat",
        "http://host/chat#fragment",
        "http://host/has space",
        "http://host/" + chr(0),
    ],
)
@pytest.mark.parametrize(
    "endpoint,key",
    [
        ("/api/scan", "target_url"),
        ("/api/discovery", "url"),
        ("/api/swarms/run", "target_url"),
        ("/api/sentinel/start", "target_url"),
        ("/api/sentinel/probe", "target_url"),
    ],
)
def test_invalid_targets_stop_before_work(client, monkeypatch, endpoint, key, value):
    work = AsyncMock()
    monkeypatch.setattr("agentscan.core.runner.run_scan_multi", work)
    monkeypatch.setattr("agentscan.core.discovery.discover_http", work)
    monkeypatch.setattr("agentscan.swarm.coordinator.SwarmCoordinator.run_swarm", work)
    monkeypatch.setattr("agentscan.sentinel.watcher.ContinuousWatcher.run_iteration", work)
    monkeypatch.setattr("agentscan.sentinel.watcher.ContinuousWatcher.run_loop", work)
    response = client.post(endpoint, json={key: value})
    assert response.status_code == 400
    assert key in response.json()["field_errors"]
    assert "secret@" not in response.text
    work.assert_not_called()
    assert state.active_scan is None
    assert state.sentinel_task is None


@pytest.mark.parametrize("value", ["", " ", "4", None, True, False, -1, 0, 1.5, 100001])
@pytest.mark.parametrize(
    "endpoint,key",
    [
        ("/api/scan", "concurrency"),
        ("/api/swarms/run", "rounds"),
        ("/api/sentinel/start", "interval_seconds"),
        ("/api/sentinel/start", "max_iterations"),
    ],
)
def test_numeric_fields_reject_coercion(client, endpoint, key, value):
    response = client.post(endpoint, json={"target_url": "http://agent.example/chat", key: value})
    assert response.status_code == 400
    assert key in response.json()["field_errors"]


@pytest.mark.parametrize(
    "endpoint,key",
    [
        ("/api/scan", "exploit"),
        ("/api/scan", "deep"),
        ("/api/scan", "mutate"),
        ("/api/discovery", "no_exploit"),
        ("/api/audit", "offline"),
        ("/api/audit", "show_transitive"),
        ("/api/audit", "scan_deps"),
        ("/api/audit", "scan_config"),
        ("/api/audit", "scan_secrets"),
        ("/api/audit", "scan_typo"),
        ("/api/audit", "scan_mcp"),
        ("/api/audit", "scan_identity"),
        ("/api/audit", "scan_frameworks"),
        ("/api/audit", "scan_semgrep"),
        ("/api/heal/apply", "backup"),
        ("/api/heal/server/simulate", "apply"),
    ],
)
@pytest.mark.parametrize("value", ["false", 0, None])
def test_boolean_fields_are_strict(client, endpoint, key, value):
    response = client.post(
        endpoint,
        json={
            "target_url": "http://agent.example/chat",
            "url": "http://agent.example/chat",
            key: value,
        },
    )
    assert response.status_code == 400
    assert key in response.json()["field_errors"]


@pytest.mark.parametrize(
    "endpoint,key,value",
    [
        ("/api/scan", "mode", "wrong"),
        ("/api/scan", "framework", "wrong"),
        ("/api/scan", "indirect_adapter", "tool_v1"),
        ("/api/scan", "indirect_adapter", ""),
        ("/api/scan", "indirect_adapter", None),
        ("/api/scan", "indirect_adapter", True),
        ("/api/discovery", "mode", "wrong"),
        ("/api/swarms/run", "team", "wrong"),
        ("/api/audit", "ruleset", "wrong"),
        ("/api/calibrate", "model", "gemini/model"),
        ("/api/calibrate", "model", "ollama/model-cloud"),
        ("/api/events", "type", "bad\nname"),
        ("/api/events", "data", []),
        ("/api/mcp/invoke", "arguments", []),
        ("/api/mcp/invoke", "name", "no-tool"),
        ("/api/certificate", "secret_key", "short"),
        ("/api/certificate", "secret_key", 7),
        ("/api/heal/apply", "kinds", "ast_patch"),
        ("/api/heal/apply", "kinds", ["unknown"]),
        ("/api/heal/apply", "root_path", 7),
    ],
)
def test_other_fields_have_actionable_errors(client, endpoint, key, value):
    response = client.post(
        endpoint,
        json={
            "target_url": "http://agent.example/chat",
            "url": "http://agent.example/chat",
            key: value,
        },
    )
    assert response.status_code == 400
    assert key in response.json()["field_errors"]


@pytest.mark.parametrize("mode,key", [("local", "local_model"), ("external", "external_model")])
@pytest.mark.parametrize("value", ["", " ", None, 42, "wrong", "ollama/model-cloud"])
def test_analysis_model_fields(client, mode, key, value):
    response = client.post(
        "/api/scan",
        json={
            "target_url": "http://agent.example/chat",
            "analysis_mode": mode,
            "data_classification": "non_sensitive",
            key: value,
        },
    )
    assert response.status_code == 400
    assert key in response.json()["field_errors"]


def test_inactive_models_are_ignored_and_sensitive_external_is_blocked():
    fields = Fields({"local_model": 42, "external_model": [], "analysis_mode": "deterministic"})
    assert fields.analysis()["analysis_mode"] == "deterministic"
    assert not fields.errors
    fields = Fields({"analysis_mode": "external", "external_model": "gemini/example"})
    fields.analysis()
    assert "data_classification" in fields.errors


@pytest.mark.parametrize(
    "value",
    [
        42,
        True,
        False,
        [],
        {},
        "short",
        "x" * 129,
        "bad reference value",
        "abc!" * 5,
        "abcdefghijklmnoé",
        "valid_reference_001\x00",
    ],
)
def test_invalid_private_reference_stops_before_scan_without_echo(client, monkeypatch, value):
    work = AsyncMock()
    monkeypatch.setattr("agentscan.core.runner.run_scan_multi", work)
    response = client.post(
        "/api/scan", json={"target_url": "http://agent.example/chat", "canary_token": value}
    )
    assert response.status_code == 400
    assert "canary_token" in response.json()["field_errors"]
    if isinstance(value, str):
        assert value not in response.text
    work.assert_not_called()
    assert state.active_scan is None


@pytest.mark.parametrize("value", [None, "", "   ", "SYNTHETIC_PRIVATE_REFERENCE_001"])
def test_optional_private_reference_reaches_background_target(client, monkeypatch, value):
    from agentscan.core.models import ScanMode, ScanReport

    captured = []

    async def scan(target, modes):
        captured.append((target, modes))
        return ScanReport(target_url=target.url, scan_mode=ScanMode.SCAN)

    monkeypatch.setattr("agentscan.core.runner.run_scan_multi", scan)
    response = client.post(
        "/api/scan", json={"target_url": "http://agent.example/chat", "canary_token": value}
    )
    assert response.status_code == 200
    # Read status through the same event loop after the scheduled coroutine.
    client.get("/api/status")
    assert len(captured) == 1
    target, modes = captured[0]
    assert target.canary_token == (value.strip() or None if isinstance(value, str) else None)
    assert modes == [ScanMode.SCAN]
    assert target.analysis_mode == "deterministic"
    assert not target.include_sensitive_data
    if value and value.strip():
        assert value not in response.text


@pytest.mark.parametrize("scheme", ["http", "https", "ws", "wss", "mcp+sse", "mcp+sses"])
def test_scan_protocols_preserved(scheme):
    fields = Fields({"target_url": f"{scheme}://agent.example/chat"})
    assert (
        fields.url("target_url", schemes=("http", "https", "ws", "wss", "mcp+sse", "mcp+sses"))
        == f"{scheme}://agent.example/chat"
    )
    assert not fields.errors


@pytest.mark.parametrize("value", [float("nan"), float("inf"), True, "5", 1.1])
def test_integer_nan_and_infinite_are_invalid(value):
    fields = Fields({"value": value})
    fields.integer("value", 1, 10)
    assert fields.errors


def test_optional_blank_fields_and_valid_signing_key(client, monkeypatch):
    fields = Fields({"webhook_url": "  ", "system_prompt": ""})
    assert fields.url("webhook_url", required=False) is None
    assert fields.text("system_prompt") is None
    assert not fields.errors
    monkeypatch.setenv("AGENTSCAN_HMAC_KEY", "x" * 32)
    assert client.post("/api/certificate", json={"secret_key": ""}).status_code == 200
    assert client.post("/api/certificate", json={"secret_key": "x" * 32}).status_code == 200


def test_safe_json_object_size_and_nonfinite_contract():
    for value in ([], None, {"x": "s" * 65536}, {"x": float("nan")}):
        fields = Fields({"data": value})
        fields.object("data")
        assert fields.errors


@pytest.mark.parametrize(
    "endpoint,payload,key",
    [
        ("/api/audit", {"path": ""}, "path"),
        ("/api/audit", {"path": "missing"}, "path"),
        ("/api/audit", {"path": "../outside"}, "path"),
        ("/api/discovery/save", {"profile": [], "output_path": "target.yaml"}, "profile"),
        (
            "/api/discovery/save",
            {"profile": {"url": "http://agent.example"}, "output_path": ""},
            "output_path",
        ),
        (
            "/api/discovery/save",
            {"profile": {"url": "http://agent.example"}, "output_path": "target.exe"},
            "output_path",
        ),
        (
            "/api/heal/server/simulate",
            {"file": "missing.py", "vulnerability_type": "SQL_INJECTION", "evidence": "simulation"},
            "file",
        ),
        (
            "/api/heal/server/simulate",
            {"file": "example.py", "vulnerability_type": "wrong", "evidence": "simulation"},
            "vulnerability_type",
        ),
        (
            "/api/heal/server/simulate",
            {"file": "example.py", "vulnerability_type": "SQL_INJECTION", "evidence": ""},
            "evidence",
        ),
    ],
)
def test_file_and_simulation_fields(client, endpoint, payload, key):
    response = client.post(endpoint, json=payload)
    assert response.status_code in (400, 403)
    assert key in response.json()["field_errors"]


def test_real_simulation_shape_plans_without_writing(client, monkeypatch):
    from agentscan.remediation.models import FixPlan

    plan = Mock(return_value=FixPlan(actions=[]))
    apply = Mock()
    monkeypatch.setattr("agentscan.remediation.engine.RemediationEngine.plan", plan)
    monkeypatch.setattr("agentscan.remediation.engine.RemediationEngine.apply", apply)
    response = client.post(
        "/api/heal/server/simulate",
        json={
            "file": "example.py",
            "vulnerability_type": "SQL_INJECTION",
            "evidence": "simulated alert",
        },
    )
    assert response.status_code == 200
    finding = plan.call_args.args[0][0]
    assert finding.metadata["simulation"] is True
    assert finding.metadata["file"].endswith("example.py")
    apply.assert_not_called()


class Controls(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = set()

    def handle_starttag(self, tag, attrs):
        if tag in ("input", "select", "textarea"):
            identifier = dict(attrs).get("id")
            assert identifier, f"Missing field ID on {tag}"
            self.ids.add(identifier)


def authored_control_ids(html):
    controls = Controls()
    controls.feed(html)
    controls.close()
    # Certificate controls are authored inside a JavaScript render template.
    for markup in re.findall(r"<(?:input|select|textarea)\b[^>]*>", html):
        # Each opening tag is a separate fragment; textarea state must not leak.
        fragment = Controls()
        fragment.feed(markup)
        fragment.close()
        controls.ids.update(fragment.ids)
    return controls.ids


def test_authored_controls_include_templates_after_textarea(monkeypatch):
    # Exercise newer raw-text parsing behavior on older Python patch releases too.
    monkeypatch.setattr(
        Controls, "CDATA_CONTENT_ELEMENTS", (*Controls.CDATA_CONTENT_ELEMENTS, "textarea")
    )
    html = (
        '<textarea id="task"></textarea>'
        '<script>const field = `<input id="cert-secret-key" />`;</script>'
    )
    assert authored_control_ids(html) == {"task", "cert-secret-key"}


def test_every_authored_control_has_validation_and_invalid_value_case():
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is required to test dashboard JavaScript validation")
    root = Path(__file__).resolve().parents[1]
    html = (root / "agentscan/ui/static/index.html").read_text(encoding="utf-8")
    # Authored controls may live in the externalized dashboard scripts too.
    for script_name in (
        "dashboard-app-core.js",
        "dashboard-app-renderers.js",
        "dashboard-app-actions.js",
    ):
        script_path = root / "agentscan/ui/static" / script_name
        assert script_path.is_file(), script_name
        html += "\n" + script_path.read_text(encoding="utf-8")
    control_ids = authored_control_ids(html)
    script = r"""
    const assert = require('node:assert/strict');
    const forms = require('./agentscan/ui/static/form-validation.js');
    const inventory = forms.inventory();
    const good = {url:'http://agent.example/chat',path:'example.py',integer:'5',choice:null,boolean:false,consent:true,localModel:'ollama/example',externalModel:'example-1',tool:'agentscan_scan',jsonObject:'{}',signingKey:'x'.repeat(32),text:'example',canary:'SYNTHETIC_PRIVATE_REFERENCE_001'};
    for (const spec of inventory) {
      const valid = spec.type === 'choice' ? spec.choices[0] : good[spec.type];
      assert.ok(!forms.checkField(spec, valid).error, spec.id + ' valid');
      if (spec.optional) assert.ok(!forms.checkField(spec, '').error, spec.id + ' optional');
      else if (spec.type !== 'boolean') assert.ok(forms.checkField(spec, '').error, spec.id + ' blank');
      if (spec.type === 'integer') for (const value of ['NaN','Infinity','1.5','true',String(spec.min-1),String(spec.max+1)]) assert.ok(forms.checkField(spec,value).error,spec.id + ' numeric');
      if (spec.type === 'boolean') assert.ok(forms.checkField(spec,'false').error,spec.id + ' boolean');
      if (spec.type === 'url') for (const value of ['ftp://host','http://host:0','http://u:p@host','http://host/#fragment','http://host/a b']) assert.ok(forms.checkField(spec,value).error,spec.id + ' URL');
      if (spec.type === 'signingKey') for (const value of ['short','agentscan-audit-verification-key']) assert.ok(forms.checkField(spec,value).error,spec.id + ' signing key');
      if (spec.type === 'localModel') assert.ok(forms.checkField(spec,'ollama/example-cloud').error,spec.id + ' local cloud model');
      if (spec.type === 'canary') for (const value of ['short', 'x'.repeat(129), 'bad reference value', 'abc!'.repeat(5), 'abcdefghijklmnoé']) assert.ok(forms.checkField(spec,value).error,spec.id + ' synthetic reference');
      if (spec.type === 'text' || spec.type === 'path') assert.ok(forms.checkField(spec,'bad\0value').error,spec.id + ' null');
      if (spec.type === 'jsonObject') for (const value of ['[]','null','1','{"x":}', '"scalar"']) assert.ok(forms.checkField(spec,value).error,spec.id + ' JSON');
    }
    console.log(JSON.stringify(inventory));
    """
    result = subprocess.run(
        [node, "-e", script], cwd=root, check=True, capture_output=True, text=True, timeout=20
    )
    inventory = json.loads(result.stdout)
    assert control_ids == {field["id"] for field in inventory}


@pytest.mark.parametrize(
    "endpoint", ["/api/aibom", "/api/aibom/download", "/api/dependencies/graph"]
)
@pytest.mark.parametrize("path", ["", "   ", "missing", "../outside"])
def test_query_path_errors_are_explicit(client, endpoint, path):
    response = client.get(endpoint, params={"path": path})
    assert response.status_code in (400, 403)
    assert "path" in response.json()["field_errors"]


@pytest.mark.parametrize(
    "payload,key",
    [
        ({"report": [], "certificate": {}}, "report"),
        ({"certificate": []}, "certificate"),
        ({"certificate": "not-object"}, "certificate"),
        ({"certificate": {"algorithm": "HMAC-SHA256"}, "secret_key": "short"}, "secret_key"),
    ],
)
def test_verification_json_and_key_fields(client, payload, key):
    response = client.post("/api/verify-certificate", json=payload)
    assert response.status_code == 400
    assert key in response.json()["field_errors"]


@pytest.mark.parametrize(
    "name,arguments,key",
    [
        ("agentscan_scan", {"target_url": ""}, "target_url"),
        ("agentscan_scan", {"target_url": "http://agent.example", "timeout": True}, "timeout"),
        ("agentscan_swarm", {"target_url": "http://agent.example", "rounds": 0}, "rounds"),
        ("agentscan_swarm", {"target_url": "http://agent.example", "team": ""}, "team"),
        (
            "agentscan_swarm",
            {"target_url": "http://agent.example", "offline": False, "model": "gemini/model"},
            "model",
        ),
        ("agentscan_audit", {"path": "", "offline": True}, "path"),
        ("agentscan_audit", {"offline": "false"}, "offline"),
    ],
)
def test_dynamic_mcp_arguments_are_validated_before_dispatch(
    client, monkeypatch, name, arguments, key
):
    process = Mock()
    monkeypatch.setattr("agentscan.mcp.server.process_jsonrpc_message", process)
    response = client.post("/api/mcp/invoke", json={"name": name, "arguments": arguments})
    assert response.status_code == 400
    assert f"arguments.{key}" in response.json()["field_errors"]
    process.assert_not_called()


def test_profile_save_creates_scoped_directory_and_protects_existing_file(client):
    payload = {"profile": {"url": "http://agent.example/chat"}, "output_path": "guide-test.yaml"}
    assert client.post("/api/discovery/save", json=payload).status_code == 200
    response = client.post("/api/discovery/save", json=payload)
    assert response.status_code == 409
    assert "output_path" in response.json()["field_errors"]
    response = client.post(
        "/api/discovery/save", json={**payload, "output_path": "../../escape.yaml"}
    )
    assert response.status_code == 403


@pytest.mark.parametrize("value", ["", "wrong", None, True])
@pytest.mark.parametrize("key", ["analysis_mode", "data_classification"])
def test_analysis_enum_values(client, key, value):
    response = client.post("/api/scan", json={"target_url": "http://agent.example", key: value})
    assert response.status_code == 400
    assert key in response.json()["field_errors"]


def test_form_dom_errors_are_accessible_and_inactive_fields_do_not_block():
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is required for dashboard validation")
    root = Path(__file__).resolve().parents[1]
    script = r"""
    const assert = require('node:assert/strict');
    const elements = {};
    const element = id => ({id, value:'', checked:false, options:[], dataset:{}, attrs:{}, events:{}, hidden:true, textContent:'',
      parentElement:{append(node){ elements[node.id]=node; }},
      setAttribute(k,v){this.attrs[k]=v;},getAttribute(k){return this.attrs[k] || null;},removeAttribute(k){delete this.attrs[k];},
      addEventListener(k,fn){(this.events[k] ||= []).push(fn);}, focus(){this.focused=true;}});
    global.document={getElementById:id => elements[id] || null, createElement:() => element('')};
    const forms=require('./agentscan/ui/static/form-validation.js');
    const defaults={url:'http://agent.example/chat',path:'example.py',integer:'5',boolean:false,consent:false,localModel:'ollama/example',externalModel:'example',tool:'agentscan_audit',jsonObject:'{}',signingKey:'',text:'example'};
    for (const spec of forms.inventory()) {
      const field=elements[spec.id] ||= element(spec.id);
      field.value=spec.type==='choice' ? spec.choices[0] : defaults[spec.type];
      field.checked=spec.type==='boolean';
      field.options=[{value:field.value}];
    }
    for(const workflow of new Set(forms.inventory().map(x=>x.workflow))) assert.ok(forms.validate(workflow).valid,workflow);
    elements['scan-target-url'].value='  ';
    assert.equal(forms.validate('scan').valid,false);
    assert.equal(elements['scan-target-url'].attrs['aria-invalid'],'true');
    assert.ok(elements['scan-target-url'].focused);
    assert.match(elements['scan-target-url-error'].textContent,/required/);
    elements['scan-target-url'].value='http://agent.example';
    elements['scan-local-model'].value='invalid hidden';
    elements['scan-external-model'].value='invalid hidden';
    assert.ok(forms.validate('scan').valid);
    assert.ok(!elements['scan-target-url'].attrs['aria-invalid']);
    elements['scan-analysis-mode'].value='external';
    assert.equal(forms.validate('scan').valid,false);
    assert.equal(elements['scan-external-consent'].attrs['aria-invalid'],'true');
    forms.attach();
    elements['scan-analysis-mode'].value='deterministic';
    for(const fn of elements['scan-analysis-mode'].events.change) fn();
    assert.ok(!elements['scan-external-model'].attrs['aria-invalid']);
    forms.applyServer('mcp',{field_errors:{'arguments.target_url':'Enter an actual target endpoint.'}});
    assert.equal(elements['mcp-tool-args'].attrs['aria-invalid'],'true');
    assert.match(elements['mcp-tool-args-error'].textContent,/actual target/);
    for(const spec of forms.inventory().filter(spec=>spec.workflow==='audit' && spec.field.startsWith('scan_'))) elements[spec.id].checked=false;
    assert.match(forms.validate('audit').errors.ruleset,/at least one/);
    elements['sentinel-interval-seconds'].value='bad';
    assert.ok(forms.validate('sentinelProbe').valid);
    assert.equal(forms.validate('sentinel').valid,false);
    """
    subprocess.run(
        [node, "-e", script], cwd=root, check=True, capture_output=True, text=True, timeout=20
    )


@pytest.mark.parametrize(
    "payload,key",
    [
        ({}, "findings"),
        ({"findings": [{"metadata": []}]}, "findings.0.metadata"),
        ({"findings": [{"severity": "wrong"}]}, "findings.0.severity"),
        ({"findings": [{"evidence": []}]}, "findings.0.evidence"),
    ],
)
def test_raw_alert_findings_fail_before_planning(client, monkeypatch, payload, key):
    plan = Mock()
    monkeypatch.setattr("agentscan.remediation.engine.RemediationEngine.plan", plan)
    response = client.post("/api/heal/server/simulate", json=payload)
    assert response.status_code == 400
    assert key in response.json()["field_errors"]
    plan.assert_not_called()


@pytest.mark.parametrize(
    "value",
    [
        "Bad Header: secret",
        ": secret",
        "Authorization:",
        "Authorization: secret\r\nInjected: value",
        "Bearer synthetic-token\n",
        "secret" + chr(1),
        "secret" + chr(127),
        "token-" + chr(233),
        "x" * 4097,
    ],
)
def test_invalid_target_auth_headers_fail_before_start(client, value):
    response = client.post(
        "/api/scan", json={"target_url": "http://agent.example", "auth_header": value}
    )
    assert response.status_code == 400
    assert "auth_header" in response.json()["field_errors"]
    assert "secret" not in response.text
    assert state.active_scan is None


@pytest.mark.parametrize(
    "value",
    [
        "",
        "Bearer synthetic-token",
        "Authorization: Bearer synthetic-token",
        "X-Api-Key: synthetic-token",
    ],
)
def test_valid_optional_header_shapes(value):
    fields = Fields({"auth_header": value})
    assert fields.header("auth_header") == (value or None)
    assert not fields.errors


def test_sentinel_failure_is_visible_without_echoing_secret_and_restart_clears_it(
    client, monkeypatch
):
    secret = "synthetic-secret-in-exception"
    log = Mock()
    published = []

    async def publish(event):
        published.append(event)

    monkeypatch.setattr("agentscan.ui.routers.sentinel.logger.error", log)
    monkeypatch.setattr("agentscan.ui.routers.sentinel.event_bus.publish", publish)
    watcher = AsyncMock(side_effect=RuntimeError(secret))
    monkeypatch.setattr("agentscan.sentinel.watcher.ContinuousWatcher.run_loop", watcher)
    response = client.post(
        "/api/sentinel/start",
        json={"target_url": "http://agent.example/chat", "interval_seconds": 5},
    )
    assert response.status_code == 200
    result = client.get("/api/sentinel/status").json()
    assert result["running"] is False
    assert result["status"] == "ERROR"
    assert result["error_id"]
    assert "monitoring failed" in result["error"]
    assert secret not in json.dumps(result)
    assert secret not in repr(log.call_args)
    failures = [event for event in published if event["type"] == "sentinel:error"]
    assert failures[0]["data"]["error_id"] == result["error_id"]
    assert secret not in json.dumps(published)
    watcher.side_effect = None
    response = client.post(
        "/api/sentinel/start",
        json={"target_url": "http://agent.example/chat", "interval_seconds": 5},
    )
    assert response.status_code == 200
    result = client.get("/api/sentinel/status").json()
    assert result["error"] is None
    assert result["error_id"] is None
    assert result["status"] != "ERROR"


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["http401", "connection", "timeout", "runtime", "response"])
async def test_actual_watcher_cannot_turn_target_failures_into_pass(failure):
    import httpx

    from agentscan.core.models import Target
    from agentscan.core.outcomes import TargetRequestError
    from agentscan.sentinel.watcher import ContinuousWatcher, SentinelProbeError

    secret = "synthetic-secret-target-error"
    errors = {
        "http401": TargetRequestError("Target returned HTTP 401"),
        "connection": httpx.ConnectError(secret),
        "timeout": httpx.ReadTimeout(secret),
        "runtime": RuntimeError(secret),
    }
    connector = Mock()
    connector.send_prompt = AsyncMock(
        side_effect=errors.get(failure), return_value=object() if failure == "response" else "safe"
    )
    watcher = ContinuousWatcher(Target(url="http://agent.example"))
    with pytest.raises(SentinelProbeError) as captured:
        await watcher.run_iteration(connector)
    assert secret not in str(captured.value)
    if failure == "http401":
        assert "HTTP 401" in str(captured.value)
    connector.send_prompt.assert_awaited_once()


@pytest.mark.asyncio
async def test_watcher_preserves_cancellation():
    import asyncio

    from agentscan.core.models import Target
    from agentscan.sentinel.watcher import ContinuousWatcher

    connector = Mock(send_prompt=AsyncMock(side_effect=asyncio.CancelledError()))
    with pytest.raises(asyncio.CancelledError):
        await ContinuousWatcher(Target(url="http://agent.example")).run_iteration(connector)


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["status", "network"])
async def test_webhook_delivery_diagnostic_and_logs_never_echo_secrets(monkeypatch, failure):
    import httpx

    from agentscan.sentinel.watcher import WebhookDispatcher

    secret = "synthetic-secret-hook-url-and-error"
    request = httpx.Request("POST", "http://hook.example")
    response = httpx.Response(401, request=request)
    client = Mock(
        post=AsyncMock(
            side_effect=httpx.ConnectError(secret) if failure == "network" else None,
            return_value=response,
        )
    )
    log = Mock()
    monkeypatch.setattr("agentscan.sentinel.watcher.logger.error", log)
    dispatcher = WebhookDispatcher()
    assert not await dispatcher.dispatch(
        f"http://hook.example/{secret}", "http://agent.example", [], 50, client=client
    )
    assert dispatcher.last_error and dispatcher.last_error["error_id"]
    assert secret not in json.dumps(dispatcher.last_error)
    assert secret not in repr(log.call_args)
    client.post.side_effect = None
    client.post.return_value = httpx.Response(204, request=request)
    assert await dispatcher.dispatch(
        "http://hook.example", "http://agent.example", [], 50, client=client
    )
    assert dispatcher.last_error is None


def test_one_shot_probe_401_is_an_error_not_pass(client, monkeypatch):
    from agentscan.core.outcomes import TargetRequestError

    monkeypatch.setattr(
        "agentscan.core.connectors.HttpJsonConnector.send_prompt",
        AsyncMock(side_effect=TargetRequestError("Target returned HTTP 401")),
    )
    response = client.post("/api/sentinel/probe", json={"target_url": "http://agent.example"})
    assert response.status_code == 502
    result = response.json()
    assert result["status"] == "ERROR"
    assert "HTTP 401" in result["error"]
    assert result["error_id"]
    assert "PASS" not in response.text
