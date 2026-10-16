"""Independent contracts for charts of observations, unavailable data and local rendering."""

from __future__ import annotations

import copy
import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def node():
    executable = shutil.which("node")
    if not executable:
        pytest.skip("Node is required for dashboard analytics contracts")
    return executable


def js(node, script, payload):
    result = subprocess.run(
        [node, "-e", script],
        input=json.dumps(payload),
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=20,
    )
    return json.loads(result.stdout)


SUMMARY_SCRIPT = r"""
const fs = require('node:fs');
const analytics = require('./agentscan/ui/static/scan-analytics.js');
const payload = JSON.parse(fs.readFileSync(0, 'utf8'));
const before = JSON.stringify(payload);
const summary = analytics.summarize(payload);
if (JSON.stringify(payload) !== before) throw new Error('Report was mutated');
console.log(JSON.stringify(summary));
"""


def summarize(node, report):
    return js(node, SUMMARY_SCRIPT, report)


def outcome(module_id="ATK-001", selected=24, evaluated=24, status="COMPLETE", scope="target"):
    return {
        "module_id": module_id,
        "module_name": "Synthetic module",
        "selected_tests": selected,
        "executed_tests": evaluated,
        "status": status,
        "assessment_scope": scope,
        "reason": "",
    }


def report(*, selected=24, evaluated=24, status="COMPLETE", scope="target", outcomes=None):
    return {
        "status": status,
        "assessment_scope": scope,
        "tests_selected": selected,
        "tests_run": evaluated,
        "module_outcomes": outcomes
        if outcomes is not None
        else [outcome(selected=selected, evaluated=evaluated, status=status, scope=scope)],
        "findings": [],
        "reference_observations": [],
        "started_at": "2026-10-10T09:00:00+00:00",
        "completed_at": "2026-10-10T09:00:02.500+00:00",
    }


def assert_coverage_unavailable(coverage):
    assert coverage["available"] is False
    assert coverage["selected"] is None
    assert coverage["evaluated"] is None
    assert coverage["remaining"] is None
    assert coverage["reason"]


def test_complete_scan_has_observed_counts_and_elapsed_time(node):
    summary = summarize(node, report())
    assert summary["available"] is True
    assert summary["status"] == "COMPLETE"
    assert summary["scope"] == "target"
    assert summary["coverage"] == {
        "available": True,
        "selected": 24,
        "evaluated": 24,
        "remaining": 0,
        "reason": "",
    }
    assert summary["modules"][0]["coverage"] == summary["coverage"]
    assert summary["statuses"]["available"] is True
    assert summary["statuses"]["counts"]["COMPLETE"] == 1
    assert summary["statuses"]["total"] == 1
    assert summary["severity"]["available"] is True
    assert summary["severity"]["total"] == 0
    assert summary["elapsed"]["available"] is True
    assert summary["elapsed"]["milliseconds"] == 2500
    assert summary["referenceCount"] == 0
    assert not ({"score", "successRate", "resistance", "securePercentage"} & summary.keys())


def test_partial_error_preserves_findings_and_unevaluated_checks(node):
    payload = report(selected=24, evaluated=3, status="ERROR")
    payload["module_outcomes"][0]["reason"] = "Request budget exhausted after three checks"
    payload["module_errors"] = [{"module_id": "ATK-001", "error": "Budget exhausted"}]
    payload["findings"] = [{"severity": "HIGH"}, {"severity": "HIGH"}, {"severity": "MEDIUM"}]
    summary = summarize(node, payload)
    assert summary["coverage"]["remaining"] == 21
    assert summary["statuses"]["counts"]["ERROR"] == 1
    assert summary["modules"][0]["reason"] == payload["module_outcomes"][0]["reason"]
    assert summary["severity"]["total"] == 3
    assert summary["severity"]["counts"]["HIGH"] == 2
    assert summary["severity"]["counts"]["MEDIUM"] == 1


def test_many_findings_do_not_become_many_attempts(node):
    payload = report(selected=1, evaluated=1)
    payload["findings"] = [{"severity": "HIGH"}] * 5
    summary = summarize(node, payload)
    assert summary["coverage"]["selected"] == 1
    assert summary["coverage"]["evaluated"] == 1
    assert summary["severity"]["total"] == 5
    assert summary["severity"]["counts"]["HIGH"] == 5


@pytest.mark.parametrize("status", ["ERROR", "INCONCLUSIVE", "SKIPPED"])
def test_all_unavailable_and_missing_criterion_are_not_resisted_checks(node, status):
    payload = report(evaluated=0, status=status)
    payload["module_outcomes"][0]["reason"] = "Private criterion is unavailable"
    summary = summarize(node, payload)
    assert summary["coverage"]["selected"] == 24
    assert summary["coverage"]["evaluated"] == 0
    assert summary["coverage"]["remaining"] == 24
    assert summary["statuses"]["counts"][status] == 1
    assert summary["modules"][0]["reason"] == "Private criterion is unavailable"


@pytest.mark.parametrize("value", [None, "24", "", True, False, -1, 1.5, 2**53])
@pytest.mark.parametrize("key", ["tests_selected", "tests_run"])
def test_report_counts_cannot_be_coerced_or_clamped(node, key, value):
    payload = report()
    payload[key] = value
    assert_coverage_unavailable(summarize(node, payload)["coverage"])


@pytest.mark.parametrize("value", [None, "24", "", True, False, -1, 1.5, 2**53])
@pytest.mark.parametrize("key", ["selected_tests", "executed_tests"])
def test_module_counts_cannot_be_coerced_or_clamped(node, key, value):
    payload = report()
    payload["module_outcomes"][0][key] = value
    summary = summarize(node, payload)
    assert_coverage_unavailable(summary["modules"][0]["coverage"])


@pytest.mark.parametrize("location", ["report", "module"])
def test_evaluated_greater_than_selected_is_unavailable(node, location):
    payload = report()
    if location == "report":
        payload["tests_run"] = 25
    else:
        payload["module_outcomes"][0]["executed_tests"] = 25
    summary = summarize(node, payload)
    selected = summary["coverage"] if location == "report" else summary["modules"][0]["coverage"]
    assert_coverage_unavailable(selected)


def test_report_and_module_totals_must_agree(node):
    payload = report()
    payload["tests_selected"] = 2
    payload["tests_run"] = 2
    assert_coverage_unavailable(summarize(node, payload)["coverage"])


def test_known_zero_is_different_from_missing_counts(node):
    zero = summarize(node, report(selected=0, evaluated=0, status="SKIPPED"))
    assert zero["coverage"]["available"] is True
    assert zero["coverage"]["selected"] == 0
    assert zero["coverage"]["evaluated"] == 0
    legacy = {"findings": [], "tests_run": 24}
    summary = summarize(node, legacy)
    assert_coverage_unavailable(summary["coverage"])
    assert summary["statuses"]["available"] is False
    assert summary["statuses"]["total"] is None
    assert summary["elapsed"]["available"] is False
    assert summary["referenceCount"] is None


@pytest.mark.parametrize("payload", [None, [], "report", 0, {}, {"error": "Unavailable"}])
def test_absent_or_invalid_report_does_not_fabricate_a_zero_scan(node, payload):
    summary = summarize(node, payload)
    assert summary["available"] is False
    assert_coverage_unavailable(summary["coverage"])
    assert summary["severity"]["available"] is False
    assert summary["severity"]["total"] is None
    assert summary["statuses"]["available"] is False
    assert summary["statuses"]["total"] is None


def test_all_module_statuses_have_separate_counts(node):
    statuses = ["COMPLETE", "INCONCLUSIVE", "ERROR", "SKIPPED", "RUNNING", "mystery"]
    outcomes = [outcome(f"ATK-{i:03}", 1, 0, status) for i, status in enumerate(statuses)]
    summary = summarize(node, report(selected=6, evaluated=0, outcomes=outcomes))
    assert summary["statuses"]["available"] is True
    assert summary["statuses"]["total"] == 6
    assert summary["statuses"]["counts"] == {
        "COMPLETE": 1,
        "INCONCLUSIVE": 1,
        "ERROR": 1,
        "SKIPPED": 1,
        "RUNNING": 1,
        "UNAVAILABLE": 1,
    }
    assert summary["modules"][-1]["status"] == "UNAVAILABLE"


@pytest.mark.parametrize("value", [None, {}, "ERROR"])
def test_malformed_module_collection_cannot_invent_status_counts(node, value):
    payload = report()
    payload["module_outcomes"] = value
    summary = summarize(node, payload)
    assert summary["statuses"]["available"] is False
    assert summary["statuses"]["total"] is None


def test_null_module_row_stays_unknown_and_does_not_crash(node):
    payload = report(outcomes=[None])
    summary = summarize(node, payload)
    assert summary["statuses"]["counts"]["UNAVAILABLE"] == 1
    assert_coverage_unavailable(summary["modules"][0]["coverage"])


def test_unknown_findings_and_pass_are_not_silently_dropped(node):
    payload = report()
    payload["findings"] = [
        {"severity": severity} for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "PASS"]
    ] + [{"severity": "unexpected"}, None, {}]
    summary = summarize(node, payload)
    assert summary["severity"]["total"] == 9
    assert summary["severity"]["counts"] == {
        "CRITICAL": 1,
        "HIGH": 1,
        "MEDIUM": 1,
        "LOW": 1,
        "INFO": 1,
        "PASS": 1,
        "UNCLASSIFIED": 3,
    }


@pytest.mark.parametrize("value", [None, {}, "HIGH"])
def test_missing_or_invalid_findings_is_unavailable_not_empty(node, value):
    payload = report()
    payload["findings"] = value
    summary = summarize(node, payload)
    assert summary["severity"]["available"] is False
    assert summary["severity"]["total"] is None


@pytest.mark.parametrize("scope", ["local_reference_model", "mixed"])
def test_reference_observations_never_enter_target_severity_counts(node, scope):
    outcomes = [outcome(scope="local_reference_model")]
    selected = evaluated = 24
    if scope == "mixed":
        outcomes.append(outcome("ATK-002", 2, 1, "INCONCLUSIVE", "direct_text_known_reference"))
        selected, evaluated = 26, 25
    payload = report(selected=selected, evaluated=evaluated, scope=scope, outcomes=outcomes)
    payload["reference_observations"] = [{"severity": "CRITICAL"}] * 4
    payload["findings"] = [{"severity": "LOW"}] if scope == "mixed" else []
    summary = summarize(node, payload)
    assert summary["scope"] == scope
    assert summary["referenceCount"] == 4
    assert summary["severity"]["counts"]["CRITICAL"] == 0
    assert summary["severity"]["total"] == (1 if scope == "mixed" else 0)
    assert summary["modules"][0]["scope"] == "local_reference_model"
    if scope == "mixed":
        assert summary["modules"][1]["scope"] == "direct_text_known_reference"


@pytest.mark.parametrize("scope", [None, "", "mixed"])
def test_missing_module_scope_never_infers_target_from_mixed_or_unknown_report(node, scope):
    payload = report(scope=scope)
    del payload["module_outcomes"][0]["assessment_scope"]
    summary = summarize(node, payload)
    assert summary["modules"][0]["scope"].lower() in {"unavailable", "unknown"}


@pytest.mark.parametrize(
    "key,value",
    [
        ("started_at", None),
        ("completed_at", None),
        ("started_at", "not a date"),
        ("completed_at", "not a date"),
        ("started_at", 0),
        ("completed_at", "2026-10-10T08:59:59Z"),
        ("completed_at", "2026-02-30T09:00:02Z"),
        ("completed_at", "2026-10-10T09:00:02"),
    ],
)
def test_missing_invalid_or_reversed_timestamps_have_no_duration(node, key, value):
    payload = report()
    payload[key] = value
    summary = summarize(node, payload)
    assert summary["elapsed"]["available"] is False
    assert summary["elapsed"]["milliseconds"] is None
    assert summary["elapsed"]["reason"]


def test_equivalent_timezones_and_explicit_zero_duration_are_supported(node):
    payload = report()
    payload["completed_at"] = "2026-10-10T14:30:00+05:30"
    summary = summarize(node, payload)
    assert summary["elapsed"]["available"] is True
    assert summary["elapsed"]["milliseconds"] == 0


def test_summary_discards_sensitive_nonmetric_fields(node):
    payload = report()
    private = "SYNTHETIC_PRIVATE_DO_NOT_RENDER_001"
    payload.update(
        canary_token=private,
        target_url=f"https://owned.invalid/{private}",
        trajectory=[{"payload": private, "response": private}],
        reference_observations=[{"severity": "HIGH", "evidence": private}],
        findings=[{"severity": "HIGH", "description": private, "evidence": private}],
        score=100,
    )
    summary = summarize(node, payload)
    assert private not in json.dumps(summary)
    assert summary["referenceCount"] == 1
    assert summary["severity"]["counts"]["HIGH"] == 1


RENDER_SCRIPT = r"""
const fs = require('node:fs');
const payload = JSON.parse(fs.readFileSync(0, 'utf8'));
const before = JSON.stringify(payload);
let networkCalls = 0;
const network = () => { networkCalls += 1; throw new Error('Analytics attempted network IO'); };
global.fetch = network;
global.XMLHttpRequest = network;
global.WebSocket = network;
Object.defineProperty(global, 'navigator', {configurable: true, value: {sendBeacon: network}});
class Element {
  constructor(tag, document) {
    this.tagName = tag.toUpperCase(); this.ownerDocument = document;
    this.children = []; this.attrs = {}; this.dataset = {}; this.style = {};
    this.events = {}; this._text = ''; this.className = ''; this.hidden = false;
  }
  get textContent() { return this._text + this.children.map(x => x.textContent).join(''); }
  set textContent(value) { this._text = String(value ?? ''); this.children = []; }
  get type() { return this.attrs.type ?? ''; }
  set type(value) { this.setAttribute('type',value); }
  get disabled() { return 'disabled' in this.attrs; }
  set disabled(value) { if (value) this.setAttribute('disabled',''); else this.removeAttribute('disabled'); }
  get innerHTML() { throw new Error('Analytics test requires DOM construction'); }
  set innerHTML(value) { throw new Error('Untrusted data must not use innerHTML'); }
  append(...nodes) { for (const node of nodes) this.appendChild(node); }
  appendChild(node) { if (typeof node === 'string') { const value = new Element('#text', this.ownerDocument); value.textContent = node; node = value; } node.parentElement = this; this.children.push(node); return node; }
  replaceChildren(...nodes) { this._text = ''; this.children = []; this.append(...nodes); }
  setAttribute(key,value) { this.attrs[key] = String(value); }
  getAttribute(key) { return this.attrs[key] ?? null; }
  removeAttribute(key) { delete this.attrs[key]; }
  addEventListener(key,handler) { (this.events[key] ||= []).push(handler); }
  querySelectorAll(selector) {
    const all = []; const visit = node => { for (const child of node.children) { if (selector === '[data-analytics-severity]' ? child.dataset.analyticsSeverity || child.attrs['data-analytics-severity'] : child.tagName.toLowerCase() === selector) all.push(child); visit(child); } }; visit(this); return all;
  }
}
const document = {createElement: tag => new Element(tag, document), createTextNode: text => { const node = new Element('#text', document); node.textContent = text; return node; }};
global.document = document;
const container = document.createElement('div');
const analytics = require('./agentscan/ui/static/scan-analytics.js');
const callbacks = [];
analytics.render(payload, container, {onSeverity: severity => callbacks.push(severity)});
if (JSON.stringify(payload) !== before) throw new Error('Rendering mutated the report');
const originalText = container.textContent;
const originalTree = serialize(container);
const buttons = container.querySelectorAll('[data-analytics-severity]');
for (const button of buttons) for (const callback of button.events.click || []) callback({currentTarget:button});
if (payload) analytics.render(null, container, {onSeverity: severity => callbacks.push(severity)});
function serialize(node) { return {tag:node.tagName, text:node.textContent, attrs:node.attrs, dataset:node.dataset, className:node.className, children:node.children.map(serialize)}; }
console.log(JSON.stringify({text: originalText, tree: originalTree, callbacks, networkCalls, afterClear:container.textContent}));
"""


def descendants(tree):
    yield tree
    for child in tree["children"]:
        yield from descendants(child)


def test_render_has_accessible_table_and_native_severity_filters(node):
    payload = report()
    payload["findings"] = [{"severity": "HIGH"}, {"severity": "MEDIUM"}]
    rendered = js(node, RENDER_SCRIPT, payload)
    elements = list(descendants(rendered["tree"]))
    tables = [element for element in elements if element["tag"] == "TABLE"]
    assert tables
    assert any(element["tag"] == "CAPTION" and element["text"] for element in elements)
    assert any(element["tag"] == "TH" and element["attrs"].get("scope") for element in elements)
    assert any("24" in table["text"] and "ATK-001" in table["text"] for table in tables)
    buttons = [element for element in elements if element["tag"] == "BUTTON"]
    assert len(buttons) >= 6
    assert all(button["attrs"].get("type") == "button" for button in buttons)
    # Empty severity categories may stay visible and disabled; occupied categories filter.
    assert set(rendered["callbacks"]) == {"HIGH", "MEDIUM"}
    assert rendered["networkCalls"] == 0
    assert "ATK-001" not in rendered["afterClear"]


def test_render_keeps_literal_hostile_labels_and_never_uses_html(node):
    payload = report(status="ERROR", evaluated=1)
    marker = '<img src=x onerror="global.stolen=true">'
    payload["module_outcomes"][0].update(module_name=marker, reason=marker, assessment_scope=marker)
    payload["findings"] = [{"severity": "HIGH", "description": "SYNTHETIC_PRIVATE_TEXT_001"}]
    rendered = js(node, RENDER_SCRIPT, payload)
    assert marker in rendered["text"]
    assert "SYNTHETIC_PRIVATE_TEXT_001" not in rendered["text"]
    assert not any(element["tag"] in {"IMG", "SCRIPT"} for element in descendants(rendered["tree"]))
    assert rendered["networkCalls"] == 0


def test_output_inventory_displays_count_scope_and_unknown_impact(node):
    inventory = outcome(
        module_id="ATK-007",
        selected=12,
        evaluated=0,
        status="INCONCLUSIVE",
        scope="output_text_indicator_inventory",
    )
    inventory["reason"] = "12 output observations recorded. Downstream impact is unassessed."
    payload = report(selected=12, evaluated=0, status="INCONCLUSIVE", outcomes=[inventory])
    rendered = js(node, RENDER_SCRIPT, payload)
    assert "Output text · impact unassessed" in rendered["text"]
    assert inventory["reason"] in rendered["text"]
    assert "INCONCLUSIVE" in rendered["text"]
    assert rendered["networkCalls"] == 0


@pytest.mark.parametrize("scope", ["constructor", "toString", "__proto__"])
def test_unknown_scope_labels_cannot_resolve_object_prototype_properties(node, scope):
    payload = report(scope=scope)
    rendered = js(node, RENDER_SCRIPT, payload)
    scope_labels = [
        element["text"]
        for element in descendants(rendered["tree"])
        if element["className"] == "analytics-scope"
    ]
    assert scope_labels == [scope.replace("_", " ")]


@pytest.mark.parametrize(
    "scenario", ["legacy", "malformed", "missing-reference", "error-with-findings"]
)
def test_render_unknown_and_error_paths_keep_explanations_and_do_not_crash(node, scenario):
    payload = report()
    if scenario == "legacy":
        payload = {"tests_run": 24, "findings": []}
    elif scenario == "malformed":
        payload["module_outcomes"] = [None, {"selected_tests": "bad", "executed_tests": 10}]
        payload["findings"] = None
    elif scenario == "missing-reference":
        payload = report(evaluated=0, status="INCONCLUSIVE")
        payload["module_outcomes"][0]["reason"] = "Private criterion is unavailable"
    else:
        payload = report(evaluated=1, status="ERROR")
        payload["module_outcomes"][0]["reason"] = "Target returned HTTP 401"
        payload["findings"] = [{"severity": "HIGH"}]
    rendered = js(node, RENDER_SCRIPT, payload)
    assert rendered["networkCalls"] == 0
    assert rendered["text"]
    if scenario == "missing-reference":
        assert "Private criterion is unavailable" in rendered["text"]
    elif scenario == "error-with-findings":
        assert "Target returned HTTP 401" in rendered["text"]
        assert "HIGH" in rendered["text"]
    else:
        assert "unavailable" in rendered["text"].lower()


def test_report_is_unchanged_after_summary_and_render(node):
    payload = report()
    original = copy.deepcopy(payload)
    summarize(node, payload)
    js(node, RENDER_SCRIPT, payload)
    assert payload == original
