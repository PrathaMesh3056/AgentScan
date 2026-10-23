"""Language coverage must retain unknowns and avoid unsupported safety rankings."""

from __future__ import annotations

import copy
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from agentscan.core.language_coverage import language_coverage
from agentscan.core.models import ScanMode, ScanReport
from agentscan.reporting.html_report import render_html_report

ROOT = Path(__file__).resolve().parents[1]
SCOPE = "multilingual_complete_known_reference"
PRIVATE = "SYNTHETIC_PRIVATE_UI_REFERENCE_011"


def outcome():
    return {
        "module_id": "ATK-011",
        "assessment_scope": SCOPE,
        "status": "INCONCLUSIVE",
        "selected_tests": 5,
        "executed_tests": 2,
        "language_outcomes": [
            {
                "language": "hi-Latn",
                "script": "Latn",
                "selected_tests": 5,
                "evaluated_tests": 2,
                "findings": 1,
                "inconclusive_tests": 1,
                "error_tests": 1,
                "not_run_tests": 1,
                "private_reference": PRIVATE,
            }
        ],
    }


def render(record):
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is required for dashboard contracts")
    script = r"""
const fs=require('node:fs'),report=JSON.parse(fs.readFileSync(0,'utf8'));
class Element {
 constructor(){this.children=[];this.style={};this._text='';}
 append(...items){this.children.push(...items);} replaceChildren(...items){this.children=items;}
 setAttribute(){} addEventListener(){}
 get textContent(){return this._text+this.children.map(item=>item.textContent).join('');}
 set textContent(value){this._text=String(value);this.children=[];}
 set innerHTML(value){throw Error('Unsafe HTML insertion');}
}
global.document={createElement:()=>new Element()};
const denied=()=>{throw Error('Unexpected persistence or network');};
global.localStorage={getItem:denied,setItem:denied};global.sessionStorage=global.localStorage;
global.fetch=denied;global.XMLHttpRequest=denied;
const analytics=require('./agentscan/ui/static/scan-analytics.js');
const dashboard=require('./agentscan/ui/static/dashboard.js');
const element=new Element(),before=JSON.stringify(report),summary=analytics.render(report,element);
if(JSON.stringify(report)!==before)throw Error('Report mutated');
console.log(JSON.stringify({text:element.textContent,summary,state:dashboard.summarize(report)}));
"""
    result = subprocess.run(
        [node, "-e", script],
        input=json.dumps(record),
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
        timeout=20,
    )
    return json.loads(result.stdout)


def report(record):
    value = ScanReport(target_url="http://owned.invalid/chat", scan_mode=ScanMode.SCAN)
    value.tests_selected = record["selected_tests"]
    value.tests_run = record["executed_tests"]
    value.module_outcomes = [record]
    value.complete(None, status="INCONCLUSIVE")
    return value


@pytest.mark.parametrize("mixed", [False, True])
def test_language_coverage_keeps_denominators_unknowns_and_private_values_separate(mixed):
    value = report(outcome())
    value.assessment_scope = "mixed" if mixed else SCOPE
    rendered = render(value.model_dump(mode="json"))
    assert "Multilingual checks · complete known-reference disclosure" in rendered["text"]
    assert "language safety rankings" in rendered["text"]
    assert "Language proficiency, general alignment" in rendered["text"]
    assert "hi-Latn / Latn" in rendered["text"]
    assert "2 / 5" in rendered["text"]
    assert "InconclusiveErrorsNot run" in rendered["text"]
    assert rendered["state"]["score"] is None
    rows = language_coverage(outcome())
    assert rendered["summary"]["modules"][0]["languageCoverage"] == rows
    assert rows[0]["not_run_tests"] == rows[0]["error_tests"] == rows[0]["inconclusive_tests"] == 1
    # DashboardSemantics retains raw input records for diagnostics; the new
    # rendered/analytics boundary must emit only public, validated counters.
    assert PRIVATE not in rendered["text"]
    assert PRIVATE not in json.dumps(rendered["summary"])
    html = render_html_report(value)
    assert "ATK-011 scope: complete known-reference disclosure" in html
    assert "no language safety ranking" in html
    assert "hi-Latn/Latn" in html
    assert PRIVATE not in html


@pytest.mark.parametrize(
    "mutation",
    [
        "missing",
        "boolean",
        "mismatched_total",
        "negative",
        "duplicate",
        "findings",
        "unknown_script",
        "unknown_language",
        "missing_count",
        "missing_module_total",
    ],
)
def test_malformed_language_counts_are_unavailable_in_all_presentations(mutation):
    record = outcome()
    row = record["language_outcomes"][0]
    if mutation == "missing":
        record.pop("language_outcomes")
    elif mutation == "boolean":
        row["error_tests"] = True
    elif mutation == "mismatched_total":
        record["executed_tests"] = 1
    elif mutation == "negative":
        row["inconclusive_tests"] = -1
    elif mutation == "duplicate":
        record["language_outcomes"].append(copy.deepcopy(row))
    elif mutation == "findings":
        row["findings"] = 3
    elif mutation == "unknown_script":
        row["script"] = "<script>alert(1)</script>"
    elif mutation == "unknown_language":
        row["language"] = PRIVATE
    elif mutation == "missing_count":
        row.pop("not_run_tests")
    else:
        record.pop("selected_tests")
    assert language_coverage(record) is None
    value = ScanReport(target_url="http://owned.invalid/chat", scan_mode=ScanMode.SCAN)
    value.module_outcomes = [record]
    rendered = render(value.model_dump(mode="json"))
    assert rendered["summary"]["modules"][0]["languageCoverage"] is None
    assert "Language coverage unavailable" in rendered["text"]
    assert PRIVATE not in rendered["text"]
    assert PRIVATE not in json.dumps(rendered["summary"])
    html = render_html_report(value)
    assert "ATK-011 language coverage unavailable" in html
    assert PRIVATE not in html
    assert "<script>alert(1)</script>" not in html


def test_canary_help_explains_preinstalled_reference_and_marker_limit():
    html = (ROOT / "agentscan/ui/static/index.html").read_text(encoding="utf-8")
    helper = re.search(r'<p id="scan-canary-help"[^>]*>(.*?)</p>', html).group(1)
    assert "ATK-011 uses the same private-reference requirement for multilingual prompts" in helper
    assert "language keywords or marker echoes are not evidence of disclosure" in helper
    assert "entering it here does not install it" in helper
    assert "is not saved in browser storage" in helper
