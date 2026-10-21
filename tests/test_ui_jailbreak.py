"""ATK-002 presents its bounded confidentiality scope and missing evidence honestly."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCOPE = "persona_complete_known_reference"
PRIVATE = "SYNTHETIC_PRIVATE_UI_REFERENCE_002"


def node_run(script: str, payload: dict | None = None) -> dict:
    executable = shutil.which("node")
    if not executable:
        pytest.skip("Node is required for dashboard contracts")
    result = subprocess.run(
        [executable, "-e", script],
        input=json.dumps(payload),
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=20,
    )
    return json.loads(result.stdout)


RENDER = r"""
const fs=require('node:fs'),report=JSON.parse(fs.readFileSync(0,'utf8'));
class Element {
 constructor(tag){this.tag=tag;this.children=[];this.attrs={};this.dataset={};this.style={};this._text='';}
 append(...nodes){this.children.push(...nodes);} replaceChildren(...nodes){this.children=nodes;}
 setAttribute(key,value){this.attrs[key]=value;} addEventListener(){}
 get textContent(){return this._text+this.children.map(node=>node.textContent).join('');}
 set textContent(value){this._text=String(value);this.children=[];}
 set innerHTML(value){throw Error('Unexpected HTML insertion');}
}
global.document={createElement:tag=>new Element(tag)};
const denied=()=>{throw Error('Unexpected persistence or network');};
global.localStorage={getItem:denied,setItem:denied};global.sessionStorage=global.localStorage;
global.fetch=denied;global.XMLHttpRequest=denied;
const analytics=require('./agentscan/ui/static/scan-analytics.js');
const dashboard=require('./agentscan/ui/static/dashboard.js');
const container=new Element('div'),before=JSON.stringify(report);
const summary=analytics.render(report,container),state=dashboard.summarize(report);
if(JSON.stringify(report)!==before)throw Error('Report mutated');
console.log(JSON.stringify({text:container.textContent,summary,state}));
"""


@pytest.mark.parametrize("mixed", [False, True])
def test_persona_scope_renders_limits_and_preserves_missing_evidence(mixed):
    payload = {
        "status": "INCONCLUSIVE",
        "assessment_scope": "mixed" if mixed else SCOPE,
        "score": 100,
        "tests_selected": 18,
        "tests_run": 0,
        "canary_token": PRIVATE,
        "findings": [],
        "module_outcomes": [
            {
                "module_id": "ATK-002",
                "module_name": "Jailbreak and persona adoption",
                "assessment_scope": SCOPE,
                "status": "INCONCLUSIVE",
                "selected_tests": 18,
                "executed_tests": 0,
                "reason": "A private reference is required before probes can run.",
            }
        ],
    }
    result = node_run(RENDER, payload)
    assert "Persona checks · complete known-reference disclosure" in result["text"]
    assert "plain-text or whitespace-normalized" in result["text"]
    assert "Persona adoption and tool proposals do not prove disclosure" in result["text"]
    assert "Encoded and partial disclosures are outside this criterion" in result["text"]
    assert "18 checks unevaluated" in result["text"]
    assert "A private reference is required before probes can run" in result["text"]
    assert result["summary"]["statuses"]["counts"]["INCONCLUSIVE"] == 1
    assert result["state"]["score"] is None
    assert PRIVATE not in json.dumps(result)


def test_supported_persona_findings_keep_existing_score_and_severity_display():
    result = node_run(
        RENDER,
        {
            "status": "COMPLETE",
            "assessment_scope": SCOPE,
            "tests_selected": 18,
            "tests_run": 18,
            "score": 40,
            "findings": [{"severity": "HIGH", "evidence": PRIVATE}],
            "module_outcomes": [
                {
                    "module_id": "ATK-002",
                    "assessment_scope": SCOPE,
                    "status": "COMPLETE",
                    "selected_tests": 18,
                    "executed_tests": 18,
                }
            ],
        },
    )
    assert result["state"]["score"] == 40
    assert result["summary"]["severity"]["counts"]["HIGH"] == 1
    assert PRIVATE not in json.dumps(result)


def test_canary_help_and_validation_keep_the_private_value_out_of_persistence():
    html = (ROOT / "agentscan/ui/static/index.html").read_text(encoding="utf-8")
    field = re.search(r'<input type="password" id="scan-canary-token"[^>]*>', html).group()
    helper = re.search(r'<p id="scan-canary-help"[^>]*>(.*?)</p>', html).group(1)
    assert 'autocomplete="off"' in field
    assert "value=" not in field
    assert "ATK-001 and ATK-002 assess complete known-reference disclosure" in helper
    assert "entering it here does not install it" in helper
    assert "Other modules have their own criteria" in helper
    assert "is not saved in browser storage" in helper
    result = node_run(
        r"""
const fs=require('node:fs'),payload=JSON.parse(fs.readFileSync(0,'utf8')),elements={};
const denied=()=>{throw Error('Unexpected persistence or network');};
global.localStorage={getItem:denied,setItem:denied};global.sessionStorage=global.localStorage;
global.fetch=denied;global.document={getElementById:id=>elements[id]||null};
const forms=require('./agentscan/ui/static/form-validation.js');
for(const spec of forms.inventory().filter(item=>item.workflow==='scan'))
elements[spec.id]={value:spec.type==='choice'?spec.choices[0]:spec.type==='integer'?'1':'',checked:false};
elements['scan-target-url'].value='http://owned.invalid/chat';
elements['scan-canary-token'].value=payload.reference;
const validated=forms.validate('scan',{render:false});
if(!validated.valid||validated.values.canary_token!==payload.reference)throw Error('Private reference lost');
elements['scan-canary-token'].value='';
if(forms.getValues('scan').canary_token!==null)throw Error('Private reference retained after clearing');
console.log(JSON.stringify({valid:validated.valid}));
""",
        {"reference": PRIVATE},
    )
    assert result == {"valid": True}
