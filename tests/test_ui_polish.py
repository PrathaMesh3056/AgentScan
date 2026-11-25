"""Regression coverage for issue #46 dashboard polish."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def node() -> str:
    executable = shutil.which("node")
    if not executable:
        pytest.skip("Node is required for dashboard polish contracts")
    return executable


def run_node(node: str, script: str) -> dict[str, str]:
    result = subprocess.run(
        [node, "-e", script],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=30,
    )
    return json.loads(result.stdout)


GATEWAY_SCRIPT = r"""
const fs = require('fs');
const vm = require('vm');
let source = fs.readFileSync('agentscan/ui/static/dashboard-app-core.js', 'utf8');
source += "\n;globalThis.__qa = { setGateway(value) { globalTelemetry.gateway = value; }, renderGateway };";
const container = { innerHTML: '' };
const context = {
  window: { addEventListener() {} },
  document: {
    getElementById(id) { return id === 'gateway-status-container' ? container : null; },
    addEventListener() {},
  },
  DashboardSemantics: { escape(value) { return String(value); } },
  console,
};
vm.createContext(context);
vm.runInContext(source, context, { filename: 'dashboard-app-core.js' });
const base = {
  configured: true,
  url: 'http://127.0.0.1:8765',
  checked_at: '2026-01-01T00:00:00Z',
  health: { status: 'ok', http_status: 200, latency_ms: 1.2 },
};
context.__qa.setGateway({
  ...base,
  status: 'ready',
  readiness: { status: 'ready', http_status: 200, latency_ms: 1.3, reason: 'unknown_reason' },
});
context.__qa.renderGateway();
const ready = container.innerHTML;
context.__qa.setGateway({
  ...base,
  status: 'not_ready',
  readiness: { status: 'not_ready', http_status: 503, latency_ms: 1.3, reason: null },
});
context.__qa.renderGateway();
const notReady = container.innerHTML;
console.log(JSON.stringify({ ready, notReady }));
"""


def test_ready_gateway_status_omits_unknown_reason(node: str) -> None:
    html = run_node(node, GATEWAY_SCRIPT)

    assert "unknown_reason" not in html["ready"]
    assert "Reason:" not in html["ready"]
    assert "unknown_reason" in html["notReady"]


MCP_SCRIPT = r"""
const fs = require('fs');
const vm = require('vm');

function makeSelect(values) {
  const select = {
    _options: values.map(value => ({ value })),
    _value: values[0] || '',
    get options() { return this._options; },
    get value() { return this._value; },
    set value(next) {
      this._value = this._options.some(option => option.value === next) ? next : '';
    },
    get innerHTML() { return ''; },
    set innerHTML(html) {
      const parsed = [];
      const pattern = /<option value="([^"]*)"/g;
      let match;
      while ((match = pattern.exec(html)) !== null) parsed.push({ value: match[1] });
      this._options = parsed;
      this.value = parsed[0] ? parsed[0].value : '';
    },
  };
  return select;
}

const elements = {
  'modal-mcp': { classList: { add() {}, remove() {} } },
  'mcp-tool-select': makeSelect([
    'agentscan_list_attacks',
    'agentscan_scan',
    'agentscan_audit',
    'agentscan_swarm',
  ]),
  'mcp-tool-args': { value: '{}' },
};
const context = {
  window: { addEventListener() {} },
  document: {
    getElementById(id) { return elements[id] || null; },
    addEventListener() {},
    querySelectorAll() { return []; },
  },
  globalTelemetry: {
    mcp: {
      tools: [
        { name: 'agentscan_list_attacks', description: 'List available modules' },
        { name: 'agentscan_scan', description: 'Execute a scan' },
      ],
    },
  },
  escapeHtml(value) { return String(value); },
  console,
};
vm.createContext(context);
vm.runInContext(
  fs.readFileSync('agentscan/ui/static/dashboard-app-actions.js', 'utf8'),
  context,
  { filename: 'dashboard-app-actions.js' },
);
context.openMcpTestModal('scan_target');
const aliasSelected = elements['mcp-tool-select'].value;
const aliasArgs = elements['mcp-tool-args'].value;
context.globalTelemetry = {
  mcp: { tools: [{ name: 'agentscan_list_attacks', description: 'List available modules' }] },
};
context.openMcpTestModal('scan_target');
const fallbackSelected = elements['mcp-tool-select'].value;
console.log(JSON.stringify({ aliasSelected, aliasArgs, fallbackSelected }));
"""


def test_mcp_modal_selects_a_real_tool(node: str) -> None:
    result = run_node(node, MCP_SCRIPT)

    assert result["aliasSelected"] == "agentscan_scan"
    assert "target_url" in result["aliasArgs"]
    assert result["fallbackSelected"] == "agentscan_list_attacks"
