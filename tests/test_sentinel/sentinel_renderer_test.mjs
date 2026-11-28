// tests/test_sentinel/sentinel_renderer_test.mjs
//
// QA-170: the Sentinel renderer must derive every claim from backend evidence.
// Run with: node tests/test_sentinel/sentinel_renderer_test.mjs

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import vm from 'node:vm';

const require = createRequire(import.meta.url);
const DashboardSemantics = require('../../agentscan/ui/static/dashboard.js');
const rendererSource = readFileSync(
  new URL('../../agentscan/ui/static/dashboard-app-renderers.js', import.meta.url),
  'utf8',
);

function element(id) {
  return {
    id,
    innerHTML: '',
    textContent: '',
    hidden: false,
    classList: { toggle() {} },
    querySelectorAll() { return []; },
  };
}

function renderSentinel(sentinel) {
  const elements = new Map();
  const container = element('sentinel-container');
  elements.set('sentinel-container', container);
  const sandbox = {
    document: {
      getElementById(id) {
        if (!elements.has(id)) elements.set(id, element(id));
        return elements.get(id);
      },
      querySelectorAll() { return []; },
    },
    DashboardSemantics,
    escapeHtml: DashboardSemantics.escape,
    globalTelemetry: { sentinel },
    console,
  };
  sandbox.window = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(rendererSource, sandbox, { filename: 'dashboard-app-renderers.js' });
  sandbox.renderSentinel();
  return {
    html: container.innerHTML,
    inlineStatus: elements.get('sentinel-status-inline').textContent,
  };
}

const base = {
  running: false,
  status: 'STOPPED',
  error: null,
  error_id: null,
  webhook_error: null,
  target: 'http://127.0.0.1:9000/chat',
  interval: 30,
  canary_token: 'CANARY-TEST-1234-ABCD',
  webhook_url: null,
  probes_run: 0,
  probes_failed: 0,
  leaks_detected: 0,
  last_probe_at: null,
  last_probe_status: null,
  last_probe_error: null,
  last_probe_error_id: null,
  alerts: [],
};

// 1. One recorded ALERT with a stopped watcher: show the alert, not a clean claim.
{
  const alert = {
    timestamp: '2026-11-16T12:00:00+00:00',
    cycle: 2,
    status: 'ALERT',
    findings_count: 1,
    target: 'http://127.0.0.1:9000/chat',
  };
  const rendered = renderSentinel({
    ...base,
    probes_run: 2,
    // Deliberately stale/absent aggregate: the renderer must trust recorded alerts.
    leaks_detected: 0,
    last_probe_at: alert.timestamp,
    last_probe_status: 'ALERT',
    alerts: [alert],
  });
  assert.match(rendered.html, /ALERT/);
  assert.match(rendered.html, /1 Detected/);
  assert.match(rendered.html, /2026-11-16T12:00:00\+00:00/);
  assert.match(rendered.html, /2 Probes/);
  assert.match(rendered.inlineStatus, /STOPPED/);
  assert.doesNotMatch(rendered.html, /NO RECORDED FINDING/);
  assert.doesNotMatch(rendered.html, /LIVE FEED/);
  assert.doesNotMatch(rendered.html, /ACTIVE/);
}

// 2. Failed probe: show an explicit error/inconclusive state, never a clean count.
{
  const rendered = renderSentinel({
    ...base,
    probes_run: 1,
    probes_failed: 1,
    last_probe_at: '2026-11-16T12:05:00+00:00',
    last_probe_status: 'ERROR',
    last_probe_error: 'Sentinel target returned HTTP 401. Check endpoint and target authentication.',
    last_probe_error_id: 'probe-error-reference',
  });
  assert.match(rendered.html, /PROBE ERROR/);
  assert.match(rendered.html, /INCONCLUSIVE/);
  assert.match(rendered.html, /1 failed/);
  assert.match(rendered.html, /Sentinel target returned HTTP 401/);
  assert.match(rendered.html, /probe-error-reference/);
  assert.doesNotMatch(rendered.html, /0 Probes/);
  assert.doesNotMatch(rendered.html, /CANARY PROBES ACTIVE/);
  assert.doesNotMatch(rendered.html, /ACTIVE/);
  assert.doesNotMatch(rendered.html, /NO RECORDED FINDING/);
  assert.doesNotMatch(rendered.html, /LIVE FEED/);
}

// 3. Clean stopped state: neutral evidence-backed empty state, no static claims.
{
  const rendered = renderSentinel({ ...base });
  assert.match(rendered.html, /NOT EVALUATED/);
  assert.match(rendered.html, /No probes recorded/);
  assert.match(rendered.html, /Alerts recorded: <strong>0<\/strong>/);
  assert.doesNotMatch(rendered.html, /ACTIVE/);
  assert.doesNotMatch(rendered.html, /LIVE FEED/);
  assert.doesNotMatch(rendered.html, /NO RECORDED FINDING/);
}

// 4. Missing Sentinel payload: say unavailable rather than inventing a state.
{
  const rendered = renderSentinel(null);
  assert.match(rendered.html, /UNAVAILABLE/);
  assert.match(rendered.html, /No Sentinel status available/);
  assert.doesNotMatch(rendered.html, /ACTIVE/);
  assert.doesNotMatch(rendered.html, /LIVE FEED/);
}

console.log('sentinel renderer evidence checks passed');
