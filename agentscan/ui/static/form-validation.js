/* Field validation is shared by every dashboard submission. No input values are logged. */
(function (root) {
  'use strict';
  const remote = ['http:', 'https:'];
  const scanRemote = [...remote, 'ws:', 'wss:', 'mcp+sse:', 'mcp+sses:'];
  const descriptor = (id, field, type, extra = {}) => ({ id, field, type, ...extra });
  const analysis = prefix => [
    descriptor(`${prefix}-analysis-mode`, 'analysis_mode', 'choice', { choices: ['deterministic', 'local', 'external'] }),
    descriptor(`${prefix}-local-model`, 'local_model', 'localModel', { when: 'local' }),
    descriptor(`${prefix}-external-provider`, 'external_provider', 'choice', { choices: ['openai', 'anthropic', 'gemini'], when: 'external' }),
    descriptor(`${prefix}-external-model`, 'external_model', 'externalModel', { when: 'external' }),
    descriptor(`${prefix}-external-consent`, 'data_classification', 'consent', { when: 'external' })
  ];
  const definitions = {
    scan: [descriptor('scan-target-url', 'target_url', 'url', { protocols: scanRemote }), descriptor('scan-mode', 'mode', 'choice', { choices: ['FAST', 'ACTIVE', 'DEEP'] }), descriptor('scan-concurrency', 'concurrency', 'integer', { min: 1, max: 10 }), descriptor('scan-canary-token', 'canary_token', 'canary', { optional: true }), descriptor('scan-indirect-adapter', 'indirect_adapter', 'choice', { choices: ['none', 'document_v1'] }), descriptor('scan-mcp-inventory-baseline', 'mcp_inventory_baseline', 'mcpBaseline', { optional: true }), descriptor('scan-factuality-baseline', 'factuality_baseline', 'factualityBaseline', { optional: true }), ...analysis('scan')],
    discovery: [descriptor('discovery-target', 'url', 'url', { protocols: remote }), descriptor('discovery-mode', 'mode', 'choice', { choices: ['auto', 'http', 'browser'] }), descriptor('discovery-auto-probe', 'allow_probe', 'boolean')],
    audit: [descriptor('audit-codebase-path', 'path', 'path'), descriptor('audit-ruleset', 'ruleset', 'choice', { choices: ['default'] }),
      descriptor('audit-offline', 'offline', 'boolean'), descriptor('audit-show-transitive', 'show_transitive', 'boolean'),
      ...['deps', 'config', 'secrets', 'typo', 'mcp', 'identity', 'frameworks', 'semgrep'].map(name => descriptor(`audit-check-${name}`, `scan_${name}`, 'boolean'))],
    calibration: [descriptor('calibrate-local-model', 'model', 'localModel')],
    sentinelProbe: [descriptor('sentinel-target-url', 'target_url', 'url', { protocols: remote })],
    sentinel: [descriptor('sentinel-target-url', 'target_url', 'url', { protocols: remote }), descriptor('sentinel-interval-seconds', 'interval_seconds', 'integer', { min: 5, max: 3600 }), descriptor('sentinel-webhook-url', 'webhook_url', 'url', { protocols: remote, optional: true })],
    mcp: [descriptor('mcp-tool-select', 'tool', 'tool'), descriptor('mcp-tool-args', 'arguments', 'jsonObject')],
    swarm: [descriptor('swarm-strategy-select', 'team', 'choice', { choices: ['COLLABORATIVE', 'ADAPTIVE', 'AGENCY', 'STEALTH', 'TRIO', 'trio', 'agency', 'stealth'] }), descriptor('swarm-max-rounds', 'max_rounds', 'integer', { min: 1, max: 10 }), descriptor('swarm-target-url', 'target_url', 'url', { protocols: remote }), ...analysis('swarm')],
    healApply: [descriptor('heal-apply-backup-check', 'backup', 'boolean')],
    healSimulation: [descriptor('heal-sim-file', 'file', 'path'), descriptor('heal-sim-type', 'vulnerability_type', 'choice', { choices: ['PROMPT_INJECTION', 'SSRF_TOOL_LEAK', 'SQL_INJECTION', 'PRIVILEGE_ESCALATION'] }), descriptor('heal-sim-evidence', 'evidence', 'text', { max: 65536 })],
    event: [descriptor('event-inject-type', 'type', 'choice', { choices: ['finding', 'probe', 'traffic', 'sentinel_alert', 'reload'] }), descriptor('event-inject-payload', 'data', 'jsonObject')],
    certificate: [descriptor('cert-secret-key', 'secret_key', 'signingKey', { optional: true })],
    search: [descriptor('top-search-input', 'global_search', 'text', { optional: true }), descriptor('findings-search', 'findings_search', 'text', { optional: true }), descriptor('dep-search-input', 'dependency_search', 'text', { optional: true })]
  };
  const text = value => typeof value === 'string' ? value.trim() : '';
  const bytes = value => typeof TextEncoder !== 'undefined' ? new TextEncoder().encode(value).length : value.length;

  function uniqueJSON(value) {
    const parsed = JSON.parse(value);
    let position = 0;
    const space = () => { while (/\s/.test(value[position] || '') && position < value.length) position++; };
    const string = () => {
      const start = position++;
      while (position < value.length) {
        if (value[position] === '\\') { position += 2; continue; }
        if (value[position++] === '"') return JSON.parse(value.slice(start, position));
      }
      throw new Error('Invalid JSON');
    };
    const visit = depth => {
      if (depth > 32) throw new Error('JSON nesting limit');
      space();
      if (value[position] === '{') {
        position++; space();
        const keys = new Set();
        if (value[position] === '}') { position++; return; }
        do {
          space(); const key = string();
          if (keys.has(key)) throw new Error('Duplicate JSON key');
          keys.add(key); space(); position++; visit(depth + 1); space();
          if (value[position] === '}') { position++; return; }
          position++;
        } while (position < value.length);
      } else if (value[position] === '[') {
        position++; space();
        if (value[position] === ']') { position++; return; }
        do {
          visit(depth + 1); space();
          if (value[position] === ']') { position++; return; }
          position++;
        } while (position < value.length);
      } else if (value[position] === '"') string();
      else while (position < value.length && !/[\s,}\]]/.test(value[position])) position++;
    };
    visit(0);
    return parsed;
  }

  function endpoint(value, protocols) {
    const raw = text(value);
    if (!raw) throw new Error('Enter the actual agent endpoint.');
    if (/[\s\x00-\x1f\\]/.test(raw)) throw new Error('Enter a URL without spaces, control characters or backslashes.');
    const parsed = new URL(raw.includes('://') ? raw : `http://${raw}`);
    if (!protocols.includes(parsed.protocol) || !parsed.hostname || parsed.hostname.startsWith('.') || parsed.port === '0') throw new Error('Choose a supported endpoint URL.');
    if (parsed.username || parsed.password) throw new Error('Use a URL without credentials; configure target authentication separately.');
    if (parsed.hash) throw new Error('Remove the URL fragment; enter the actual service endpoint.');
    return root.DashboardSemantics?.targetEndpoint ? root.DashboardSemantics.targetEndpoint(raw, protocols) : parsed.href;
  }

  function checkField(spec, raw) {
    const value = text(raw);
    if (spec.optional && (raw === null || raw === undefined || (typeof raw === 'string' && value === ''))) return { value: null };
    if (spec.type === 'boolean') return typeof raw === 'boolean' ? { value: raw } : { error: 'Choose a checked or unchecked value.' };
    if (spec.type === 'consent') return raw === true ? { value: 'non_sensitive' } : { error: 'Designate this scan as non-sensitive and authorize external analysis, or choose deterministic/local analysis.' };
    if (!value) return { error: 'This field is required.' };
    if (spec.type === 'integer') {
      if (!/^\d+$/.test(value) || !Number.isSafeInteger(Number(value)) || Number(value) < spec.min || Number(value) > spec.max) return { error: `Enter a whole number between ${spec.min} and ${spec.max}.` };
      return { value: Number(value) };
    }
    if (spec.type === 'choice') return spec.choices.includes(value) ? { value } : { error: 'Choose one of the available options.' };
    if (spec.type === 'canary') return /^[A-Za-z0-9_-]{16,128}$/.test(value) ? { value } : { error: 'Use a synthetic reference of 16–128 letters, numbers, underscores or hyphens already provisioned on your agent, or leave empty.' };
    if (spec.type === 'url') {
      try { return { value: endpoint(value, spec.protocols) }; }
      catch (error) { return { error: error.message === 'Invalid URL' ? 'Enter a valid service endpoint URL.' : error.message }; }
    }
    if (spec.type === 'localModel') return /^ollama\/[A-Za-z0-9_.:/-]{1,128}$/.test(value) && !/cloud/i.test(value) ? { value } : { error: 'Enter an installed offline model as ollama/model-name.' };
    if (spec.type === 'externalModel') return /^[A-Za-z0-9._-]{1,128}$/.test(value) ? { value } : { error: 'Enter the exact provider model ID using letters, numbers, dots, underscores or hyphens.' };
    if (spec.type === 'path') return value.length <= 4096 && !/[\x00-\x1f]/.test(value) ? { value } : { error: 'Enter a project path without control characters (up to 4096 characters).' };
    if (spec.type === 'signingKey') return bytes(value) >= 32 && value !== 'agentscan-audit-verification-key' ? { value } : { error: 'Use a private signing key of at least 32 bytes, or leave this field empty to use the server key.' };
    if (spec.type === 'jsonObject') {
      if (bytes(value) > 65536) return { error: 'Use a JSON object smaller than 64 KB.' };
      try {
        const parsed = JSON.parse(value);
        return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? { value: parsed } : { error: 'Enter a JSON object, for example {}. Arrays, null and scalar values are not accepted.' };
      } catch { return { error: 'Enter valid JSON with double-quoted keys and no trailing commas.' }; }
    }
    if (spec.type === 'mcpBaseline') {
      const error = 'Use approved catalog JSON with an exact endpoint, at most 1000 exact ASCII tool names and lowercase SHA256 hashes; the supported algorithm is mcp-tool-json-sha256-v1.';
      if (bytes(raw) > 262144) return { error: 'Use an approved catalog JSON object of at most 256 KB.' };
      try {
        const parsed = JSON.parse(value);
        const object = item => item !== null && typeof item === 'object' && !Array.isArray(item);
        if (!object(parsed) || Object.keys(parsed).some(key => !['endpoint', 'tools', 'algorithm'].includes(key)) ||
            typeof parsed.endpoint !== 'string' || !parsed.endpoint || parsed.endpoint.length > 8192 || /[\s\x00-\x1f\x7f]/.test(parsed.endpoint) ||
            (Object.hasOwn(parsed, 'algorithm') && parsed.algorithm !== 'mcp-tool-json-sha256-v1') || !object(parsed.tools) || Object.keys(parsed.tools).length > 1000 ||
            Object.entries(parsed.tools).some(([name, hash]) => !name.length || name.length > 128 || /[^A-Za-z0-9_.-]/.test(name) || typeof hash !== 'string' || hash.length !== 64 || /[^0-9a-f]/.test(hash))) return { error };
        return { value: parsed };
      } catch { return { error }; }
    }
    if (spec.type === 'factualityBaseline') {
      const error = 'Use approved answer-check JSON with schema_version agentscan.factuality.v1, an exact HTTP(S) target_url and 1–16 unique ASCII case IDs; each case needs a question (1–2048 characters), expected_answer and a different false_answer (1–512 characters each). Extra or duplicate keys are not accepted.';
      if (bytes(raw) > 262144) return { error: 'Use approved answer-check JSON of at most 256 KB.' };
      try {
        const parsed = uniqueJSON(value);
        const object = item => item !== null && typeof item === 'object' && !Array.isArray(item);
        const exactKeys = (item, keys) => object(item) && Object.keys(item).length === keys.length && keys.every(key => Object.hasOwn(item, key));
        const boundedText = (item, limit) => typeof item === 'string' && item.trim().length > 0 && [...item].length <= limit &&
          ![...item].some(char => char.length === 1 && char.charCodeAt(0) >= 0xD800 && char.charCodeAt(0) <= 0xDFFF);
        if (!exactKeys(parsed, ['schema_version', 'target_url', 'cases']) || parsed.schema_version !== 'agentscan.factuality.v1' ||
            typeof parsed.target_url !== 'string' || !/^https?:\/\//.test(parsed.target_url) || parsed.target_url.length > 8192 ||
            /[\s\x00-\x1f\x7f\\]/.test(parsed.target_url) || !Array.isArray(parsed.cases) || parsed.cases.length < 1 || parsed.cases.length > 16) return { error };
        const parsedURL = new URL(parsed.target_url);
        if (!parsedURL.hostname || parsedURL.username || parsedURL.password || parsedURL.hash || parsedURL.port === '0') return { error };
        const ids = new Set();
        for (const item of parsed.cases) {
          if (!exactKeys(item, ['id', 'question', 'expected_answer', 'false_answer']) || typeof item.id !== 'string' ||
              !/^[A-Za-z0-9_.-]{1,64}$/.test(item.id) || ids.has(item.id) || !boundedText(item.question, 2048) ||
              !boundedText(item.expected_answer, 512) || !boundedText(item.false_answer, 512) || item.expected_answer === item.false_answer) return { error };
          ids.add(item.id);
        }
        return { value: parsed };
      } catch { return { error }; }
    }
    if (value.length > (spec.max || 65536) || value.includes('\0')) return { error: 'Use text within the field size limit without null characters.' };
    return { value };
  }

  function specs(workflow) { return definitions[workflow] || []; }
  function fieldFor(workflow, key) {
    const aliases = { target: 'target_url', max_rounds: 'max_rounds', rounds: 'max_rounds', interval: 'interval_seconds', name: 'tool', model: workflow === 'swarm' ? 'local_model' : 'model', attacker_model: workflow === 'calibration' ? 'model' : 'local_model', strategy: 'team', vulnerability_type: 'vulnerability_type', data_classification: 'data_classification' };
    if (key.startsWith('arguments.')) key = 'arguments';
    if (key.startsWith('mcp_inventory_baseline.')) key = 'mcp_inventory_baseline';
    if (key.startsWith('factuality_baseline.')) key = 'factuality_baseline';
    if (workflow === 'discovery' && ['target', 'target_url'].includes(key)) key = 'url';
    const normalized = aliases[key] || key;
    return specs(workflow).find(spec => spec.field === normalized) || (key === 'body' ? specs(workflow)[0] : null);
  }
  function renderField(spec, message) {
    const element = root.document?.getElementById(spec.id);
    if (!element) return;
    const id = `${spec.id}-error`;
    let error = root.document.getElementById(id);
    if (!error) {
      error = root.document.createElement('p'); error.id = id; error.className = 'form-field-error'; error.setAttribute('aria-live', 'polite');
      element.parentElement.append(error);
    }
    error.textContent = message || ''; error.hidden = !message;
    const descriptions = new Set((element.getAttribute('aria-describedby') || '').split(/\s+/).filter(Boolean));
    if (message) { element.setAttribute('aria-invalid', 'true'); descriptions.add(id); }
    else { element.removeAttribute('aria-invalid'); descriptions.delete(id); }
    if (descriptions.size) element.setAttribute('aria-describedby', [...descriptions].join(' '));
    else element.removeAttribute('aria-describedby');
  }
  function clear(workflow) { specs(workflow).forEach(spec => renderField(spec, null)); }
  function clearSecretFields(workflow) {
    // A submitted secret must not stay readable in the DOM for screenshots, extensions
    // or shoulder-surfing. Only authored secret inputs are cleared; everything else
    // keeps its value for the operator.
    let cleared = 0;
    specs(workflow).forEach(spec => {
      if (!['signingKey', 'canary'].includes(spec.type)) return;
      const element = root.document?.getElementById(spec.id);
      if (element && 'value' in element && element.value) { element.value = ''; cleared += 1; }
    });
    return cleared;
  }
  function applyServer(workflow, payload) {
    const errors = payload?.field_errors || {};
    Object.entries(errors).forEach(([key, message]) => { const spec = fieldFor(workflow, key); if (spec) renderField(spec, String(message).slice(0, 500)); });
    return errors;
  }
  function validate(workflow, options = {}) {
    const values = {}, errors = {};
    const mode = root.document?.getElementById(`${workflow}-analysis-mode`)?.value || 'deterministic';
    for (const spec of specs(workflow)) {
      if (spec.when && mode !== spec.when) continue;
      const element = root.document?.getElementById(spec.id);
      if (!element) {
        if (!spec.optional) errors[spec.field] = 'The field is unavailable. Reload the dashboard and try again.';
        continue;
      }
      const raw = ['boolean', 'consent'].includes(spec.type) ? element.checked : element.value;
      const result = checkField(spec, raw);
      if (result.error) errors[spec.field] = result.error; else values[spec.field] = result.value;
      if (spec.type === 'tool' && !Array.from(element.options).some(option => option.value === element.value)) errors[spec.field] = 'Choose an available MCP tool.';
    }
    if (['scan', 'swarm'].includes(workflow)) {
      values.data_classification = mode === 'external' ? values.data_classification : 'sensitive';
      if (mode === 'external' && values.external_provider && values.external_model) values.external_model = `${values.external_provider}/${values.external_model}`;
      delete values.external_provider;
    }
    if (workflow === 'scan' && values.mcp_inventory_baseline) {
      if (!/^mcp\+sses?:\/\//.test(values.target_url || '') || values.mcp_inventory_baseline.endpoint !== values.target_url ||
          values.mode !== 'FAST' || mode !== 'deterministic' || values.indirect_adapter !== 'none') {
        errors.mcp_inventory_baseline = 'Catalog-only checks require the exact MCP SSE endpoint, standard mode, deterministic analysis and no document adapter.';
      }
    }
    if (workflow === 'scan' && values.factuality_baseline) {
      if (!/^https?:\/\//.test(values.target_url || '') || values.factuality_baseline.target_url !== values.target_url ||
          values.mode !== 'FAST' || mode !== 'deterministic' || values.indirect_adapter !== 'none' || values.mcp_inventory_baseline) {
        errors.factuality_baseline = 'Approved answer checks require the exact HTTP(S) endpoint, standard mode, deterministic analysis, no document adapter and no MCP catalog baseline.';
      }
    }
    if (workflow === 'discovery') { values.no_exploit = !values.allow_probe; delete values.allow_probe; }
    if (workflow === 'audit' && !specs('audit').filter(spec => spec.field.startsWith('scan_')).some(spec => values[spec.field] === true)) errors.ruleset = 'Select at least one audit check.';
    if (workflow === 'mcp' && values.arguments) {
      const args = values.arguments, tool = values.tool;
      const checkArgument = (key, spec, optional = false) => {
        if (optional && !(key in args)) return;
        const result = checkField(spec, typeof args[key] === 'number' ? String(args[key]) : args[key]);
        if (result.error) errors[`arguments.${key}`] = result.error; else args[key] = result.value;
      };
      if (['agentscan_scan', 'scan_target', 'agentscan_swarm'].includes(tool)) checkArgument('target_url', { type: 'url', protocols: tool === 'agentscan_swarm' ? remote : scanRemote });
      if (tool === 'agentscan_scan') checkArgument('timeout', { type: 'integer', min: 1, max: 300 }, true);
      if (tool === 'agentscan_swarm') {
        checkArgument('rounds', { type: 'integer', min: 1, max: 10 }, true);
        if ('team' in args && (typeof args.team !== 'string' || !args.team.trim())) errors['arguments.team'] = 'Choose a swarm preset or project YAML team path.';
        if (args.offline === false) checkArgument('model', { type: 'localModel' });
      }
      if (tool === 'agentscan_audit') checkArgument('path', { type: 'path' }, true);
      for (const key of ['offline', 'show_transitive']) if (key in args && typeof args[key] !== 'boolean') errors[`arguments.${key}`] = 'Use a JSON boolean: true or false.';
    }
    if (options.render !== false) {
      clear(workflow); applyServer(workflow, { field_errors: errors });
      if (Object.keys(errors).length && options.focus !== false) { const first = fieldFor(workflow, Object.keys(errors)[0]); root.document?.getElementById(first?.id)?.focus(); }
    }
    return { valid: !Object.keys(errors).length, values, errors };
  }
  function attach() {
    Object.keys(definitions).forEach(workflow => specs(workflow).forEach(spec => {
      const element = root.document?.getElementById(spec.id);
      if (!element) return;
      const attached = new Set((element.dataset.validationAttached || '').split(' ').filter(Boolean));
      if (attached.has(workflow)) return;
      attached.add(workflow); element.dataset.validationAttached = [...attached].join(' ');
      const update = () => {
        const result = validate(workflow, { render: false });
        renderField(spec, result.errors[spec.field]);
        if (workflow === 'scan' && ['target_url', 'mode', 'analysis_mode', 'indirect_adapter', 'mcp_inventory_baseline', 'factuality_baseline'].includes(spec.field)) {
          const baseline = specs(workflow).find(item => item.field === 'factuality_baseline');
          if (baseline) renderField(baseline, result.errors.factuality_baseline);
        }
        if (spec.field === 'analysis_mode') {
          specs(workflow).filter(item => item.when && item.when !== element.value).forEach(item => renderField(item, null));
        }
        const banners = { scan: 'scan-launch-error', discovery: 'discovery-launch-error', audit: 'audit-launch-error', calibration: 'calibration-launch-error', sentinel: 'sentinel-launch-error', sentinelProbe: 'sentinel-launch-error', mcp: 'mcp-launch-error', swarm: 'swarm-launch-error', healApply: 'heal-apply-launch-error', healSimulation: 'heal-simulation-launch-error', event: 'event-launch-error', certificate: 'certificate-launch-error' };
        const banner = root.document?.getElementById(banners[workflow]);
        if (banner) { banner.hidden = true; banner.textContent = ''; }
      };
      element.addEventListener('input', update); element.addEventListener('change', update);
    }));
  }
  const api = { validate, clear, clearSecretFields, applyServer, attach, getValues: workflow => validate(workflow, { render: false }).values, inventory: () => Object.entries(definitions).flatMap(([workflow, fields]) => fields.map(field => ({ workflow, ...field }))), checkField };
  root.AgentScanForms = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis);
