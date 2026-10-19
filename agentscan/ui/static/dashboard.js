/* Shared display semantics. These helpers never manufacture scan evidence. */
(function (root) {
  'use strict';
  const escape = value => String(value ?? '').replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));
  const count = value => typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? value : null;

  function targetEndpoint(value, protocols = ['http:', 'https:'], dashboardUrl = root.location?.href) {
    const raw = String(value ?? '').trim();
    if (!raw) throw new Error('Enter the actual agent endpoint. The AgentScan dashboard is a separate service.');
    const hasScheme = /^[a-z][a-z\d+.-]*:\/\//i.test(raw);
    let target;
    try { target = new URL(hasScheme ? raw : `http://${raw}`); }
    catch { throw new Error('Enter a valid absolute agent endpoint URL.'); }
    if (!protocols.includes(target.protocol) || !target.hostname) {
      throw new Error('Choose a supported remote agent endpoint URL.');
    }
    const hostname = url => url.hostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
    const port = url => url.port || (['https:', 'wss:', 'mcp+sses:'].includes(url.protocol) ? '443' : '80');
    const local = new Set(['localhost', '127.0.0.1', '::1']);
    if (dashboardUrl) {
      const dashboard = new URL(dashboardUrl);
      const targetHost = hostname(target);
      const dashboardHost = hostname(dashboard);
      const sameHost = targetHost === dashboardHost || (local.has(targetHost) && local.has(dashboardHost));
      if (sameHost && port(target) === port(dashboard)) {
        throw new Error('This URL points to the AgentScan dashboard. Enter your separate agent API endpoint, using its own port.');
      }
    }
    return target.href;
  }

  function errorText(value) {
    return String(value ?? 'No error detail was recorded.')
      .replace(/(authorization\s*[:=]\s*(?:bearer\s+)?)[^\s,;]+/gi, '$1[redacted]')
      .replace(/((?:api[_-]?key|access[_-]?token|secret|password)\s*[:=]\s*)[^\s,;&]+/gi, '$1[redacted]')
      .slice(0, 1200);
  }

  function errorGuidance(value) {
    const error = errorText(value);
    if (/points to the AgentScan dashboard|separate.*agent endpoint|endpoint.*separate service/i.test(error)) return { title: 'Choose your agent endpoint', action: 'AgentScan is the dashboard and scanner. Enter the separate agent service URL and its port.' };
    if (/non.sensitive|sensitive.*external|designation/i.test(error)) return { title: 'External analysis needs a designation', action: 'Use deterministic or local analysis for sensitive scans. External analysis requires explicit non-sensitive designation for this scan.' };
    if (/configure.*(?:API_KEY|provider key)|provider\/model|external.*model ID/i.test(error)) return { title: 'External analysis setup is incomplete', action: 'Choose the provider and exact model ID. Configure that provider key locally in the server environment or .env; it is separate from target authentication.' };
    if (/offline.*model|local.*(?:Ollama|loopback|model)|Ollama|model.*(?:not found|not installed)/i.test(error)) return { title: 'Local model analysis is unavailable', action: 'Verify the installed local model, the loopback Ollama service, and disabled cloud features. Deterministic checks can run without an analysis model.' };
    if (/Dashboard request.*\b401\b/i.test(error)) return { title: 'Dashboard session is not authorized', action: 'Reopen the launch URL printed by agentscan ui to establish its local session. Dashboard authentication is separate from target credentials.' };
    if (/Dashboard request.*\b403\b/i.test(error)) return { title: 'The dashboard rejected the request', action: 'Reload the dashboard from its launch URL and review the recorded policy or session error. No successful operation has been confirmed.' };
    if (/\b409\b|already running/i.test(error)) return { title: 'Another operation is already running', action: 'Review the current operation status. Wait for it to finish or cancel it before starting another.' };
    if (/\b413\b|too large|size limit/i.test(error)) return { title: 'The request exceeds the size limit', action: 'Reduce the JSON payload or text to the displayed field limit, then retry.' };
    if (/ModuleNotFoundError|ImportError|No module named|not installed|(?:missing|required).*(?:dependency|extra)|optional.*(?:dependency|extra)/i.test(error)) return { title: 'A required dependency is unavailable', action: 'Review the missing module and install the optional feature dependencies in the scanner environment before rerunning that check.' };
    if (/required|highlighted fields|whole number|valid JSON|choose one|enter.*(?:URL|endpoint|model|path)/i.test(error)) return { title: 'Review the highlighted fields', action: 'Correct the message beside each field, then submit again. Your request has not started.' };
    if (/webhook/i.test(error)) return { title: 'Webhook notification was not delivered', action: 'Review the configured notification endpoint and its delivery requirements. Monitoring status and recorded findings are separate from notification delivery.' };
    if (/\b401\b|unauthorized/i.test(error)) return { title: 'Authentication was rejected', action: 'Verify the actual target endpoint and its authentication requirements. Configure target credentials through a CLI target profile or --auth-header. Provider credentials belong to analysis setup.' };
    if (/\b403\b|forbidden|denied|not enrolled/i.test(error)) return { title: 'Access or policy denied the request', action: 'Check target authorization and the operator or tenant network policy. The recorded error identifies the denied request; a denied check is not a clean result.' };
    if (/\b404\b|route.*not found|endpoint.*not found/i.test(error)) return { title: 'The requested route was not found', action: 'Verify the agent API path and request format. Default HTTP scans use POST JSON {"message": "..."}; configure a CLI transport for another API shape.' };
    if (/\b429\b|rate.?limit|too many requests/i.test(error)) return { title: 'The service rate limited the request', action: 'Review the service quota and retry window. Reduce scan concurrency before retrying; failed checks remain unevaluated.' };
    if (/timeout|timed out|deadline/i.test(error)) return { title: 'A request exceeded its deadline', action: 'Check service availability and response time, then review timeout and concurrency settings. A timeout does not prove the agent resisted a probe.' };
    if (/dashboard service could not be reached/i.test(error)) return { title: 'The dashboard service could not be reached', action: 'Check that AgentScan is still running and reload its launch URL. The launch was not acknowledged; review scan status before retrying.' };
    if (/ConnectError|connection.*(?:refused|failed|reset)|could not connect|name.*resolution|DNS/i.test(error)) return { title: 'The service could not be reached', action: 'Check the host, port, protocol, network access, and whether the agent service is running. A local agent uses its own port, separate from this dashboard.' };
    if (/\b5\d\d\b|server error/i.test(error)) return { title: 'A service returned a server error', action: 'Review the service logs and request compatibility before rerunning. The scanner cannot infer a security verdict from a failed response.' };
    return { title: 'Execution needs review', action: 'Review the exact recorded error and selected check configuration. This error has no known automatic diagnosis.' };
  }

  function assessmentErrorMarkup(report) {
    if (!report || typeof report !== 'object') return '';
    const failures = [];
    const seen = new Set();
    const add = item => {
      const name = item.module_name || item.module_id || 'Scanner';
      const reason = errorText(`${item.error_id ? 'Diagnostic reference: ' + String(item.error_id).slice(0, 64) + '. ' : ''}${item.error || item.reason || 'No error detail was recorded.'}`);
      const key = `${name}|${reason}`;
      if (!seen.has(key)) { seen.add(key); failures.push({ name, reason }); }
    };
    (Array.isArray(report.module_errors) ? report.module_errors : []).forEach(item => add(typeof item === 'object' && item ? item : { error: item }));
    (Array.isArray(report.module_outcomes) ? report.module_outcomes : [])
      .filter(item => item && typeof item === 'object' && ['ERROR', 'FAILED', 'UNAVAILABLE', 'INCONCLUSIVE'].includes(String(item.status).toUpperCase()))
      .forEach(add);
    const incomplete = ['ERROR', 'INCONCLUSIVE'].includes(String(report.status).toUpperCase());
    if (!failures.length && !incomplete) return '';
    const summary = summarize(report);
    const catalog = report.assessment_scope === 'catalog';
    const dashboard = report.assessment_scope === 'dashboard';
    const audit = report.assessment_scope === 'audit';
    const watcher = report.assessment_scope === 'watcher';
    const discovery = report.assessment_scope === 'discovery';
    const delivery = report.assessment_scope === 'sentinel_delivery';
    const details = failures.slice(0, 200).map(failure => {
      const guidance = errorGuidance(failure.reason);
      return `<details class="assessment-error-detail"><summary><code>${escape(failure.name)}</code><span>${escape(guidance.title)}</span></summary><p>${escape(guidance.action)}</p><pre>${escape(failure.reason)}</pre></details>`;
    }).join('');
    return `<section class="assessment-errors" aria-label="Assessment errors and guidance">
      <div class="assessment-errors-heading"><strong>${delivery ? 'Sentinel notification delivery failed' : watcher ? 'Sentinel watcher stopped on error' : dashboard ? 'Dashboard data needs attention' : catalog ? 'Module setup needs attention' : failures.length ? 'Some checks could not complete' : 'Assessment is incomplete'}</strong>${catalog || dashboard || audit || watcher || discovery || delivery ? '' : `<span>${summary.evaluated ?? 'Unavailable'} / ${summary.selected ?? 'Unavailable'} evaluated</span>`}</div>
      <p>${dashboard ? 'These dashboard datasets could not refresh. Their current values are unavailable; review each request and retry the refresh.' : catalog ? 'These modules could not load in this environment. These setup warnings are separate from scan execution results; currently available modules remain selectable.' : failures.length ? `${failures.length} recorded failure${failures.length === 1 ? '' : 's'}. Expand each item for its error and next step. Unavailable checks cannot support a clean verdict.` : 'No detailed error was recorded. Review the assessment configuration and scanner logs before retrying. Unavailable checks cannot support a clean verdict.'}</p>
      <div class="assessment-errors-list">${details}</div>${failures.length > 200 ? `<p>${failures.length - 200} more failures are available in the JSON report.</p>` : ''}
    </section>`;
  }

  function showLaunchError(elementId, value) {
    const element = document.getElementById(elementId);
    if (!element) return;
    element.replaceChildren();
    element.hidden = value === null || value === undefined;
    if (element.hidden) return;
    const guidance = errorGuidance(value);
    const title = document.createElement('strong');
    title.textContent = guidance.title;
    const action = document.createElement('p');
    action.textContent = guidance.action;
    const detail = document.createElement('pre');
    detail.textContent = errorText(value);
    element.append(title, action, detail);
  }

  function responseError(payload, status) {
    let detail;
    if (typeof payload?.error === 'string') detail = payload.error;
    else if (typeof payload?.detail === 'string') detail = payload.detail;
    else if (Array.isArray(payload?.detail)) detail = payload.detail.map(item => item.msg || 'Invalid request').join('; ');
    else if (payload?.field_errors && typeof payload.field_errors === 'object') detail = Object.values(payload.field_errors).join('; ');
    else detail = `Request failed (${status}). No additional error detail was recorded.`;
    const reference = typeof payload?.error_id === 'string' ? `Diagnostic reference: ${payload.error_id.slice(0, 64)}. ` : '';
    return reference + errorText(detail).slice(0, 1100);
  }

  async function requestJSON(url, options = {}, workflow) {
    let response;
    try { response = await root.fetch(url, options); }
    catch { throw new Error('Connection failed: the dashboard service could not be reached. Check that AgentScan is still running, then retry.'); }
    let data;
    try { data = await response.json(); }
    catch {
      throw new Error(`Dashboard request ${url} returned HTTP ${response.status} without a valid JSON response. Check the dashboard session and service logs before retrying.`);
    }
    if (workflow && root.AgentScanForms) root.AgentScanForms.applyServer(workflow, data);
    if (!response.ok) throw new Error(`Dashboard request ${url}: HTTP ${response.status}. ${responseError(data, response.status)}`);
    return data;
  }

  function summarize(report) {
    const observations = root.AgentScanAnalytics?.summarize(report);
    if (!report || typeof report !== 'object' || report.error || observations?.available === false) {
      return { status: 'NOT RUN', tone: 'neutral', score: null, selected: 0,
        evaluated: 0, referenceCount: 0, outcomes: [], scope: 'target',
        detail: 'Run a scan or load a report to assess this target.' };
    }
    const status = String(report.status || 'LEGACY REPORT').toUpperCase();
    const selectedCount = count(report.tests_selected);
    const evaluatedCount = count(report.tests_run);
    const validCounts = selectedCount !== null && evaluatedCount !== null && evaluatedCount <= selectedCount;
    const evaluated = observations ? observations.coverage.evaluated : validCounts ? evaluatedCount : null;
    const selected = observations ? observations.coverage.selected : validCounts ? selectedCount : null;
    const scope = observations ? observations.scope : typeof report.assessment_scope === 'string' ? report.assessment_scope : 'unavailable';
    const numeric = typeof report.score === 'number' && Number.isFinite(report.score);
    const score = numeric && evaluated > 0 && ['COMPLETE', 'INCONCLUSIVE'].includes(status) &&
      !['local_reference_model', 'factuality_policy', 'overreliance_response_inventory'].includes(scope)
      ? Math.max(0, Math.min(100, Math.round(report.score))) : null;
    const outcomes = Array.isArray(report.module_outcomes) ? report.module_outcomes.map(item => item && typeof item === 'object' ? item : { status: 'UNAVAILABLE', reason: 'Malformed module record. Review the JSON report.' }) : [];
    const referenceCount = Array.isArray(report.reference_observations) ? report.reference_observations.length : 0;
    const tone = status === 'ERROR' ? 'error' : status === 'INCONCLUSIVE' ? 'warning'
      : status === 'COMPLETE' ? 'complete' : 'neutral';
    let detail = status === 'COMPLETE' ? 'Selected checks finished. Review the findings and assessment scope.'
      : status === 'INCONCLUSIVE' ? 'Coverage is incomplete. Unavailable or failed checks cannot support a clean verdict.'
      : status === 'ERROR' ? 'The assessment encountered execution errors. Review module errors before retrying.'
      : status === 'RUNNING' ? 'Assessment is running. Results are still being collected.'
      : 'This older report has no explicit execution status. Treat coverage as unverified.';
    if (scope === 'local_reference_model') {
      detail = 'Local reference-model diagnostics do not assess this remote target. Target score is unavailable.';
    }
    if (scope === 'factuality_policy') {
      detail = 'These checks compare responses with client-approved exact answers. Policy mismatches do not verify factual truth or downstream security impact. Target score is unavailable.';
    }
    if (scope === 'overreliance_response_inventory') {
      detail = 'These probes record response indicators. Factual truth, tool execution and downstream impact remain unassessed. Target score is unavailable.';
    }
    if (selected === null || evaluated === null) detail = observations?.coverage.reason || 'Coverage counts are unavailable or inconsistent. Review the JSON report.';
    return { status, tone, score, selected, evaluated, referenceCount, outcomes, scope, detail };
  }

  function severityClass(value) {
    const severity = String(value || 'INFO').toLowerCase();
    return 'severity-badge severity-' + (['critical', 'high', 'medium', 'low', 'info', 'pass'].includes(severity) ? severity : 'info');
  }

  function inlineArgument(value) {
    // JSON protects JavaScript string syntax; HTML escaping protects the attribute.
    return escape(JSON.stringify(String(value ?? '')));
  }

  function coverageMarkup(report) {
    const summary = summarize(report);
    const available = summary.selected !== null && summary.evaluated !== null;
    const percent = available && summary.selected ? Math.round(summary.evaluated / summary.selected * 100) : 0;
    const rows = summary.outcomes.map(outcome => {
      const status = String(outcome.status || 'UNKNOWN').toUpperCase();
      const tone = status === 'COMPLETE' ? 'complete' : status === 'ERROR' ? 'error' : 'warning';
      return `<div class="coverage-row"><span title="${escape(outcome.reason || '')}">${escape(outcome.module_name || outcome.module_id || 'Module')}</span><span class="assessment-badge status-${tone}">${escape(status)}</span></div>`;
    }).join('');
    return `<div class="coverage-heading"><span>Evaluated coverage</span><strong>${available ? `${summary.evaluated} / ${summary.selected}` : 'Unavailable'}</strong></div>
      ${available ? `<div class="coverage-track" role="progressbar" aria-label="Evaluated checks" aria-valuenow="${percent}" aria-valuemin="0" aria-valuemax="100"><span style="width:${percent}%"></span></div>` : ''}
      <p class="coverage-explanation">${escape(summary.detail)}</p>
      ${rows ? `<details class="coverage-module-outcomes"><summary>Review all ${summary.outcomes.length} module outcomes</summary><div class="coverage-module-list">${rows}</div></details>` : '<div class="coverage-empty">No module execution records available.</div>'}
      ${summary.referenceCount ? `<p class="coverage-footnote">${summary.referenceCount} local reference observations · excluded from target findings and score.</p>` : ''}`;
  }

  function renderOverview(telemetry) {
    const report = telemetry.report;
    const summary = summarize(report);
    const findings = telemetry.findings || [];
    const text = (id, value) => {
      const el = document.getElementById(id);
      if (el) el.textContent = value;
    };
    const critical = findings.filter(f => f.severity === 'CRITICAL').length;
    const high = findings.filter(f => f.severity === 'HIGH').length;
    text('stat-suites-active', summary.evaluated ?? 'N/A');
    text('metric-checks-detail', report ? `${summary.outcomes.length} module outcomes recorded` : 'No assessment loaded');
    text('metric-checks-footer', `Selected checks: ${summary.selected ?? 'Unavailable'}`);
    text('stat-defense-score', summary.score === null ? 'N/A' : `${summary.score} / 100`);
    text('metric-score-detail', summary.score === null ? 'No supported target score available' : summary.status === 'INCONCLUSIVE' ? 'Partial score · coverage is incomplete' : 'Report score for evaluated target checks');
    text('metric-score-footer', summary.status === 'NOT RUN' ? 'Run a scan to collect assessment evidence' : summary.scope.replaceAll('_', ' '));
    text('stat-total-findings', findings.length);
    text('metric-findings-detail', findings.length ? `${critical} critical · ${high} high · ${findings.length - critical - high} other` : 'No findings recorded');
    const healing = telemetry.heal;
    const planned = healing && !healing.error && Number.isFinite(healing.total_actions) ? healing.total_actions : null;
    text('stat-healing-rate', planned === null ? 'N/A' : planned);
    text('metric-healing-detail', planned === null ? 'No remediation plan loaded' : `${planned} planned action${planned === 1 ? '' : 's'} · application unverified`);
    text('sidebar-cve-count', findings.length);
    const target = report?.target_url || report?.target?.url || 'No target assessed';
    text('header-target', target.replace(/^https?:\/\//, ''));
    text('overview-target', target);
    const badge = document.getElementById('assessment-status');
    if (badge) {
      badge.className = `assessment-badge status-${summary.tone}`;
      badge.textContent = summary.status;
    }
    const coverage = document.getElementById('assessment-coverage');
    if (coverage) coverage.innerHTML = coverageMarkup(report) + assessmentErrorMarkup(report);
    if (root.AgentScanAnalytics) root.AgentScanAnalytics.render(report, document.getElementById('scan-analytics'), {
      onSeverity: severity => {
        const search = document.getElementById('findings-search');
        if (search) search.value = '';
        root.switchTab('findings');
        root.filterFindings(severity);
        const suffix = { CRITICAL: 'crit', HIGH: 'high', MEDIUM: 'med', LOW: 'low', INFO: 'info', PASS: 'pass' };
        document.getElementById(`filter-btn-${suffix[severity]}`)?.focus();
      },
    });
    const container = document.getElementById('overview-findings-grid');
    if (!container) return;
    if (!findings.length) {
      container.innerHTML = `<div class="overview-empty-state col-span-1 sm:col-span-2 lg:col-span-4"><span class="empty-state-symbol" aria-hidden="true">◎</span><strong>No findings recorded</strong><p>${report ? 'Review assessment coverage before drawing a security conclusion.' : 'Launch a scan or load a saved report to collect evidence.'}</p><button class="btn-pill-light" onclick="openScanModal()">Launch a scan →</button></div>`;
      return;
    }
    container.innerHTML = findings.slice(0, 4).map(f => `<div class="finding-card finding-preview">
      <div class="finding-preview-head"><code>${escape(f.attack_id)}</code><span class="${severityClass(f.severity)}">${escape(f.severity)}</span></div>
      <h3>${escape(f.title)}</h3><p>${escape(f.description)}</p>
      <div class="finding-preview-footer"><span>${f.remediation ? 'Guidance available' : 'Review evidence'}</span><button onclick="switchTab('findings'); openFindingInspector(${inlineArgument(f.cve)})" class="finding-inspect">Inspect →</button></div>
    </div>`).join('');
  }

  const api = { summarize, severityClass, inlineArgument, coverageMarkup, renderOverview, targetEndpoint, errorText, errorGuidance, assessmentErrorMarkup, showLaunchError, responseError, requestJSON, escape };
  root.DashboardSemantics = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window === 'undefined' ? globalThis : window);
