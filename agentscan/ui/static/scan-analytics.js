/* Local report analytics. Counts describe observations, never agent resistance. */
(function (root) {
  'use strict';
  const STATUSES = ['COMPLETE', 'INCONCLUSIVE', 'ERROR', 'SKIPPED', 'RUNNING', 'UNAVAILABLE'];
  const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'PASS', 'UNCLASSIFIED'];
  const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
  const count = value => typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
  const label = (value, fallback) => typeof value === 'string' && value.trim() ? value.trim() : fallback;
  const safeReason = value => {
    const text = label(value, '');
    return root.DashboardSemantics ? root.DashboardSemantics.errorText(text) : text;
  };

  function coverage(selected, evaluated) {
    const available = count(selected) && count(evaluated) && evaluated <= selected;
    return { available, selected: available ? selected : null, evaluated: available ? evaluated : null,
      remaining: available ? selected - evaluated : null,
      reason: available ? '' : 'Counts are missing or inconsistent. Review the JSON report.' };
  }

  function timestamp(value) {
    if (typeof value !== 'string') return null;
    const parts = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,6})?(Z|[+-](\d{2}):(\d{2}))$/.exec(value);
    if (!parts) return null;
    const [, yearText, monthText, dayText, hourText, minuteText, secondText] = parts;
    const [year, month, day, hour, minute, second] = [yearText, monthText, dayText, hourText, minuteText, secondText].map(Number);
    const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
    const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if (year < 1 || month < 1 || month > 12 || day < 1 || day > days[month - 1] ||
        hour > 23 || minute > 59 || second > 59 || Number(parts[8] || 0) > 23 || Number(parts[9] || 0) > 59) return null;
    const milliseconds = Date.parse(value);
    return Number.isFinite(milliseconds) ? milliseconds : null;
  }

  function summarize(report) {
    const available = object(report) && !report.error &&
      (typeof report.status === 'string' || Array.isArray(report.findings) || Array.isArray(report.module_outcomes) ||
        Object.hasOwn(report, 'tests_selected') || Object.hasOwn(report, 'tests_run'));
    const status = available ? label(report.status, 'LEGACY REPORT').toUpperCase() : 'NOT RUN';
    const scope = available ? label(report.assessment_scope, 'unavailable') : 'unavailable';
    const reportCoverage = available ? coverage(report.tests_selected, report.tests_run) : coverage(undefined, undefined);
    if (!available) reportCoverage.reason = 'Run a scan or load a report to view recorded coverage.';
    const rawModules = available && Array.isArray(report.module_outcomes) ? report.module_outcomes : [];
    const modules = rawModules.map((item, index) => {
      const row = object(item) ? item : {};
      const recordedStatus = label(row.status, 'UNAVAILABLE').toUpperCase();
      return {
        id: label(row.module_id, `record-${index + 1}`),
        name: label(row.module_name, label(row.module_id, `Unavailable module record ${index + 1}`)),
        status: STATUSES.includes(recordedStatus) ? recordedStatus : 'UNAVAILABLE',
        scope: label(row.assessment_scope, scope === 'mixed' ? 'unavailable' : scope),
        coverage: coverage(row.selected_tests, row.executed_tests),
        reason: safeReason(row.reason || row.error),
      };
    });
    if (reportCoverage.available && modules.length) {
      const selected = modules.reduce((total, item) => total + (item.coverage.selected ?? NaN), 0);
      const evaluated = modules.reduce((total, item) => total + (item.coverage.evaluated ?? NaN), 0);
      if (!count(selected) || !count(evaluated) || selected !== reportCoverage.selected || evaluated !== reportCoverage.evaluated) {
        Object.assign(reportCoverage, { available: false, selected: null, evaluated: null, remaining: null,
          reason: 'Report totals and module counts do not agree. Review the JSON report.' });
      }
    }
    const statusCounts = Object.fromEntries(STATUSES.map(item => [item, 0]));
    modules.forEach(item => statusCounts[item.status]++);
    const statuses = { available: modules.length > 0, counts: statusCounts,
      total: modules.length ? modules.length : null,
      reason: modules.length ? '' : 'No module execution records are available.' };
    const rawFindings = available && Array.isArray(report.findings) ? report.findings : null;
    const severityCounts = Object.fromEntries(SEVERITIES.map(item => [item, 0]));
    if (rawFindings) rawFindings.forEach(item => {
      const severity = object(item) ? label(item.severity, 'UNCLASSIFIED').toUpperCase() : 'UNCLASSIFIED';
      severityCounts[SEVERITIES.includes(severity) ? severity : 'UNCLASSIFIED']++;
    });
    const severity = { available: rawFindings !== null, counts: severityCounts, total: rawFindings ? rawFindings.length : null,
      reason: rawFindings === null ? 'Finding records are unavailable in this report.' : '' };
    const started = available ? timestamp(report.started_at) : null;
    const completed = available ? timestamp(report.completed_at) : null;
    const elapsedAvailable = started !== null && completed !== null && completed >= started;
    const elapsed = { available: elapsedAvailable, milliseconds: elapsedAvailable ? completed - started : null,
      reason: elapsedAvailable ? '' : status === 'RUNNING' ? 'The scan is still running. Elapsed time is available after completion.'
        : 'Valid start and completion timestamps are required.' };
    return { available, status, scope, coverage: reportCoverage, modules, statuses, severity, elapsed,
      referenceCount: available && Array.isArray(report.reference_observations) ? report.reference_observations.length : null };
  }

  function duration(milliseconds) {
    if (milliseconds < 60000) return `${Math.round(milliseconds / 100) / 10} s`;
    const seconds = Math.floor(milliseconds / 1000);
    if (seconds < 3600) return `${Math.floor(seconds / 60)} min ${seconds % 60} s`;
    return `${Math.floor(seconds / 3600)} h ${Math.floor(seconds / 60) % 60} min`;
  }

  function scopeLabel(scope) {
    const labels = { target: 'Target assessment', output_text_indicator_inventory: 'Output text · impact unassessed', direct_text_known_reference: 'Direct text · known reference',
      local_reference_model: 'Local reference diagnostics', local_consumer_validation: 'Local consumer validation · excluded from target score', owned_synthetic_target: 'Owned synthetic consumer · excluded from target score', local_consumer_lab: 'Local consumer lab · excluded from target score', mixed: 'Mixed assessment scopes',
      unavailable: 'Assessment scope unavailable' };
    return Object.hasOwn(labels, scope) ? labels[scope] : scope.replaceAll('_', ' ');
  }

  function render(report, container, options = {}) {
    if (!container) return;
    const summary = summarize(report);
    const document = container.ownerDocument || root.document;
    const node = (tag, text, className) => {
      const element = document.createElement(tag);
      if (text !== undefined) element.textContent = text;
      if (className) element.className = className;
      return element;
    };
    const panel = (title, explanation) => {
      const card = node('section', undefined, 'dl-card analytics-card');
      card.append(node('h3', title), node('p', explanation, 'analytics-explanation'));
      return card;
    };
    const empty = (parent, text) => parent.append(node('p', text, 'analytics-unavailable'));
    const meter = (parent, amount, total, kind) => {
      const track = node('div', undefined, 'analytics-bar');
      track.setAttribute('aria-hidden', 'true');
      const fill = node('span', undefined, `analytics-fill analytics-${kind}`);
      fill.style.width = `${total > 0 ? amount / total * 100 : 0}%`;
      track.append(fill);
      parent.append(track);
    };
    const content = node('div');
    const heading = node('div', undefined, 'analytics-heading');
    const title = node('div');
    title.append(node('div', 'Recorded observations', 'eyebrow'), node('h2', 'Scan evidence'),
      node('p', 'Coverage, findings and execution status for the loaded report.'));
    heading.append(title, node('span', scopeLabel(summary.scope), 'analytics-scope'));
    content.append(heading);
    if (!summary.available) {
      empty(content, 'Run a scan or load a saved report to view charts.');
      container.replaceChildren(content);
      return summary;
    }
    if (summary.scope === 'mixed' || summary.scope === 'local_reference_model') {
      empty(content, 'Local reference diagnostics are included in coverage and do not establish target security. Review each module’s scope.');
    } else if (summary.scope === 'unavailable') {
      empty(content, 'This report does not declare an assessment scope. Interpret its observations with care.');
    }
    const grid = node('div', undefined, 'analytics-grid');
    const coverageCard = panel('Evaluated coverage', 'Checks assessed against their stated criteria. Unevaluated checks remain visible.');
    if (summary.coverage.available) {
      coverageCard.append(node('strong', `${summary.coverage.evaluated} / ${summary.coverage.selected}`, 'analytics-value'));
      meter(coverageCard, summary.coverage.evaluated, summary.coverage.selected, 'evaluated');
      coverageCard.append(node('p', summary.coverage.selected === 0 ? 'No checks selected.' : `${summary.coverage.remaining} checks unevaluated.`, 'analytics-caption'));
    } else empty(coverageCard, summary.coverage.reason);
    grid.append(coverageCard);
    const elapsedCard = panel('Scan elapsed time', 'Whole-scan duration recorded between valid start and completion timestamps.');
    if (summary.elapsed.available) elapsedCard.append(node('strong', duration(summary.elapsed.milliseconds), 'analytics-value'));
    else empty(elapsedCard, summary.elapsed.reason);
    elapsedCard.append(node('p', 'Request latency is not measured by this chart.', 'analytics-caption'));
    grid.append(elapsedCard);
    const severityCard = panel('Finding severity', 'Recorded findings by severity. One check may produce several findings.');
    if (summary.severity.available) {
      const maximum = Math.max(1, ...Object.values(summary.severity.counts));
      SEVERITIES.forEach(severity => {
        if (severity === 'UNCLASSIFIED' && summary.severity.counts[severity] === 0) return;
        const row = node('div', undefined, 'analytics-count-row');
        const button = node('button', severity, 'analytics-filter');
        button.type = 'button';
        button.setAttribute('data-analytics-severity', severity);
        button.setAttribute('aria-label', `View ${summary.severity.counts[severity]} ${severity.toLowerCase()} findings`);
        button.disabled = severity === 'UNCLASSIFIED' || summary.severity.counts[severity] === 0 || !options.onSeverity;
        if (!button.disabled) button.addEventListener('click', () => options.onSeverity(severity));
        row.append(button, node('span', String(summary.severity.counts[severity]), 'analytics-count'));
        meter(row, summary.severity.counts[severity], maximum, severity.toLowerCase());
        severityCard.append(row);
      });
      severityCard.append(node('p', `${summary.severity.total} findings recorded. ${summary.referenceCount ?? 'Unavailable'} local reference observations are listed separately.`, 'analytics-caption'));
      if (summary.severity.total === 0) empty(severityCard, 'No findings recorded. Review coverage and errors before drawing a security conclusion.');
    } else empty(severityCard, summary.severity.reason);
    grid.append(severityCard);
    const statusCard = panel('Module execution status', 'Completion describes execution of scoped checks. Error and inconclusive outcomes remain visible.');
    if (summary.statuses.available) {
      const stack = node('div', undefined, 'analytics-status-stack');
      stack.setAttribute('aria-hidden', 'true');
      STATUSES.forEach(status => {
        const amount = summary.statuses.counts[status];
        if (amount) {
          const slice = node('span', undefined, `analytics-${status.toLowerCase()}`);
          slice.style.width = `${amount / summary.statuses.total * 100}%`;
          stack.append(slice);
        }
        const row = node('div', undefined, 'analytics-status-row');
        row.append(node('span', status, `analytics-status-label analytics-label-${status.toLowerCase()}`), node('strong', String(amount)));
        statusCard.append(row);
      });
      statusCard.append(stack);
    } else empty(statusCard, summary.statuses.reason);
    grid.append(statusCard);
    content.append(grid);
    if (summary.modules.length) {
      const modulesCard = panel('Coverage by module', 'Counts and reasons are also available in this table. Bars show evaluated checks within each module.');
      const wrapper = node('div', undefined, 'analytics-table-scroll');
      wrapper.tabIndex = 0;
      wrapper.setAttribute('role', 'region');
      wrapper.setAttribute('aria-label', 'Module coverage table, scroll horizontally when needed');
      const table = node('table', undefined, 'analytics-module-table');
      table.append(node('caption', 'Recorded module coverage, scope and execution reasons'));
      const head = node('thead');
      const headers = node('tr');
      ['Module', 'Status', 'Assessment scope', 'Evaluated / selected', 'Unevaluated', 'Reason'].forEach(text => {
        const th = node('th', text);
        th.setAttribute('scope', 'col');
        headers.append(th);
      });
      head.append(headers);
      table.append(head);
      const body = node('tbody');
      summary.modules.forEach(item => {
        const row = node('tr');
        const name = node('th');
        name.append(node('strong', item.name), node('code', item.id, 'analytics-module-id'));
        name.setAttribute('scope', 'row');
        row.append(name, node('td', item.status), node('td', scopeLabel(item.scope)));
        const counts = node('td');
        counts.append(node('span', item.coverage.available ? `${item.coverage.evaluated} / ${item.coverage.selected}` : 'Unavailable'));
        if (item.coverage.available) meter(counts, item.coverage.evaluated, item.coverage.selected, 'evaluated');
        row.append(counts, node('td', item.coverage.available ? String(item.coverage.remaining) : 'Unavailable'),
          node('td', [item.reason, item.coverage.reason].filter(Boolean).join(' ') || 'No reason recorded.'));
        body.append(row);
      });
      table.append(body);
      wrapper.append(table);
      modulesCard.append(wrapper);
      content.append(modulesCard);
    }
    content.append(node('p', 'These charts describe recorded observations. Coverage and finding counts do not measure attack success, detector accuracy or an agent’s overall security.', 'analytics-footnote'));
    container.replaceChildren(content);
    return summary;
  }

  const api = { summarize, render };
  root.AgentScanAnalytics = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window === 'undefined' ? globalThis : window);
