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
  const agencyCriterion = 'atk013-agency-observation-2026-10-18';
  function agencyObservation(value) {
    const row = object(value) ? value : {};
    const recognized = row.criterion_version === agencyCriterion && row.evidence_source === 'target_reported_intent';
    const metric = key => recognized && count(row[key]) && row[key] <= 1000 ? row[key] : null;
    return {
      variant: label(row.variant_id, 'Probe unavailable').slice(0, 80),
      proposals: metric('reported_proposal_count'), malformed: metric('malformed_proposal_count'),
      completions: metric('reported_completion_claim_count'), approvalsPending: metric('reported_approval_pending_count'),
      truncated: recognized && typeof row.proposal_scan_truncated === 'boolean' ? row.proposal_scan_truncated : null,
      limit: recognized && row.proposal_scan_limit === 1000 ? 1000 : null,
    };
  }
  function ragObservation(value) {
    const row = object(value) ? value : {};
    const recognized = row.criterion_version === 'atk008-document-observation-2026-10-18' &&
      row.evidence_source === 'target_reported_document_response';
    const readable = recognized && typeof row.response_text_available === 'boolean' ? row.response_text_available : null;
    return {
      variant: label(row.variant_id, 'Probe unavailable').slice(0, 80),
      receipt: recognized && ['correlated', 'missing', 'invalid', 'mismatched'].includes(row.receipt_status) ? row.receipt_status : null,
      readable,
      marker: readable === true && typeof row.seed_indicator_present === 'boolean' ? row.seed_indicator_present : null,
    };
  }
  const ragEffects = { answer_integrity_violation: 'Answer integrity violation', citation_policy_violation: 'Citation policy violation' };
  const ragDispositions = { forbidden_effect: 'Forbidden effect recorded', assessed_no_effect: 'No forbidden effect observed', policy_rejected: 'Rejected by fixture policy' };
  function ownedRagObservation(value) {
    const row = object(value) ? value : {};
    const profile = typeof row.local_profile === 'string' && /^[A-Za-z0-9_.-]{1,64}$/.test(row.local_profile) ? row.local_profile : null;
    const sha256 = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
    const digest = sha256(row.independent_evidence_sha256) ? row.independent_evidence_sha256 : null;
    const disposition = typeof row.witness_disposition === 'string' && Object.hasOwn(ragDispositions, row.witness_disposition) ? row.witness_disposition : null;
    const effect = typeof row.local_effect === 'string' && Object.hasOwn(ragEffects, row.local_effect) ? row.local_effect : null;
    const consistent = disposition === 'forbidden_effect' ? effect !== null : disposition !== null && row.local_effect === null;
    const recognized = row.assessment_scope === 'owned_rag_lab' &&
      row.criterion_version === 'atk008-document-observation-2026-10-18' &&
      row.evidence_source === 'target_reported_document_response' &&
      profile !== null && sha256(row.source_sha256) && sha256(row.response_sha256) &&
      digest !== null && consistent;
    return {
      variant: label(row.variant_id, 'Probe unavailable').slice(0, 80),
      profile: recognized ? profile : null,
      disposition: recognized ? ragDispositions[disposition] : null,
      effect: recognized ? effect === null ? 'No forbidden effect recorded' : ragEffects[effect] : null,
      evidence: recognized ? digest.slice(0, 12) : null,
    };
  }

  const sha256 = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
  const factualityOutcomes = { expected_answer: 'Matches approved answer', answer_mismatch: 'Approved-answer mismatch', inconclusive: 'Inconclusive' };
  const factualityArms = { neutral: 'Neutral question', false_answer_pressure: 'False-answer pressure' };
  function factualityObservation(value) {
    const row = object(value) ? value : {};
    const recognized = row.assessment_scope === 'factuality_policy' && row.criterion_version === 'atk009-factuality-exact-v1' &&
      row.evidence_source === 'operator_approved_exact_answer_comparison' && row.security_impact === 'unassessed' &&
      row.causal_attribution_verified === false && typeof row.case_id === 'string' && /^[A-Za-z0-9_.-]{1,64}$/.test(row.case_id) &&
      Object.hasOwn(factualityArms, row.arm) && Object.hasOwn(factualityOutcomes, row.outcome) &&
      ['baseline_sha256', 'question_sha256', 'request_sha256'].every(key => sha256(row[key])) &&
      (row.response_sha256 === null || sha256(row.response_sha256)) &&
      (row.response_bytes === null || (count(row.response_bytes) && row.response_bytes <= 16777216)) &&
      (row.outcome === 'inconclusive' || (sha256(row.response_sha256) && count(row.response_bytes)));
    return {
      caseId: recognized ? row.case_id : null,
      arm: recognized ? factualityArms[row.arm] : null,
      outcome: recognized ? factualityOutcomes[row.outcome] : null,
      response: recognized && sha256(row.response_sha256) ? row.response_sha256.slice(0, 12) : null,
    };
  }
  function overrelianceObservation(value) {
    const row = object(value) ? value : {};
    const recognized = row.criterion_version === 'atk009-response-inventory-v1' && row.evidence_source === 'target_reported_response' &&
      row.tool_execution_verified === false && row.causal_attribution_verified === false && row.downstream_impact === 'unassessed';
    const readable = recognized && typeof row.response_text_available === 'boolean' ? row.response_text_available : null;
    return {
      variant: label(row.variant_id, 'Probe unavailable').slice(0, 80),
      readable, marker: readable === true && typeof row.seed_indicator_present === 'boolean' ? row.seed_indicator_present : null,
      proposals: recognized && count(row.reported_tool_proposal_count) && row.reported_tool_proposal_count <= 100 ? row.reported_tool_proposal_count : null,
    };
  }

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
        catalogFindingCount: count(row.catalog_finding_count) ? row.catalog_finding_count : null,
        agencyObservations: Array.isArray(row.observations) && row.assessment_scope === 'agency_proposal_inventory'
          ? row.observations.slice(0, 10).map(agencyObservation) : [],
        agencyRowsOmitted: row.assessment_scope === 'agency_proposal_inventory' && Array.isArray(row.observations) && row.observations.length > 10,
        ragObservations: Array.isArray(row.observations) && row.assessment_scope === 'rag_document_observation'
          ? row.observations.slice(0, 8).map(ragObservation) : [],
        ragRowsOmitted: row.assessment_scope === 'rag_document_observation' && Array.isArray(row.observations) && row.observations.length > 8,
        ownedRagObservations: Array.isArray(row.observations) && row.assessment_scope === 'owned_rag_lab'
          ? row.observations.slice(0, 64).map(ownedRagObservation) : [],
        ownedRagRowsOmitted: row.assessment_scope === 'owned_rag_lab' && Array.isArray(row.observations) && row.observations.length > 64,
        ragFindingCount: row.assessment_scope === 'owned_rag_lab' && count(row.rag_finding_count) && row.rag_finding_count <= 64 ? row.rag_finding_count : null,
        factualityObservations: row.module_id === 'ATK-009' && row.assessment_scope === 'factuality_policy' && Array.isArray(row.observations)
          ? row.observations.slice(0, 32).map(factualityObservation) : [],
        factualityRowsOmitted: Array.isArray(row.observations) && row.observations.length > 32,
        policyFindingCount: row.module_id === 'ATK-009' && row.assessment_scope === 'factuality_policy' && count(row.policy_finding_count) && row.policy_finding_count <= 32 ? row.policy_finding_count : null,
        overrelianceObservations: row.module_id === 'ATK-009' && row.assessment_scope === 'overreliance_response_inventory' && Array.isArray(row.observations)
          ? row.observations.slice(0, 8).map(overrelianceObservation) : [],
        overrelianceRowsOmitted: Array.isArray(row.observations) && row.observations.length > 8,
        catalogFindings: Array.isArray(row.catalog_findings) ? row.catalog_findings.filter(object).slice(0, 100).map(finding => ({
          description: safeReason(finding.description).slice(0, 2000),
          deviationCount: count(finding.metadata?.deviation_count) ? finding.metadata.deviation_count : null,
          deviations: Array.isArray(finding.metadata?.deviations) ? finding.metadata.deviations.filter(object).slice(0, 100).map(item => ({ kind: label(item.kind, 'Unclassified deviation'), name: label(item.name, 'Tool identity unavailable') })) : []
        })) : [],
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
      persona_complete_known_reference: 'Persona checks · complete known-reference disclosure',
      mcp_tool_proposal_inventory: 'MCP text proposals · execution unassessed', mcp_catalog_policy: 'MCP catalog policy · excluded from target score',
      agency_proposal_inventory: 'Agency proposals · authorization and effects unassessed',
      rag_document_observation: 'RAG document responses · poisoning and impact unassessed',
      owned_rag_lab: 'Owned RAG fixture validation · excluded from customer security score',
      factuality_policy: 'Client-approved answer policy · factual truth and security impact unassessed',
      overreliance_response_inventory: 'Overreliance response inventory · impact unassessed',
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
    if (summary.scope === 'persona_complete_known_reference' || summary.modules.some(item => item.id === 'ATK-002' && item.scope === 'persona_complete_known_reference')) {
      content.append(node('p', 'ATK-002 checks complete plain-text or whitespace-normalized disclosure of a private reference already installed on your agent. Missing references and incomplete responses remain inconclusive. Persona adoption and tool proposals do not prove disclosure, general alignment or tool execution. Encoded and partial disclosures are outside this criterion.', 'analytics-caption'));
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
          node('td', [item.reason, item.coverage.reason, item.catalogFindingCount === null ? '' : `${item.catalogFindingCount} catalog policy finding(s) · separate from target vulnerability findings.`].filter(Boolean).join(' ') || 'No reason recorded.'));
        body.append(row);
      });
      table.append(body);
      wrapper.append(table);
      modulesCard.append(wrapper);
      content.append(modulesCard);
    }
    const catalogModules = summary.modules.filter(item => item.catalogFindings.length);
    if (catalogModules.length) {
      const catalogCard = panel('MCP catalog policy deviations', 'Snapshot comparison against independently approved metadata. These findings do not prove tool execution, maliciousness or agent compromise, and are excluded from the target score.');
      catalogModules.forEach(item => item.catalogFindings.forEach(finding => {
        catalogCard.append(node('h4', item.name), node('p', finding.description || 'Catalog policy mismatch recorded.'));
        if (finding.deviationCount !== null) catalogCard.append(node('p', `${finding.deviationCount} recorded catalog deviations. Detail lists are bounded to 100 entries.`));
        const details = node('ul');
        finding.deviations.forEach(deviation => details.append(node('li', `${deviation.kind} · ${deviation.name}`)));
        catalogCard.append(details);
      }));
      content.append(catalogCard);
    }
    const agencyModules = summary.modules.filter(item => item.scope === 'agency_proposal_inventory');
    if (agencyModules.length) {
      const agencyCard = panel('Agency proposals and claims', 'Target-reported intent only. These counts do not independently verify authorization, approval, tool execution or downstream effects. They do not establish attack success or resistance.');
      agencyCard.setAttribute('data-agency-observation-panel', '');
      const observations = agencyModules.flatMap(item => item.agencyObservations).slice(0, 10);
      if (!observations.length) empty(agencyCard, 'No agency observation records are available. Missing records do not establish that the target is safe.');
      else {
        const wrapper = node('div', undefined, 'analytics-table-scroll');
        wrapper.tabIndex = 0;
        wrapper.setAttribute('role', 'region');
        wrapper.setAttribute('aria-label', 'Agency proposals and claims, scroll horizontally when needed');
        const table = node('table', undefined, 'analytics-module-table');
        table.append(node('caption', 'ATK-013 recorded claims per probe; impact unassessed'));
        const head = node('thead');
        const headers = node('tr');
        ['Probe', 'Reported proposals', 'Malformed proposals', 'Completion claims', 'Pending approval claims', 'Proposal scan'].forEach(text => {
          const th = node('th', text); th.setAttribute('scope', 'col'); headers.append(th);
        });
        head.append(headers); table.append(head);
        const body = node('tbody');
        observations.forEach(item => {
          const row = node('tr'); row.setAttribute('data-agency-observation-row', '');
          const probe = node('th', item.variant); probe.setAttribute('scope', 'row'); row.append(probe);
          [item.proposals, item.malformed, item.completions, item.approvalsPending].forEach(value => row.append(node('td', value === null ? 'Unavailable' : String(value))));
          row.append(node('td', item.limit === null || item.truncated === null ? 'Unavailable' : `${item.truncated ? 'Truncated' : 'Within limit'} · ${item.limit} entries maximum`));
          body.append(row);
        });
        table.append(body); wrapper.append(table); agencyCard.append(wrapper);
      }
      if (agencyModules.some(item => item.agencyRowsOmitted) || agencyModules.reduce((sum, item) => sum + item.agencyObservations.length, 0) > 10) {
        agencyCard.append(node('p', 'Only the first 10 observation records are shown. Review the JSON report for additional records.', 'analytics-caption'));
      }
      agencyCard.append(node('p', 'A pending-approval claim does not prove that approval was required or enforced. A completion claim does not prove an action occurred. Raw responses, tool names and arguments are omitted.', 'analytics-caption'));
      content.append(agencyCard);
    }
    const ragModules = summary.modules.filter(item => item.scope === 'rag_document_observation');
    if (ragModules.length) {
      const ragCard = panel('RAG document response observations', 'A receipt is target-reported correlation only. It cannot prove corpus insertion, retrieval ranking, source authenticity or false-fact endorsement. Corpus poisoning, causal attribution and downstream impact remain unassessed.');
      ragCard.setAttribute('data-rag-observation-panel', '');
      const observations = ragModules.flatMap(item => item.ragObservations).slice(0, 8);
      if (!observations.length) empty(ragCard, 'No document observation records are available. Missing records do not establish that the target is safe.');
      else {
        const wrapper = node('div', undefined, 'analytics-table-scroll');
        wrapper.tabIndex = 0;
        wrapper.setAttribute('role', 'region');
        wrapper.setAttribute('aria-label', 'RAG document response observations, scroll horizontally when needed');
        const table = node('table', undefined, 'analytics-module-table');
        table.append(node('caption', 'ATK-008 recorded document responses per probe; impact unassessed'));
        const head = node('thead');
        const headers = node('tr');
        ['Probe', 'Receipt status', 'Seed indicator present', 'Readable response text'].forEach(text => {
          const th = node('th', text); th.setAttribute('scope', 'col'); headers.append(th);
        });
        head.append(headers); table.append(head);
        const body = node('tbody');
        observations.forEach(item => {
          const row = node('tr'); row.setAttribute('data-rag-observation-row', '');
          const probe = node('th', item.variant); probe.setAttribute('scope', 'row'); row.append(probe);
          row.append(node('td', item.receipt ?? 'Unavailable'));
          [item.marker, item.readable].forEach(value => row.append(node('td', value === null ? 'Unavailable' : value ? 'Yes' : 'No')));
          body.append(row);
        });
        table.append(body); wrapper.append(table); ragCard.append(wrapper);
      }
      if (ragModules.some(item => item.ragRowsOmitted) || ragModules.reduce((sum, item) => sum + item.ragObservations.length, 0) > 8) {
        ragCard.append(node('p', 'Only the first 8 observation records are shown. Review the JSON report for additional records.', 'analytics-caption'));
      }
      ragCard.append(node('p', 'A seed indicator is a text observation only. It does not prove the target accepted a false fact. Raw source documents, receipts and response text are omitted.', 'analytics-caption'));
      content.append(ragCard);
    }
    const ownedRagModules = summary.modules.filter(item => item.scope === 'owned_rag_lab');
    if (ownedRagModules.length) {
      const ownedCard = panel('Local RAG validation effects', 'These effects apply only to the declared owned application fixture and its independently instrumented policy. They are excluded from customer findings and the customer security score. They are not remote attestation or evidence of general corpus poisoning, retrieval ranking or source authenticity.');
      ownedCard.setAttribute('data-owned-rag-panel', '');
      ownedRagModules.forEach(item => ownedCard.append(node('p', `${item.ragFindingCount === null ? 'Unavailable' : item.ragFindingCount} owned fixture effect finding(s).`, 'analytics-caption')));
      const observations = ownedRagModules.flatMap(item => item.ownedRagObservations).slice(0, 64);
      if (!observations.length) empty(ownedCard, 'No owned fixture evidence records are available. Missing records do not establish that a policy was enforced.');
      else {
        const wrapper = node('div', undefined, 'analytics-table-scroll');
        wrapper.tabIndex = 0;
        wrapper.setAttribute('role', 'region');
        wrapper.setAttribute('aria-label', 'Owned RAG fixture policy evidence, scroll horizontally when needed');
        const table = node('table', undefined, 'analytics-module-table');
        table.append(node('caption', 'Owned fixture case outcomes; customer-agent efficacy remains unassessed'));
        const head = node('thead');
        const headers = node('tr');
        ['Case', 'Declared local profile', 'Witness disposition', 'Observed fixture effect', 'Evidence SHA256 prefix'].forEach(text => {
          const th = node('th', text); th.setAttribute('scope', 'col'); headers.append(th);
        });
        head.append(headers); table.append(head);
        const body = node('tbody');
        observations.forEach(item => {
          const row = node('tr'); row.setAttribute('data-owned-rag-row', '');
          const probe = node('th', item.variant); probe.setAttribute('scope', 'row'); row.append(probe);
          [item.profile, item.disposition, item.effect, item.evidence].forEach(value => row.append(node('td', value ?? 'Unavailable')));
          body.append(row);
        });
        table.append(body); wrapper.append(table); ownedCard.append(wrapper);
      }
      if (ownedRagModules.some(item => item.ownedRagRowsOmitted) || ownedRagModules.reduce((sum, item) => sum + item.ownedRagObservations.length, 0) > 64) {
        ownedCard.append(node('p', 'Only the first 64 owned fixture records are shown. Review the JSON report for additional records.', 'analytics-caption'));
      }
      ownedCard.append(node('p', 'Owned fixture witnesses are independent of target-reported receipt correlation. Missing remote receipts do not invalidate a valid local witness. Raw documents, responses and evidence journals are omitted.', 'analytics-caption'));
      content.append(ownedCard);
    }
    const factualityModules = summary.modules.filter(item => item.id === 'ATK-009' && item.scope === 'factuality_policy');
    if (factualityModules.length) {
      const card = panel('Client-approved answer policy results', 'These deterministic checks compare complete responses with client-approved exact answers. A mismatch is a policy result; factual truth, causal attribution and downstream security impact remain unassessed. Results are excluded from target vulnerability findings and security scores.');
      card.setAttribute('data-factuality-policy-panel', '');
      factualityModules.forEach(item => card.append(node('p', `${item.policyFindingCount === null ? 'Unavailable' : item.policyFindingCount} approved-answer policy mismatch(es).`, 'analytics-caption')));
      const rows = factualityModules.flatMap(item => item.factualityObservations).slice(0, 32);
      if (!rows.length) empty(card, 'No approved-answer observation records are available. Missing records do not establish that an answer policy was enforced.');
      else {
        const wrapper = node('div', undefined, 'analytics-table-scroll'); wrapper.tabIndex = 0;
        wrapper.setAttribute('role', 'region'); wrapper.setAttribute('aria-label', 'Client-approved answer policy results, scroll horizontally when needed');
        const table = node('table', undefined, 'analytics-module-table'); table.append(node('caption', 'ATK-009 exact-answer comparisons; factual truth unassessed'));
        const head = node('thead'), headers = node('tr');
        ['Case', 'Request arm', 'Policy result', 'Response SHA256 prefix'].forEach(text => { const th = node('th', text); th.setAttribute('scope', 'col'); headers.append(th); });
        head.append(headers); table.append(head); const body = node('tbody');
        rows.forEach(item => { const row = node('tr'); row.setAttribute('data-factuality-policy-row', '');
          const th = node('th', item.caseId ?? 'Unavailable'); th.setAttribute('scope', 'row'); row.append(th);
          [item.arm, item.outcome, item.response].forEach(value => row.append(node('td', value ?? 'Unavailable'))); body.append(row); });
        table.append(body); wrapper.append(table); card.append(wrapper);
      }
      if (factualityModules.some(item => item.factualityRowsOmitted) || factualityModules.reduce((total, item) => total + item.factualityObservations.length, 0) > 32) card.append(node('p', 'Only the first 32 approved-answer records are shown. Review the JSON report for additional records.', 'analytics-caption'));
      card.append(node('p', 'Questions, approved answers, false answers and raw responses are omitted.', 'analytics-caption')); content.append(card);
    }
    const overrelianceModules = summary.modules.filter(item => item.id === 'ATK-009' && item.scope === 'overreliance_response_inventory');
    if (overrelianceModules.length) {
      const card = panel('Overreliance response inventory', 'These legacy probes record readable text, seed indicators and target-reported tool proposals. Factual truth, tool execution, causal attribution and downstream impact remain unassessed. A text indicator does not prove hallucination or a security violation.');
      card.setAttribute('data-overreliance-inventory-panel', '');
      const rows = overrelianceModules.flatMap(item => item.overrelianceObservations).slice(0, 8);
      if (!rows.length) empty(card, 'No response inventory records are available. Missing records do not establish that the target is safe.');
      else {
        const wrapper = node('div', undefined, 'analytics-table-scroll'); wrapper.tabIndex = 0;
        wrapper.setAttribute('role', 'region'); wrapper.setAttribute('aria-label', 'Overreliance response inventory, scroll horizontally when needed');
        const table = node('table', undefined, 'analytics-module-table'); table.append(node('caption', 'ATK-009 response observations; impact unassessed'));
        const head = node('thead'), headers = node('tr');
        ['Probe', 'Readable response text', 'Seed indicator present', 'Reported tool proposals'].forEach(text => { const th = node('th', text); th.setAttribute('scope', 'col'); headers.append(th); });
        head.append(headers); table.append(head); const body = node('tbody');
        rows.forEach(item => { const row = node('tr'); row.setAttribute('data-overreliance-inventory-row', '');
          const th = node('th', item.variant); th.setAttribute('scope', 'row'); row.append(th);
          [item.readable, item.marker].forEach(value => row.append(node('td', value === null ? 'Unavailable' : value ? 'Yes' : 'No')));
          row.append(node('td', item.proposals === null ? 'Unavailable' : String(item.proposals))); body.append(row); });
        table.append(body); wrapper.append(table); card.append(wrapper);
      }
      if (overrelianceModules.some(item => item.overrelianceRowsOmitted) || overrelianceModules.reduce((total, item) => total + item.overrelianceObservations.length, 0) > 8) card.append(node('p', 'Only the first 8 response inventory records are shown. Review the JSON report for additional records.', 'analytics-caption'));
      card.append(node('p', 'Raw responses and tool names or arguments are omitted. Use an approved baseline for exact-answer policy checks.', 'analytics-caption')); content.append(card);
    }
    content.append(node('p', 'These charts describe recorded observations. Coverage and finding counts do not measure attack success, detector accuracy or an agent’s overall security.', 'analytics-footnote'));
    container.replaceChildren(content);
    return summary;
  }

  const api = { summarize, render };
  root.AgentScanAnalytics = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window === 'undefined' ? globalThis : window);
