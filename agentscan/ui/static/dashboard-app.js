
    /* ========================================================
       APPLICATION STATE & TELEMETRY
       ======================================================== */
    let globalTelemetry = {
      report: null,
      identity: null,
      rbac: null,
      trajectory: null,
      traffic: null,
      compliance: null,
      heal: null,
      attacks: null,
      guardrails: null,
      swarms: null,
      certificate: null,
      sentinel: null,
      mcp: null,
      findings: []
    };

    let activeFilterSeverity = 'ALL';
    let activeAttackMode = 'ALL';
    let rbacEscalationFocus = false;

    /* Pagination state variables */
    let trajectoryCurrentPage = 1;
    const TRAJECTORY_PAGE_SIZE = 8;
    let trafficCurrentPage = 1;
    const TRAFFIC_PAGE_SIZE = 12;

    /* Active scan tracking timer */
    let scanPollTimer = null;
    let rawDependencyGraph = null;

    function escapeHtml(str) {
      return DashboardSemantics.escape(str);
    }

    /* Modern Toast Notification Helper */
    function showToast(message) {
      let t = document.getElementById('toast-notification');
      if (!t) {
        t = document.createElement('div');
        t.id = 'toast-notification';
        t.className = 'fixed bottom-6 right-6 z-50 px-5 py-3.5 rounded-2xl bg-[#1A1A1A] text-white text-xs font-bold shadow-2xl flex items-center gap-3 transition-all duration-300 transform translate-y-12 opacity-0 pointer-events-none border border-white/10';
        document.body.appendChild(t);
      }
      t.innerHTML = `
        <span class="w-2 h-2 rounded-full bg-[#1E655C]"></span>
        <span>${escapeHtml(message)}</span>
      `;
      t.classList.remove('translate-y-12', 'opacity-0', 'pointer-events-none');
      setTimeout(() => {
        t.classList.add('translate-y-12', 'opacity-0', 'pointer-events-none');
      }, 3200);
    }

    /* Modal Handlers */
    function openProfileModal() {
      const m = document.getElementById('modal-profile');
      if (m) m.classList.remove('hidden');
      const framesEl = document.getElementById('profile-telemetry-frames');
      if (framesEl && globalTelemetry.traffic && Array.isArray(globalTelemetry.traffic.entries)) {
        framesEl.innerText = `${globalTelemetry.traffic.entries.length} Telemetry Frames`;
      }
    }

    function closeProfileModal() {
      const m = document.getElementById('modal-profile');
      if (m) m.classList.add('hidden');
    }

    function openFindingInspector(cveId) {
      const f = (globalTelemetry.findings || []).find(item => item.cve === cveId || item.id === cveId || item.attack_id === cveId);
      if (!f) return;

      const m = document.getElementById('modal-finding-inspector');
      if (!m) return;

      const attackId = f.attack_id || f.id || f.cve || 'finding';
      const fnEl = document.getElementById('inspector-title');
      if (fnEl) fnEl.innerText = f.title || attackId;
      const fpEl = document.getElementById('inspector-location');
      const targetPath = f.location || f.file || (f.metadata && f.metadata.target) || attackId;
      if (fpEl) fpEl.innerText = targetPath;
      const sevEl = document.getElementById('inspector-severity');
      if (sevEl) { sevEl.innerText = f.severity; sevEl.className = DashboardSemantics.severityClass(f.severity); }
      const patchStatus = document.getElementById('inspector-patch-status');
      if (patchStatus) patchStatus.textContent = f.remediation ? 'Guidance available' : 'No plan recorded';
      const agEl = document.getElementById('inspector-agent');
      if (agEl) agEl.innerText = f.agent || (f.metadata && f.metadata.target_agent) || 'Security Auditor';
      const categoryEl = document.getElementById('inspector-category');
      if (categoryEl) categoryEl.innerText = f.category || 'Not specified';
      const descEl = document.getElementById('inspector-desc');
      if (descEl) descEl.innerText = f.description || f.title || '';

      const payloadEl = document.getElementById('inspector-payload');
      if (payloadEl) {
        const codeEl = payloadEl.querySelector('code') || payloadEl;
        codeEl.innerText = f.payload || 'No request payload recorded.';
      }

      const evidenceEl = document.getElementById('inspector-evidence');
      if (evidenceEl) evidenceEl.innerText = f.evidence || 'No response evidence recorded.';

      const patchEl = document.getElementById('inspector-patch');
      if (patchEl) {
        const codeEl = patchEl.querySelector('code') || patchEl;
        if (f.remediation) {
          codeEl.innerText = f.remediation;
        } else {
          codeEl.innerText = 'No remediation guidance recorded.';
        }
      }

      m.classList.remove('hidden');
    }

    function closeFindingInspector() {
      const m = document.getElementById('modal-finding-inspector');
      if (m) m.classList.add('hidden');
    }

    /* Sidebar Collapse & Mobile Handlers */
    function toggleSidebar() {
      const sb = document.getElementById('sidebar');
      const icon = document.getElementById('sidebar-toggle-icon');
      if (!sb) return;
      const isCollapsed = sb.classList.toggle('sidebar-collapsed');
      if (icon) {
        icon.style.transform = isCollapsed ? 'rotate(180deg)' : 'rotate(0deg)';
      }
    }

    function handleSidebarToggleBtn() {
      if (window.innerWidth < 1024) {
        toggleSidebarMobile(false);
      } else {
        toggleSidebar();
      }
    }

    function toggleSidebarMobile(forceState) {
      const sb = document.getElementById('sidebar');
      const backdrop = document.getElementById('sidebar-backdrop');
      if (!sb) return;
      const isOpen = forceState !== undefined ? forceState : !sb.classList.contains('mobile-open');
      if (isOpen) {
        sb.classList.add('mobile-open');
        if (backdrop) backdrop.classList.remove('hidden');
      } else {
        sb.classList.remove('mobile-open');
        if (backdrop) backdrop.classList.add('hidden');
      }
    }

    /* Navbar More Options Dropdown Handler */
    function toggleNavbarMoreMenu(forceState) {
      const dd = document.getElementById('navbar-more-dropdown');
      if (!dd) return;
      if (forceState !== undefined) {
        if (forceState) dd.classList.remove('hidden');
        else dd.classList.add('hidden');
      } else {
        dd.classList.toggle('hidden');
      }
    }

    document.addEventListener('click', function (e) {
      const container = document.getElementById('navbar-more-container');
      const dd = document.getElementById('navbar-more-dropdown');
      if (container && dd && !container.contains(e.target)) {
        dd.classList.add('hidden');
      }
    });

    function handleBrandClick() {
      const sb = document.getElementById('sidebar');
      if (sb && sb.classList.contains('sidebar-collapsed')) {
        toggleSidebar();
      }
      switchTab('overview');
      toggleSidebarMobile(false);
    }

    /* Toggle Grid vs Table View */
    function toggleFindingsView(viewType) {
      const grid = document.getElementById('findings-grid');
      const table = document.getElementById('findings-table');
      const btnGrid = document.getElementById('btn-view-grid');
      const btnTable = document.getElementById('btn-view-table');

      if (viewType === 'grid') {
        if (grid) grid.classList.remove('hidden');
        if (table) table.classList.add('hidden');
        if (btnGrid) { btnGrid.setAttribute('aria-pressed', String(viewType === 'grid')); btnGrid.className = 'px-3 py-1.5 rounded-full text-xs font-bold border bg-[#1A1A1A] text-white cursor-pointer transition-all'; }
        if (btnTable) { btnTable.setAttribute('aria-pressed', String(viewType === 'table')); btnTable.className = 'px-3 py-1.5 rounded-full text-xs font-bold border bg-white text-[#1A1A1A] border-[#1A1A1A]/10 hover:bg-[#F7F5EE] cursor-pointer transition-all'; }
      } else {
        if (grid) grid.classList.add('hidden');
        if (table) table.classList.remove('hidden');
        if (btnTable) { btnTable.setAttribute('aria-pressed', String(viewType === 'table')); btnTable.className = 'px-3 py-1.5 rounded-full text-xs font-bold border bg-[#1A1A1A] text-white cursor-pointer transition-all'; }
        if (btnGrid) { btnGrid.setAttribute('aria-pressed', String(viewType === 'grid')); btnGrid.className = 'px-3 py-1.5 rounded-full text-xs font-bold border bg-white text-[#1A1A1A] border-[#1A1A1A]/10 hover:bg-[#F7F5EE] cursor-pointer transition-all'; }
      }
    }

    async function downloadReportJson() {
      if (!globalTelemetry.report || globalTelemetry.report.error) {
        showToast('Load or run an assessment before downloading its report.');
        return;
      }
      try {
        const report = await DashboardSemantics.requestJSON('/api/report');
        if (report.error || !report.scan_id) throw new Error('No report available.');
        const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], {type: 'application/json'}));
        const link = document.createElement('a');
        link.href = url;
        link.download = `agentscan-report-${report.scan_id}.json`;
        document.body.appendChild(link);
        link.click();
        link.remove();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
      } catch (error) {
        DashboardSemantics.showLaunchError('dashboard-operation-error', error.message || 'Report download failed.');
        showToast(error.message || 'Report download failed.');
      }
    }

    function copyUnifiedPatch() {
      const patch = (globalTelemetry.heal && globalTelemetry.heal.patch) || '';
      if (patch && navigator.clipboard) {
        navigator.clipboard.writeText(patch).then(() => {
          showToast("Unified diff copied to clipboard");
        }).catch(() => {
          showToast("Patch ready in viewer");
        });
      } else if (patch) {
        showToast("Patch ready in viewer");
      }
    }

    async function handleReload() {
      const btn = document.getElementById('btn-reload');
      if (btn) btn.classList.add('opacity-50', 'pointer-events-none');
      try {
        DashboardSemantics.showLaunchError('dashboard-operation-error', null);
        await DashboardSemantics.requestJSON('/api/reload', { method: 'POST' });
        await loadAllTelemetry();
        await loadFeatureGuide();
        showToast(document.getElementById('dashboard-data-errors').hidden ? 'Telemetry refreshed' : 'Some dashboard data could not refresh. Review the error panel.');
      } catch (err) {
        console.error("Reload error:", err);
        DashboardSemantics.showLaunchError('dashboard-operation-error', err.message);
        showToast('Failed to reload telemetry');
      } finally {
        if (btn) btn.classList.remove('opacity-50', 'pointer-events-none');
      }
    }

    /* Spotlight Search Handlers */
    function closeTopSearch() {
      const drop = document.getElementById('top-search-dropdown');
      if (drop) drop.classList.add('hidden');
    }

    function executeSpotlightSearch(q) {
      const drop = document.getElementById('top-search-dropdown');
      if (!drop) return;
      const query = (q || '').trim().toLowerCase();
      if (!query) {
        drop.classList.add('hidden');
        return;
      }

      const tabs = [
        { name: 'Overview Dashboard', id: 'overview', cat: 'Navigation' },
        { name: 'Findings & evidence', id: 'findings', cat: 'Vulnerabilities' },
        { name: 'Attack Suites (Red-Team)', id: 'pipelines', cat: 'Offensive' },
        { name: 'Zero-Trust RBAC Matrix', id: 'rbac', cat: 'Defensive' },
        { name: 'Live Tool Trajectory', id: 'trajectory', cat: 'Adversarial' },
        { name: 'Network Traffic Inspector', id: 'traffic', cat: 'Runtime' },
        { name: 'Security Gateway Rules', id: 'guardrails', cat: 'Ingress' },
        { name: 'Compliance (EU AI Act & NIST)', id: 'compliance', cat: 'Regulatory' },
        { name: 'Self-Healing Patches', id: 'healing', cat: 'Remediation' },
        { name: 'Configured Agent Team', id: 'team', cat: 'Inventory' },
        { name: 'Continuous Sentinel Monitor', id: 'sentinel', cat: 'Surveillance' },
        { name: 'Native MCP Protocol Monitor', id: 'mcp', cat: 'Protocols' }
      ];

      const matchedTabs = tabs.filter(t => t.name.toLowerCase().includes(query) || t.cat.toLowerCase().includes(query));

      let rawAgents = (globalTelemetry.identity && Array.isArray(globalTelemetry.identity.agents)) ? globalTelemetry.identity.agents : [];
      const matchedAgents = rawAgents.filter(a => {
        const name = a.agent_id || a.name || '';
        const role = a.declared_role || a.role || '';
        return name.toLowerCase().includes(query) || role.toLowerCase().includes(query);
      });

      const matchedFindings = (globalTelemetry.findings || []).filter(f =>
        (f.title && f.title.toLowerCase().includes(query)) ||
        (f.id && f.id.toLowerCase().includes(query)) ||
        (f.cve && f.cve.toLowerCase().includes(query)) ||
        (f.agent && f.agent.toLowerCase().includes(query))
      ).slice(0, 4);

      let html = '';

      if (matchedAgents.length > 0) {
        html += '<div class="px-3 py-1.5 text-[10px] font-extrabold text-[#1E5E54] uppercase tracking-wider">Agents & Personas</div>';
        matchedAgents.forEach(a => {
          html += `
            <div onclick="switchTab('team'); closeTopSearch();" class="px-3 py-2.5 rounded-xl hover:bg-[#EEF6F4] cursor-pointer flex items-center justify-between transition-colors">
              <div>
                <div class="text-xs font-bold text-[#1A1A1A]">${escapeHtml(a.agent_id || a.name)}</div>
                <div class="text-[10px] text-[#666666]">${escapeHtml(a.declared_role || 'Agent Node')}</div>
              </div>
              <span class="text-[10px] font-bold px-2.5 py-0.5 rounded-full bg-[#EEF6F4] text-[#1E5E54] border border-[#CFE5E1]">Manifest Loaded</span>
            </div>
          `;
        });
      }

      if (matchedTabs.length > 0) {
        html += '<div class="px-3 py-1.5 mt-2 text-[10px] font-extrabold text-[#888888] uppercase tracking-wider">Navigation Tabs</div>';
        matchedTabs.forEach(t => {
          const safeTabId = DashboardSemantics.inlineArgument(t.id);
          html += `
            <div onclick="switchTab(${safeTabId}); closeTopSearch();" class="px-3 py-2.5 rounded-xl hover:bg-[#F7F5EE] cursor-pointer flex items-center justify-between transition-colors">
              <span class="text-xs font-bold text-[#1A1A1A]">${escapeHtml(t.name)}</span>
              <span class="text-[10px] font-bold px-2.5 py-0.5 rounded-full bg-white border border-[#1A1A1A]/10 text-[#666666]">${escapeHtml(t.cat)}</span>
            </div>
          `;
        });
      }

      if (matchedFindings.length > 0) {
        html += '<div class="px-3 py-1.5 mt-2 text-[10px] font-extrabold text-[#B84E28] uppercase tracking-wider">Matched findings</div>';
        matchedFindings.forEach(f => {
          const safeCve = DashboardSemantics.inlineArgument(f.cve);
          html += `
            <div onclick="switchTab('findings'); openFindingInspector(${safeCve}); closeTopSearch();" class="px-3 py-2.5 rounded-xl hover:bg-[#FAF0EB] cursor-pointer flex items-center justify-between transition-colors">
              <div>
                <div class="text-xs font-bold text-[#1A1A1A]">${escapeHtml(f.cve)} &bull; ${escapeHtml(f.title || f.id)}</div>
                <div class="text-[10px] font-mono text-[#888888]">${escapeHtml(f.agent || '')}</div>
              </div>
              <span class="text-[10px] font-bold px-2.5 py-0.5 rounded-full bg-[#FAF0EB] text-[#B84E28] border border-[#ECCFC2]">${escapeHtml(f.severity || 'HIGH')}</span>
            </div>
          `;
        });
      }

      if (!html) {
        html = '<div class="px-4 py-4 text-xs text-[#888888] text-center font-medium">No matching findings, agents or tabs found</div>';
      }

      drop.innerHTML = html;
      drop.classList.remove('hidden');
    }

    /* Tab Switcher */
    function getTabFromUrl() {
      const hash = (window.location.hash || '').replace('#', '');
      return hash || 'overview';
    }

    function switchTab(tabId, ev) {
      if (ev) ev.preventDefault();
      window.location.hash = '#' + tabId;

      // Close mobile drawer on navigation
      toggleSidebarMobile(false);

      document.querySelectorAll('.tab-pane').forEach(el => el.classList.remove('active'));
      const activeSection = document.getElementById('tab-' + tabId);
      if (activeSection) activeSection.classList.add('active');

      document.querySelectorAll('.sidebar-nav-item').forEach(el => {
        el.classList.remove('active');
        el.style.removeProperty('background');
        el.style.removeProperty('border-color');
        el.classList.remove('text-[#1A1A1A]', 'font-bold', 'shadow-sm');
        el.classList.add('text-[#666666]');
      });

      const activeNav = document.querySelector(`.sidebar-nav-item[data-tab="${tabId}"]`);
      if (activeNav) {
        activeNav.classList.remove('text-[#666666]');
        activeNav.classList.add('active', 'text-[#1A1A1A]', 'font-bold', 'shadow-sm');
      }
    }

    async function loadFeatureGuide() {
      const content = document.getElementById('feature-guide-content');
      try {
        const manifest = await DashboardSemantics.requestJSON('/api/features');
        const actions = {
          scan: ['openScanModal()', 'Open scan'], audit: ['openAuditModal()', 'Open static audit'],
          pipelines: ["switchTab('pipelines')", 'View attack catalog'], identity: ["switchTab('rbac')", 'View identity'],
          guardrails: ["switchTab('guardrails')", 'View guardrails'], compliance: ["switchTab('compliance')", 'View mappings'],
          heal: ["switchTab('healing')", 'Review remediation'], team: ["switchTab('team')", 'View swarm'],
          sentinel: ['openSentinelModal()', 'Configure Sentinel'], mcp: ['openMcpTestModal()', 'Open MCP'],
          aibom: ['openAibomModal()', 'View AIBOM'], dependency_graph: ['openDependenciesModal()', 'View dependencies']
        };
        const workflows = (manifest.workflows || []).filter(item => item.surface === 'dashboard').map(item => {
          const action = actions[item.action];
          return `<div class="feature-workflow"><span>${escapeHtml(item.label)}</span>${action ? `<button class="btn-pill-light" onclick="${action[0]}">${action[1]} →</button>` : '<span>Unavailable in this dashboard</span>'}</div>`;
        }).join('');
        const terminal = (manifest.workflows || []).filter(item => item.surface === 'terminal').map(item => `<div class="feature-terminal"><strong>${escapeHtml(item.label)}</strong><code>${escapeHtml(item.command)}</code><p>${escapeHtml(item.note || '')}</p></div>`).join('');
        const runtime = (manifest.runtime || []).map(item => `<div class="feature-runtime"><div><strong>${escapeHtml(item.label)}</strong><span class="assessment-badge ${item.installed ? 'status-complete' : 'status-warning'}">${item.installed ? 'Packages present' : 'Setup needed'}</span></div><p>${escapeHtml(item.note || '')}</p>${!item.installed && item.setup_command ? `<code>${escapeHtml(item.setup_command)}</code>` : ''}</div>`).join('');
        const formats = ['json', 'sarif', 'html'];
        content.innerHTML = `<div class="feature-guide-grid"><section><h3>Start a workflow</h3>${workflows}</section><section><h3>Runtime requirements</h3><p>Package availability does not confirm model, Docker, GPU, credentials or service readiness.</p>${runtime}</section><section><h3>Report exports</h3><p>${escapeHtml(manifest.report?.note || 'Export recorded assessment evidence.')}</p><div class="feature-export-actions">${formats.map(format => `<button class="btn-pill-light" onclick="downloadReportFormat('${format}')">${format.toUpperCase()} ↓</button>`).join('')}</div><p>Run or load a report before exporting.</p><h3>Data policy</h3><p>Sensitive assessments use deterministic checks or an offline local model. External model analysis requires a fresh explicit non-sensitive designation and a provider key configured on the scanner.</p><p>${escapeHtml(manifest.analysis_policy?.target_note || '')}</p></section><section><h3>Terminal workflows</h3><p>These configurations require the CLI. Read docs/START_HERE.md for setup and every attack.</p>${terminal}</section></div>`;
      } catch (err) {
        content.textContent = '';
        DashboardSemantics.showLaunchError('feature-guide-content', err.message);
      }
    }

    async function downloadReportFormat(format) {
      DashboardSemantics.showLaunchError('dashboard-operation-error', null);
      try {
        const response = await fetch(`/api/report/download?format=${format}`);
        if (!response.ok) {
          let data;
          try { data = await response.json(); } catch { data = {}; }
          throw new Error(`Dashboard report export: HTTP ${response.status}. ${DashboardSemantics.responseError(data, response.status)}`);
        }
        const blob = await response.blob();
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url; link.download = `agentscan-report.${format === 'sarif' ? 'sarif.json' : format}`;
        document.body.append(link); link.click(); link.remove();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
      } catch (err) {
        DashboardSemantics.showLaunchError('dashboard-operation-error', err.message);
      }
    }

    /* Telemetry Fetcher & Renderers */
    async function loadAllTelemetry() {
      if (!window.featureGuideLoaded) { window.featureGuideLoaded = true; loadFeatureGuide(); }
      try {
        const [repRes, idRes, rbacRes, trajRes, trafRes, compRes, healRes, atkRes, gwRes, swmRes, certRes, sentRes, mcpRes] = await Promise.allSettled([
          DashboardSemantics.requestJSON('/api/report'),
          DashboardSemantics.requestJSON('/api/identity'),
          DashboardSemantics.requestJSON('/api/rbac'),
          DashboardSemantics.requestJSON('/api/trajectory'),
          DashboardSemantics.requestJSON('/api/traffic'),
          DashboardSemantics.requestJSON('/api/compliance'),
          DashboardSemantics.requestJSON('/api/heal'),
          DashboardSemantics.requestJSON('/api/attacks'),
          DashboardSemantics.requestJSON('/api/guardrails'),
          DashboardSemantics.requestJSON('/api/swarms'),
          DashboardSemantics.requestJSON('/api/certificate'),
          DashboardSemantics.requestJSON('/api/sentinel'),
          DashboardSemantics.requestJSON('/api/mcp')
        ]);

        const loads = [repRes, idRes, rbacRes, trajRes, trafRes, compRes, healRes, atkRes, gwRes, swmRes, certRes, sentRes, mcpRes];
        const datasets = ['Report', 'Identity', 'RBAC', 'Trajectory', 'Traffic', 'Compliance', 'Remediation', 'Attack catalog', 'Guardrails', 'Swarms', 'Certificate', 'Sentinel', 'MCP'];
        const failedLoads = loads.flatMap((result, index) => result.status === 'rejected' ? [{ module_name: datasets[index], error: result.reason?.message || 'Dashboard data could not be loaded.' }] : []);
        const dataErrors = document.getElementById('dashboard-data-errors');
        if (dataErrors) {
          dataErrors.hidden = !failedLoads.length;
          dataErrors.innerHTML = failedLoads.length ? DashboardSemantics.assessmentErrorMarkup({ assessment_scope: 'dashboard', module_errors: failedLoads }) : '';
        }
        globalTelemetry.report = repRes.status === 'fulfilled' && repRes.value && !repRes.value.error ? repRes.value : null;
        globalTelemetry.identity = idRes.status === 'fulfilled' && idRes.value ? idRes.value : null;
        globalTelemetry.rbac = rbacRes.status === 'fulfilled' && rbacRes.value ? rbacRes.value : null;
        globalTelemetry.trajectory = trajRes.status === 'fulfilled' && trajRes.value ? trajRes.value : null;
        globalTelemetry.traffic = trafRes.status === 'fulfilled' && trafRes.value ? trafRes.value : null;
        globalTelemetry.compliance = compRes.status === 'fulfilled' && compRes.value ? compRes.value : null;
        globalTelemetry.heal = healRes.status === 'fulfilled' && healRes.value ? healRes.value : null;
        globalTelemetry.attacks = atkRes.status === 'fulfilled' && atkRes.value ? atkRes.value : null;
        globalTelemetry.guardrails = gwRes.status === 'fulfilled' && gwRes.value ? gwRes.value : null;
        globalTelemetry.swarms = swmRes.status === 'fulfilled' && swmRes.value ? swmRes.value : null;
        globalTelemetry.certificate = certRes.status === 'fulfilled' && certRes.value ? certRes.value : null;
        globalTelemetry.sentinel = sentRes.status === 'fulfilled' && sentRes.value ? sentRes.value : null;
        globalTelemetry.mcp = mcpRes.status === 'fulfilled' && mcpRes.value ? mcpRes.value : null;

        let rawFindings = [];
        if (globalTelemetry.report && Array.isArray(globalTelemetry.report.findings)) {
          rawFindings = globalTelemetry.report.findings;
        }

        globalTelemetry.findings = rawFindings.map((record, i) => {
          const f = record && typeof record === 'object' && !Array.isArray(record) ? record : {};
          const attackId = f.attack_id || f.id || `Finding-${i + 1}`;
          const cve = f.cve || `${attackId}:${i + 1}`;
          const agentName = f.agent || f.metadata?.target_agent || globalTelemetry.report?.target_url || 'Not specified';

          return {
            ...f,
            id: cve,
            attack_id: attackId,
            title: f.attack_name || f.title || (Object.keys(f).length ? 'Recorded finding' : 'Unavailable finding record'),
            cve: cve,
            severity: String(f.severity || 'UNCLASSIFIED').toUpperCase(),
            category: f.attack_name || f.category || 'Uncategorized',
            agent: agentName,
            description: f.description || (Object.keys(f).length ? 'No description recorded.' : 'This report contains a malformed finding record. Review the JSON report.'),
            remediation: f.remediation || '',
            payload: f.payload_used || '',
            evidence: f.evidence || '',
            turn: f.turn_number ?? null
          };
        });

        renderOverview();
        renderFindings(activeFilterSeverity);
        renderPipelines();
        renderRbac();
        renderTrajectory();
        renderTraffic();
        renderGuardrails();
        renderSentinel();
        renderMcp();
        renderCompliance();
        renderHealing();
        renderTeam();
        if (window.AgentScanForms) AgentScanForms.attach();

      } catch (err) {
        DashboardSemantics.showLaunchError('dashboard-operation-error', 'Dashboard rendering failed. Reload the page and review the service logs.');
      }
    }

    function renderOverview() {
      DashboardSemantics.renderOverview(globalTelemetry);
    }

    function filterFindings(severity) {
      activeFilterSeverity = severity;
      const suffix = {ALL: 'all', CRITICAL: 'crit', HIGH: 'high', MEDIUM: 'med', LOW: 'low', INFO: 'info', PASS: 'pass'};
      document.querySelectorAll('#severity-filter-group button').forEach(button => {
        const active = button.id === `filter-btn-${suffix[severity]}`;
        button.className = `${active ? 'btn-pill-dark' : 'btn-pill-light'} text-xs shrink-0 whitespace-nowrap`;
        button.setAttribute('aria-pressed', String(active));
      });
      renderFindings(severity);
    }

    function renderFindings(filterSev) {
      const findings = globalTelemetry.findings || [];
      const filters = [['ALL', 'All', 'all'], ['CRITICAL', 'Critical', 'crit'], ['HIGH', 'High', 'high'], ['MEDIUM', 'Medium', 'med'], ['LOW', 'Low', 'low'], ['INFO', 'Info', 'info'], ['PASS', 'Pass', 'pass']];
      filters.forEach(([severity, label, suffix]) => {
        const button = document.getElementById(`filter-btn-${suffix}`);
        const count = severity === 'ALL' ? findings.length : findings.filter(f => f.severity === severity).length;
        if (button) button.textContent = `${label} (${count})`;
      });
      const query = (document.getElementById('findings-search')?.value || '').trim().toLowerCase();
      const list = findings.filter(f => (!filterSev || filterSev === 'ALL' || f.severity === filterSev) &&
        (!query || [f.attack_id, f.title, f.description, f.agent, f.evidence, f.category].some(value => String(value || '').toLowerCase().includes(query))));
      const summary = document.getElementById('findings-summary');
      const assessment = DashboardSemantics.summarize(globalTelemetry.report);
      if (summary) summary.textContent = globalTelemetry.report
        ? `${list.length} of ${findings.length} recorded findings · ${assessment.status} · ${assessment.evaluated ?? 'Unavailable'} / ${assessment.selected ?? 'Unavailable'} checks evaluated`
        : 'No assessment loaded. Run a scan or load a report to collect evidence.';
      const empty = findings.length ? 'No findings match these filters.' : globalTelemetry.report
        ? 'No findings recorded. Review assessment coverage before drawing a security conclusion.'
        : 'Run a scan or load a report to view findings.';
      const grid = document.getElementById('findings-grid');
      if (grid) grid.innerHTML = list.map(f => `
        <article class="finding-card p-5 flex flex-col justify-between gap-4">
          <div>
            <div class="flex items-center justify-between gap-3 mb-4">
              <code class="text-[10px] text-[#666666]">${escapeHtml(f.attack_id)}</code>
              <span class="${DashboardSemantics.severityClass(f.severity)}">${escapeHtml(f.severity)}</span>
            </div>
            <h3 class="text-sm font-extrabold text-[#1A1A1A] leading-relaxed">${escapeHtml(f.title)}</h3>
            <p class="text-xs text-[#666666] mt-2 line-clamp-3 leading-relaxed">${escapeHtml(f.description)}</p>
            <p class="text-[10px] text-[#888888] mt-3 truncate" title="${escapeHtml(f.agent)}">Target: ${escapeHtml(f.agent)}</p>
          </div>
          <div class="pt-4 border-t flex items-center justify-between gap-3" style="border-color: var(--border)">
            <span class="text-[10px] text-[#666666]">${f.remediation ? 'Guidance available' : 'Review evidence'}</span>
            <button onclick="openFindingInspector(${DashboardSemantics.inlineArgument(f.cve)})" class="btn-pill-dark text-xs">Inspect &rarr;</button>
          </div>
        </article>`).join('') || `<div class="col-span-full dl-card p-8 text-center text-xs text-[#666666]">${escapeHtml(empty)}</div>`;
      const tableBody = document.getElementById('findings-table-body');
      if (tableBody) tableBody.innerHTML = list.map(f => `
        <tr class="hover:bg-[#F7F5EE] transition-colors">
          <td class="py-3 px-4 font-mono text-[#666666]">${escapeHtml(f.attack_id)}</td>
          <td class="py-3 px-4 font-bold text-[#1A1A1A]">${escapeHtml(f.title)}</td>
          <td class="py-3 px-4"><span class="${DashboardSemantics.severityClass(f.severity)}">${escapeHtml(f.severity)}</span></td>
          <td class="py-3 px-4 text-[#666666]">${escapeHtml(f.agent)}</td>
          <td class="py-3 px-4"><button onclick="openFindingInspector(${DashboardSemantics.inlineArgument(f.cve)})" class="btn-pill-light text-xs">Inspect</button></td>
        </tr>`).join('') || `<tr><td colspan="5" class="p-6 text-center text-[#666666]">${escapeHtml(empty)}</td></tr>`;
    }

    function filterAttackMode(mode) {
      activeAttackMode = mode;
      const group = document.getElementById('attack-mode-filter-group');
      if (group) {
        group.querySelectorAll('button').forEach(btn => {
          btn.className = 'btn-pill-light text-xs cursor-pointer';
        });
        const activeBtn = document.getElementById(`btn-mode-${mode.toLowerCase()}`);
        if (activeBtn) activeBtn.className = 'btn-pill-dark text-xs cursor-pointer';
      }
      renderPipelines();
    }

    function renderPipelines() {
      const grid = document.getElementById('pipelines-grid');
      if (!grid) return;

      const attacks = (globalTelemetry.attacks && Array.isArray(globalTelemetry.attacks.attacks)) ? globalTelemetry.attacks.attacks : [];
      const catalog = globalTelemetry.attacks;
      const loaded = catalog && Array.isArray(catalog.attacks);
      ['ALL', 'SCAN', 'EXPLOIT', 'DEEP'].forEach(mode => {
        const button = document.getElementById(`btn-mode-${mode.toLowerCase()}`);
        const count = mode === 'ALL' ? attacks.length : attacks.filter(attack => (attack.modes || []).some(value => String(value).toUpperCase() === mode)).length;
        if (button) button.textContent = loaded ? `${mode} (${count})` : mode;
      });
      const catalogSummary = document.getElementById('attack-catalog-summary');
      if (catalogSummary) catalogSummary.textContent = loaded
        ? `${attacks.length} available registered modules. Mode counts overlap because modules can support multiple modes.`
        : 'The attack catalog is unavailable. No installed module count is assumed.';
      let catalogErrors = document.getElementById('attack-catalog-errors');
      if (!catalogErrors && catalogSummary) {
        catalogErrors = document.createElement('div');
        catalogErrors.id = 'attack-catalog-errors';
        catalogSummary.after(catalogErrors);
      }
      if (catalogErrors) catalogErrors.innerHTML = DashboardSemantics.assessmentErrorMarkup({
        status: 'CATALOG', assessment_scope: 'catalog', module_errors: catalog?.load_errors || [], tests_run: 0, tests_selected: 0
      });
      let list = attacks;
      if (activeAttackMode !== 'ALL') {
        list = list.filter(a => {
          const modes = Array.isArray(a.modes) && a.modes.length > 0
            ? a.modes.map(m => String(m).toUpperCase())
            : [(a.mode || a.category || 'SCAN').toUpperCase()];
          return modes.includes(activeAttackMode) || (a.category && a.category.toUpperCase() === activeAttackMode);
        });
      }

      if (list.length === 0) {
        grid.innerHTML = '<div class="col-span-3 p-8 text-center text-xs text-[#888888]">No attacks match the selected mode filter.</div>';
        return;
      }

      let html = '';
      list.forEach(a => {
        const atkId = a.attack_id || a.id || 'ATK';
        const atkName = a.attack_name || a.name || 'Adversarial Probe';
        const owaspId = a.owasp_id || a.owasp_category || 'LLM01';
        const modes = Array.isArray(a.modes) && a.modes.length > 0 ? a.modes : [a.mode || a.category || 'SCAN'];

        const badgesHtml = modes.map(m => {
          const mUpper = String(m).toUpperCase();
          let badgeColor = 'bg-[#FAF0EB] text-[#B84E28] border-[#ECCFC2]';
          if (mUpper === 'EXPLOIT') badgeColor = 'bg-amber-100 text-amber-900 border-amber-200';
          if (mUpper === 'DEEP') badgeColor = 'bg-purple-100 text-purple-900 border-purple-200';
          return `<span class="px-2.5 py-0.5 text-[9px] font-mono font-bold uppercase rounded-full border ${badgeColor}">${escapeHtml(mUpper)}</span>`;
        }).join(' ');

        html += `
          <div class="dl-card p-6 bg-white flex flex-col justify-between" style="border-color: var(--border)">
            <div>
              <div class="flex items-center justify-between text-xs mb-3">
                <span class="font-mono text-[#888888] font-bold">${escapeHtml(atkId)}</span>
                <div class="flex items-center gap-1.5 flex-wrap">
                  ${badgesHtml}
                </div>
              </div>
              <h3 class="text-base font-extrabold text-[#1A1A1A] mb-1.5">${escapeHtml(atkName)}</h3>
              <p class="text-xs text-[#666666] leading-relaxed mb-4">${escapeHtml(a.description || '')}</p>
            </div>

            <div class="pt-3 border-t border-[#1A1A1A]/10 flex items-center justify-between text-xs">
              <span class="font-mono text-[11px] font-bold text-[#1E5E54]">${escapeHtml(owaspId)}</span>
              <button onclick="openScanModal()" class="text-xs font-bold text-[#1A1A1A] hover:underline cursor-pointer">&plus; Target Probe</button>
            </div>
          </div>
        `;
      });
      grid.innerHTML = html;
    }

    function resetRbacGraphZoom() {
      const g = document.getElementById('rbac-svg-viewport');
      if (g) g.setAttribute('transform', 'scale(1) translate(0, 0)');
    }

    function toggleRbacFocus() {
      rbacEscalationFocus = !rbacEscalationFocus;
      const btn = document.getElementById('btn-rbac-focus');
      if (btn) {
        btn.className = rbacEscalationFocus ? 'btn-pill-dark text-xs cursor-pointer' : 'btn-pill-light text-xs cursor-pointer';
      }
      renderRbac();
    }

    function renderRbac() {
      const rbacData = globalTelemetry.rbac;
      if (!rbacData) return;

      const nodes = Array.isArray(rbacData.nodes) ? rbacData.nodes : [];
      const edges = Array.isArray(rbacData.edges) ? rbacData.edges : [];
      const escalations = Array.isArray(rbacData.escalations)
        ? rbacData.escalations
        : (Array.isArray(rbacData.escalation_paths) ? rbacData.escalation_paths : []);

      const statsEl = document.getElementById('rbac-graph-stats');
      if (statsEl) statsEl.innerText = `${nodes.length} Nodes • ${edges.length} Edges • ${escalations.length} Escalations`;

      const bannerEl = document.getElementById('rbac-escalation-banner');
      if (bannerEl) {
        if (escalations.length > 0) {
          bannerEl.innerHTML = `
            <div class="p-4 rounded-2xl bg-[#FAF0EB] border border-[#ECCFC2] text-[#B84E28] flex items-center justify-between">
              <div class="flex items-center gap-3">
                <span class="w-3 h-3 rounded-full bg-[#B84E28] animate-ping"></span>
                <span class="text-xs font-bold font-mono">ID-010 ALERT: ${escalations.length} Multi-Hop Privilege Escalation Path(s) Detected</span>
              </div>
              <span class="text-xs font-bold">Policy Violation</span>
            </div>
          `;
        } else {
          bannerEl.innerHTML = '';
        }
      }

      /* SVG DAG Renderer */
      const svg = document.getElementById('rbac-graph-svg');
      if (svg && nodes.length > 0) {
        let svgContent = '';
        const width = 800;
        const height = Math.max(400, Math.ceil(nodes.length / 4) * 140 + 80);
        svg.setAttribute('viewBox', `0 0 ${width} ${height}`);
        svg.setAttribute('height', height);

        // Position nodes in horizontal tiers
        const positions = {};
        nodes.forEach((n, i) => {
          const x = 80 + (i % 4) * 200;
          const y = 80 + Math.floor(i / 4) * 120;
          positions[n.id] = { x, y, name: n.label || n.id, role: n.role || 'agent' };
        });

        // Render edges
        edges.forEach(e => {
          const src = e.source || e.from;
          const tgt = e.target || e.to;
          const from = positions[src];
          const to = positions[tgt];
          if (from && to) {
            const isEscalation = e.is_escalation || escalations.some(p => {
              if (!p) return false;
              const pathNodes = (p.metadata && Array.isArray(p.metadata.path))
                ? p.metadata.path
                : (Array.isArray(p.path) ? p.path : (Array.isArray(p) ? p : []));
              if (pathNodes.length > 0) {
                return pathNodes.includes(src) && pathNodes.includes(tgt);
              }
              const desc = typeof p === 'string' ? p : (p.description || p.evidence || '');
              return desc.includes(src) && desc.includes(tgt);
            });
            const strokeColor = isEscalation ? '#B84E28' : '#CFE5E1';
            const strokeWidth = isEscalation ? '3' : '1.5';
            const strokeDash = isEscalation ? 'stroke-dasharray="4,4"' : '';
            svgContent += `
              <line x1="${from.x}" y1="${from.y}" x2="${to.x}" y2="${to.y}" stroke="${strokeColor}" stroke-width="${strokeWidth}" ${strokeDash} marker-end="url(#arrow)" />
            `;
          }
        });

        // Render node circles
        nodes.forEach(n => {
          const pos = positions[n.id];
          if (!pos) return;
          const isTarget = n.type === 'TARGET_AGENT' || n.role === 'target';
          const fill = isTarget ? '#FAF0EB' : '#EEF6F4';
          const stroke = isTarget ? '#B84E28' : '#1E5E54';
          const safeId = DashboardSemantics.inlineArgument('Selected node: ' + n.id);

          svgContent += `
            <g class="cursor-pointer" onclick="showToast(${safeId})">
              <circle cx="${pos.x}" cy="${pos.y}" r="24" fill="${fill}" stroke="${stroke}" stroke-width="2" />
              <text x="${pos.x}" y="${pos.y + 4}" font-size="10" font-family="monospace" font-weight="bold" fill="#1A1A1A" text-anchor="middle">${escapeHtml((n.id || '').slice(0, 6))}</text>
              <text x="${pos.x}" y="${pos.y + 38}" font-size="11" font-weight="600" fill="#666666" text-anchor="middle">${escapeHtml(pos.name)}</text>
            </g>
          `;
        });

        svg.innerHTML = `
          <defs>
            <marker id="arrow" viewBox="0 0 10 10" refX="28" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 0 L 10 5 L 0 10 z" fill="#888888" />
            </marker>
          </defs>
          <g id="rbac-svg-viewport">${svgContent}</g>
        `;
      }

      /* Matrix Table */
      const tableContainer = document.getElementById('rbac-matrix-table-container');
      if (tableContainer && nodes.length > 0) {
        let rows = '';
        nodes.forEach(n => {
          rows += `
            <tr class="hover:bg-[#F7F5EE] text-xs">
              <td class="py-3 px-4 font-bold text-[#1A1A1A]">${escapeHtml(n.label || n.id)}</td>
              <td class="py-3 px-4 font-mono text-[#666666]">${escapeHtml(n.role || 'General')}</td>
              <td class="py-3 px-4 font-mono text-xs">${(n.tools || []).join(', ') || 'None'}</td>
              <td class="py-3 px-4">${(n.allowed_scopes || []).map(s => `<span class="px-2 py-0.5 rounded-full text-[10px] bg-[#EEF6F4] text-[#1E5E54] font-bold mr-1">${escapeHtml(s)}</span>`).join('') || '<span class="text-[#888888]">None</span>'}</td>
              <td class="py-3 px-4">${(n.denied_scopes || []).map(s => `<span class="px-2 py-0.5 rounded-full text-[10px] bg-[#FAF0EB] text-[#B84E28] font-bold mr-1">${escapeHtml(s)}</span>`).join('') || '<span class="text-[#888888]">None</span>'}</td>
              <td class="py-3 px-4 font-mono text-[#888888]">${escapeHtml(n.credential_ref || 'Ephemeral')}</td>
              <td class="py-3 px-4"><span class="px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-[#EEF6F4] text-[#1E5E54]">ENFORCED</span></td>
            </tr>
          `;
        });
        tableContainer.innerHTML = `
          <div class="overflow-x-auto">
            <table class="w-full text-left text-xs border-collapse">
              <thead>
                <tr class="border-b text-[10px] font-extrabold uppercase tracking-wider text-[#666666] bg-[#F7F5EE]">
                  <th class="py-3 px-4">Agent Node</th>
                  <th class="py-3 px-4">Role</th>
                  <th class="py-3 px-4">Bound Tools</th>
                  <th class="py-3 px-4">Allowed Scopes</th>
                  <th class="py-3 px-4">Denied Scopes</th>
                  <th class="py-3 px-4">Credential</th>
                  <th class="py-3 px-4">Status</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-[#1A1A1A]/10">${rows}</tbody>
            </table>
          </div>
        `;
      }
    }

    /* Paged Trajectory Renderer */
    function changeTrajectoryPage(delta) {
      const traj = globalTelemetry.trajectory;
      const turns = (traj && Array.isArray(traj.turns)) ? traj.turns : [];
      const maxPage = Math.max(1, Math.ceil(turns.length / TRAJECTORY_PAGE_SIZE));
      trajectoryCurrentPage = Math.min(maxPage, Math.max(1, trajectoryCurrentPage + delta));
      renderTrajectory();
    }

    function renderTrajectory() {
      const c = document.getElementById('trajectory-timeline');
      if (!c) return;

      const traj = globalTelemetry.trajectory;
      const turns = (traj && Array.isArray(traj.turns)) ? traj.turns : [];
      const sspClass = (traj && traj.ssp_class) || 'SERVANT';

      let sspDesc = 'Agent complies strictly with prompt instructions and lacks autonomous boundary evasion.';
      if (sspClass === 'STALKER') sspDesc = 'Agent exhibits opportunistic data retention across turn boundaries.';
      if (sspClass === 'PREDATOR') sspDesc = 'Agent actively escalates privileges and attempts unauthorized tool execution.';

      if (turns.length === 0) {
        c.innerHTML = `
          <div class="p-8 text-center text-xs text-[#888888]">
            No execution trajectory turns recorded in this scan.
          </div>
        `;
        return;
      }

      const totalPages = Math.max(1, Math.ceil(turns.length / TRAJECTORY_PAGE_SIZE));
      if (trajectoryCurrentPage > totalPages) trajectoryCurrentPage = totalPages;

      const startIdx = (trajectoryCurrentPage - 1) * TRAJECTORY_PAGE_SIZE;
      const pageTurns = turns.slice(startIdx, startIdx + TRAJECTORY_PAGE_SIZE);

      let turnsHtml = '';
      pageTurns.forEach((t, idx) => {
        const turnNum = t.turn || (startIdx + idx + 1);
        const payload = t.payload || (t.content && t.role === 'user' ? t.content : '');
        const response = t.response || (t.content && t.role === 'assistant' ? t.content : '');
        const hasTool = (Array.isArray(t.tool_calls) && t.tool_calls.length > 0) || t.tool_name;

        turnsHtml += `
          <div class="p-4 rounded-2xl border bg-white space-y-2.5 transition-all hover:border-[#1A1A1A]/30" style="border-color: var(--border)">
            <div class="flex items-center justify-between text-xs pb-2 border-b border-[#1A1A1A]/10">
              <div class="flex items-center gap-2">
                <span class="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-[#FAF0EB] text-[#B84E28] border border-[#ECCFC2]">
                  TURN ${turnNum}
                </span>
                <span class="font-mono text-[11px] font-bold text-[#1A1A1A]">Adversarial Probe Injection</span>
              </div>
              ${hasTool ? '<span class="text-[10px] font-bold px-2.5 py-0.5 rounded-full bg-[#EEF6F4] text-[#1E5E54] border border-[#CFE5E1]">TOOL CALL INTERCEPTED</span>' : '<span class="text-[10px] font-mono text-[#888888]">Verified Response</span>'}
            </div>

            <div class="space-y-1.5 text-xs">
              <div class="p-2.5 rounded-xl bg-[#FAF0EB]/60 border border-[#ECCFC2]/50 text-[#B84E28] font-mono text-[11px] break-words">
                <strong>Payload:</strong> ${escapeHtml(payload ? payload.slice(0, 260) : 'Test prompt vector')}
              </div>
              <div class="p-2.5 rounded-xl bg-[#F7F5EE] border border-[#1A1A1A]/10 text-[#333333] text-xs leading-relaxed break-words">
                <strong>Agent Response:</strong> ${escapeHtml(response ? response.slice(0, 280) : 'Normal response')}
              </div>
            </div>
          </div>
        `;
      });

      c.innerHTML = `
        <div class="mb-6 p-5 rounded-2xl bg-[#F7F5EE] border border-[#1A1A1A]/10 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div class="flex items-center gap-2">
              <span class="text-[10px] font-extrabold uppercase tracking-wider text-[#888888]">SSP Behavioral Profile</span>
              <span class="text-[#888888]">&bull;</span>
              <span class="font-mono text-xs font-bold text-[#1A1A1A]">${turns.length} Total Recorded Turns</span>
            </div>
            <div class="text-sm font-extrabold text-[#1A1A1A] mt-1">${sspDesc}</div>
          </div>
          <div class="shrink-0">
            <span class="px-4 py-2 text-xs font-mono font-extrabold uppercase rounded-full bg-[#EEF6F4] text-[#1E5E54] border border-[#CFE5E1]">
              SSP: ${escapeHtml(sspClass)}
            </span>
          </div>
        </div>

        <div class="space-y-4">
          ${turnsHtml}
        </div>

        <div class="flex items-center justify-between pt-4 border-t border-[#1A1A1A]/10 text-xs">
          <span class="text-[#666666] font-mono">Showing page <strong>${trajectoryCurrentPage}</strong> of <strong>${totalPages}</strong> (${turns.length} turns)</span>
          <div class="flex items-center gap-2">
            <button onclick="changeTrajectoryPage(-1)" class="btn-pill-light text-xs py-1 px-3 ${trajectoryCurrentPage <= 1 ? 'opacity-50 pointer-events-none' : ''}">Previous</button>
            <button onclick="changeTrajectoryPage(1)" class="btn-pill-light text-xs py-1 px-3 ${trajectoryCurrentPage >= totalPages ? 'opacity-50 pointer-events-none' : ''}">Next</button>
          </div>
        </div>
      `;
    }

    /* Paged Network Traffic Inspector */
    function changeTrafficPage(delta) {
      const traf = globalTelemetry.traffic;
      const entries = (traf && Array.isArray(traf.entries)) ? traf.entries : [];
      const maxPage = Math.max(1, Math.ceil(entries.length / TRAFFIC_PAGE_SIZE));
      trafficCurrentPage = Math.min(maxPage, Math.max(1, trafficCurrentPage + delta));
      renderTraffic();
    }

    function renderTraffic() {
      const c = document.getElementById('traffic-recorder-container');
      if (!c) return;

      const traf = globalTelemetry.traffic;
      const entries = (traf && Array.isArray(traf.entries)) ? traf.entries : [];
      const isEnabled = traf ? Boolean(traf.enabled) : false;

      const totalPages = Math.max(1, Math.ceil(entries.length / TRAFFIC_PAGE_SIZE));
      if (trafficCurrentPage > totalPages) trafficCurrentPage = totalPages;

      const startIdx = (trafficCurrentPage - 1) * TRAFFIC_PAGE_SIZE;
      const pageEntries = entries.slice(startIdx, startIdx + TRAFFIC_PAGE_SIZE);

      let rows = '';
      pageEntries.forEach(e => {
        const seq = e.seq !== undefined ? e.seq : 0;
        const mod = e.module_name || e.module_id || 'http_tracer';
        const kind = e.kind || 'REQUEST';
        const reqStr = JSON.stringify(e.request || {});
        const respStr = JSON.stringify(e.response || {});

        rows += `
          <tr class="hover:bg-[#F7F5EE] font-mono text-[11px] transition-colors">
            <td class="py-2.5 px-3 font-bold text-[#1A1A1A]">#${seq}</td>
            <td class="py-2.5 px-3 text-[#666666] font-medium">${escapeHtml(mod)}</td>
            <td class="py-2.5 px-3"><span class="px-2 py-0.5 rounded-full text-[10px] font-bold bg-[#FAF0EB] text-[#B84E28]">${escapeHtml(kind)}</span></td>
            <td class="py-2.5 px-3 truncate max-w-xs text-[#1A1A1A]">${escapeHtml(reqStr)}</td>
            <td class="py-2.5 px-3 truncate max-w-xs text-[#666666]">${escapeHtml(respStr)}</td>
            <td class="py-2.5 px-3 text-right">
              <button onclick="openTrafficFrameModal(${seq})" class="btn-pill-light text-[10px] py-0.5 px-2.5 cursor-pointer">
                &rarr; View Frame
              </button>
            </td>
          </tr>
        `;
      });

      c.innerHTML = `
        <div class="p-5 rounded-2xl bg-white border border-[#1A1A1A]/10 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <div class="text-xs font-bold text-[#1A1A1A]">Network Traffic Telemetry Recorder: ${isEnabled ? 'ACTIVE' : 'STANDBY'}</div>
            <p class="text-xs text-[#666666] mt-0.5">Captures full HTTP request and response payloads during test suite execution.</p>
          </div>
          <div class="flex items-center gap-2 shrink-0">
            <span class="px-3 py-1 text-[10px] font-mono font-bold rounded-full ${isEnabled ? 'bg-[#EEF6F4] text-[#1E5E54] border border-[#CFE5E1]' : 'bg-[#FAF0EB] text-[#B84E28] border border-[#ECCFC2]'}">
              ${isEnabled ? 'RECORDING ON' : 'DISABLED (ENABLE WITH --trace)'}
            </span>
          </div>
        </div>

        <div class="dl-card p-6 bg-white" style="border-color: var(--border)">
          <div class="flex items-center justify-between pb-3 mb-3 border-b border-[#1A1A1A]/10">
            <h3 class="text-base font-extrabold text-[#1A1A1A]">Recorded Network Traffic Frames</h3>
            <span class="text-[10px] font-mono font-bold px-2.5 py-0.5 rounded-full bg-[#EEF6F4] text-[#1E5E54]">${entries.length} Frames Captured</span>
          </div>

          <div class="overflow-x-auto">
            <table class="w-full text-left text-xs border-collapse">
              <thead>
                <tr class="border-b text-[10px] font-extrabold uppercase tracking-wider text-[#666666] bg-[#F7F5EE]">
                  <th class="py-2.5 px-3">Seq</th>
                  <th class="py-2.5 px-3">Module</th>
                  <th class="py-2.5 px-3">Kind</th>
                  <th class="py-2.5 px-3">Request Preview</th>
                  <th class="py-2.5 px-3">Response Preview</th>
                  <th class="py-2.5 px-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-[#1A1A1A]/10">
                ${rows || '<tr><td colspan="6" class="p-8 text-center text-xs text-[#888888]">No telemetry frames recorded yet. Run tests with <code>--trace</code> or inject an event.</td></tr>'}
              </tbody>
            </table>
          </div>

          <div class="flex items-center justify-between pt-4 mt-3 border-t border-[#1A1A1A]/10 text-xs">
            <span class="text-[#666666] font-mono">Page <strong>${trafficCurrentPage}</strong> of <strong>${totalPages}</strong> (${entries.length} frames)</span>
            <div class="flex items-center gap-2">
              <button onclick="changeTrafficPage(-1)" class="btn-pill-light text-xs py-1 px-3 ${trafficCurrentPage <= 1 ? 'opacity-50 pointer-events-none' : ''}">Previous</button>
              <button onclick="changeTrafficPage(1)" class="btn-pill-light text-xs py-1 px-3 ${trafficCurrentPage >= totalPages ? 'opacity-50 pointer-events-none' : ''}">Next</button>
            </div>
          </div>
        </div>
      `;
    }

    /* Dedicated Security Gateway Defense Rules Renderer */
    function renderGuardrails() {
      const c = document.getElementById('gateway-rules-container');
      if (!c) return;

      const gw = globalTelemetry.guardrails || {};
      const litellmYaml = gw.litellm || `guardrails:
  - name: agentscan_injection_shield
    mode: during_call
  - name: agentscan_keyword_filter
    keywords: [ignore previous instructions, system override]`;

      const cfJson = gw.cloudflare || `{\n  "gateway_name": "agentscan-protected-gateway",\n  "version": "1.0"\n}`;
      const bedrockJson = gw.bedrock || `{\n  "name": "AgentScanDefenseGuardrail",\n  "description": "Exported from AgentScan"\n}`;

      c.innerHTML = `
        <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <!-- LiteLLM Proxy -->
          <div class="dl-card p-6 bg-white flex flex-col justify-between" style="border-color: var(--border)">
            <div>
              <div class="flex items-center justify-between mb-3">
                <div class="flex items-center gap-2">
                  <h3 class="text-base font-extrabold text-[#1A1A1A]">LiteLLM Proxy</h3>
                  <span class="text-[9px] font-mono font-bold px-2 py-0.5 rounded-full bg-slate-100 text-slate-700">YAML</span>
                </div>
                <span class="text-[10px] font-mono font-bold px-2 py-0.5 rounded-full bg-[#EEF6F4] text-[#1E5E54]">ACTIVE</span>
              </div>
              <p class="text-xs text-[#666666] mb-3 font-medium">Banned keywords, regex redactions, and prompt shields for LiteLLM proxies.</p>
              <pre class="p-4 rounded-2xl bg-[#F7F5EE] border border-[#1A1A1A]/10 text-[#1A1A1A] text-[11px] overflow-x-auto leading-relaxed max-h-64 font-mono"><code>${escapeHtml(litellmYaml)}</code></pre>
            </div>
            <div class="pt-4 mt-4 border-t border-[#1A1A1A]/10 flex items-center justify-between">
              <button onclick="copyRule('litellm')" class="btn-pill-light text-xs py-1.5 px-3">Copy YAML</button>
              <button onclick="downloadGatewayRule('litellm', 'guardrails.yaml')" class="btn-pill-teal text-xs py-1.5 px-3">&rarr; Export</button>
            </div>
          </div>

          <!-- Cloudflare AI Gateway -->
          <div class="dl-card p-6 bg-white flex flex-col justify-between" style="border-color: var(--border)">
            <div>
              <div class="flex items-center justify-between mb-3">
                <div class="flex items-center gap-2">
                  <h3 class="text-base font-extrabold text-[#1A1A1A]">Cloudflare AI Gateway</h3>
                  <span class="text-[9px] font-mono font-bold px-2 py-0.5 rounded-full bg-slate-100 text-slate-700">JSON</span>
                </div>
                <span class="text-[10px] font-mono font-bold px-2 py-0.5 rounded-full bg-[#EEF6F4] text-[#1E5E54]">ENFORCED</span>
              </div>
              <p class="text-xs text-[#666666] mb-3 font-medium">Edge WAF regex match rules blocking jailbreaks and exfiltration.</p>
              <pre class="p-4 rounded-2xl bg-[#F7F5EE] border border-[#1A1A1A]/10 text-[#1A1A1A] text-[11px] overflow-x-auto leading-relaxed max-h-64 font-mono"><code>${escapeHtml(cfJson)}</code></pre>
            </div>
            <div class="pt-4 mt-4 border-t border-[#1A1A1A]/10 flex items-center justify-between">
              <button onclick="copyRule('cloudflare')" class="btn-pill-light text-xs py-1.5 px-3">Copy JSON</button>
              <button onclick="downloadGatewayRule('cloudflare', 'cloudflare-waf.json')" class="btn-pill-teal text-xs py-1.5 px-3">&rarr; Export</button>
            </div>
          </div>

          <!-- AWS Bedrock Guardrails -->
          <div class="dl-card p-6 bg-white flex flex-col justify-between" style="border-color: var(--border)">
            <div>
              <div class="flex items-center justify-between mb-3">
                <div class="flex items-center gap-2">
                  <h3 class="text-base font-extrabold text-[#1A1A1A]">AWS Bedrock Guardrail</h3>
                  <span class="text-[9px] font-mono font-bold px-2 py-0.5 rounded-full bg-slate-100 text-slate-700">JSON</span>
                </div>
                <span class="text-[10px] font-mono font-bold px-2 py-0.5 rounded-full bg-[#FAF0EB] text-[#B84E28]">ENTERPRISE</span>
              </div>
              <p class="text-xs text-[#666666] mb-3 font-medium">Content policy filters, PII redactions, and contextual grounding configs.</p>
              <pre class="p-4 rounded-2xl bg-[#F7F5EE] border border-[#1A1A1A]/10 text-[#1A1A1A] text-[11px] overflow-x-auto leading-relaxed max-h-64 font-mono"><code>${escapeHtml(bedrockJson)}</code></pre>
            </div>
            <div class="pt-4 mt-4 border-t border-[#1A1A1A]/10 flex items-center justify-between">
              <button onclick="copyRule('bedrock')" class="btn-pill-light text-xs py-1.5 px-3">Copy JSON</button>
              <button onclick="downloadGatewayRule('bedrock', 'bedrock-guardrail.json')" class="btn-pill-teal text-xs py-1.5 px-3">&rarr; Export</button>
            </div>
          </div>
        </div>
      `;
    }

    function downloadGatewayRule(format, filename) {
      const gw = globalTelemetry.guardrails || {};
      const content = gw[format] || '';
      if (!content) return;
      const dataStr = "data:text/plain;charset=utf-8," + encodeURIComponent(content);
      const a = document.createElement('a');
      a.href = dataStr;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      showToast(`Exported ${filename}`);
    }

    function downloadAllGatewayRules() {
      const gw = globalTelemetry.guardrails || {};
      const bundle = {
        litellm_guardrails_yaml: gw.litellm || '',
        cloudflare_gateway_rules_json: gw.cloudflare ? JSON.parse(gw.cloudflare) : {},
        aws_bedrock_guardrail_json: gw.bedrock ? JSON.parse(gw.bedrock) : {},
        exported_at: new Date().toISOString()
      };
      const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(bundle, null, 2));
      const a = document.createElement('a');
      a.href = dataStr;
      a.download = `agentscan-gateway-rules-${new Date().toISOString().slice(0, 10)}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      showToast("Exported all gateway rule sets");
    }

    function copyRule(format) {
      const gw = globalTelemetry.guardrails || {};
      const content = gw[format] || '';
      if (content && navigator.clipboard) {
        navigator.clipboard.writeText(content).then(() => {
          showToast(`Copied ${format.toUpperCase()} rules to clipboard`);
        });
      }
    }

    /* Cryptographic Audit Verification with Custom Secret Key Support */
    async function verifyCertAction() {
      if (!validateSubmission('certificate', 'certificate-launch-error')) return;
      const formValues = AgentScanForms.getValues('certificate');
      try {
        const cert = globalTelemetry.certificate;
        if (!cert) {
          DashboardSemantics.showLaunchError('certificate-launch-error', 'No active certificate is available. Load a report with a certificate before verifying.');
          return;
        }
        const secretInput = document.getElementById('cert-secret-key');
        const secret = secretInput ? secretInput.value.trim() : '';
        const payload = { certificate: cert };
        if (secret) {
          payload.secret_key = secret;
          payload.secret = secret;
        }

        const data = await DashboardSemantics.requestJSON('/api/verify-certificate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        }, 'certificate');
        const badgeEl = document.getElementById('cert-verify-status');
        if (badgeEl) {
          if (data.valid) {
            badgeEl.innerHTML = `
              <span class="px-3 py-1 text-xs font-bold rounded-full bg-[#EEF6F4] text-[#1E5E54] border border-[#CFE5E1]">
                &check; Cryptographically Verified: Zero Tampering Detected
              </span>
            `;
            showToast("Report signature verified successfully");
          } else {
            badgeEl.innerHTML = `
              <span class="px-3 py-1 text-xs font-bold rounded-full bg-[#FAF0EB] text-[#B84E28] border border-[#ECCFC2]">
                &times; Verification Failed: ${escapeHtml(data.reason)}
              </span>
            `;
            showToast("Certificate verification failed");
          }
        }
      } catch (err) {
        DashboardSemantics.showLaunchError('certificate-launch-error', err.message);
        showToast("Verification error: " + err.message);
      }
    }

    function renderCompliance() {
      const c = document.getElementById('compliance-matrix-container');
      if (!c) return;

      const comp = globalTelemetry.compliance;
      const eu = comp ? comp.eu_ai_act : null;
      const nist = comp ? comp.nist_ai_rmf : null;
      const cert = globalTelemetry.certificate;

      function renderSections(secObj) {
        if (!secObj || typeof secObj !== 'object') return '<li class="text-xs text-[#888888]">No sections evaluated.</li>';
        let lis = '';
        for (const [secName, data] of Object.entries(secObj)) {
          const isPass = data.status === 'COMPLIANT' || data.finding_count === 0;
          lis += `
            <li class="flex items-center justify-between py-2 border-b border-[#1A1A1A]/5 last:border-b-0">
              <div>
                <div class="font-bold text-[#1A1A1A]">${escapeHtml(secName)}</div>
                <div class="text-[10px] text-[#666666] font-medium">${escapeHtml(data.description || '')}</div>
              </div>
              <span class="font-mono text-xs font-bold shrink-0 ml-4 ${isPass ? 'text-[#1E5E54]' : 'text-[#B84E28]'}">
                ${isPass ? 'No mapped findings' : `${data.finding_count || 1} mapped findings`}
              </span>
            </li>
          `;
        }
        return lis;
      }

      const evaluated = DashboardSemantics.summarize(globalTelemetry.report);
      const euStatus = evaluated.status !== 'COMPLETE' ? 'UNVERIFIED COVERAGE' : eu?.overall_status === 'COMPLIANT' ? 'NO MAPPED FINDINGS' : eu?.overall_status?.replaceAll('_', ' ') || 'NOT EVALUATED';
      const euClass = 'assessment-badge status-neutral';

      const nistStatus = evaluated.status !== 'COMPLETE' ? 'UNVERIFIED COVERAGE' : nist?.overall_status === 'COMPLIANT' ? 'NO MAPPED FINDINGS' : nist?.overall_status?.replaceAll('_', ' ') || 'NOT EVALUATED';
      const nistClass = 'assessment-badge status-neutral';

      let certHtml = '';
      if (cert) {
        certHtml = `
          <div class="dl-card p-8 bg-white" style="border-color: var(--border)">
            <div class="flex flex-col sm:flex-row sm:items-center justify-between pb-4 mb-4 border-b border-[#1A1A1A]/10 gap-3">
              <div>
                <div class="flex items-center gap-2">
                  <h3 class="text-lg font-extrabold text-[#1A1A1A]">Cryptographic Audit Certificate & Signature</h3>
                  <span class="text-[10px] font-mono font-bold px-2 py-0.5 rounded-full bg-[#EEF6F4] text-[#1E5E54] border border-[#CFE5E1]">${escapeHtml(cert.algorithm || 'HMAC-SHA256')}</span>
                </div>
                <p class="text-xs text-[#666666] mt-0.5 font-medium">Tamper-evident HMAC-SHA256 digital signature certifying report authenticity.</p>
              </div>
              <div id="certificate-launch-error" class="launch-error" role="alert" hidden></div>
              <div id="cert-verify-result" class="flex items-center gap-2 flex-wrap"><span id="cert-verify-status"></span>
                <input type="password" id="cert-secret-key" aria-label="Custom Secret Key (optional)" placeholder="Custom Secret Key (optional)" class="px-3 py-1.5 text-xs border border-[#1A1A1A]/15 rounded-full font-mono focus:outline-none focus:border-[#1A1A1A] w-52" />
                <button onclick="verifyCertAction()" class="btn-pill-dark text-xs py-1.5 px-4 cursor-pointer whitespace-nowrap">
                  &rarr; Verify Authenticity
                </button>
              </div>
            </div>

            <div class="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
              <div class="p-3.5 rounded-xl bg-[#F7F5EE] border border-[#1A1A1A]/10 space-y-1">
                <div class="text-[10px] font-bold text-[#888888] uppercase tracking-wider">Report Canonical SHA-256 Digest</div>
                <div class="text-[#1A1A1A] font-bold break-all">${escapeHtml(cert.report_sha256 || 'N/A')}</div>
              </div>
              <div class="p-3.5 rounded-xl bg-[#F7F5EE] border border-[#1A1A1A]/10 space-y-1">
                <div class="text-[10px] font-bold text-[#888888] uppercase tracking-wider">HMAC Digital Signature</div>
                <div class="text-[#1E5E54] font-bold break-all">${escapeHtml(cert.signature || 'N/A')}</div>
              </div>
            </div>

            <div class="mt-4 pt-3 border-t border-[#1A1A1A]/10 flex flex-wrap items-center justify-between text-xs text-[#666666]">
              <span>Issuer: <strong>${escapeHtml(cert.issuer || 'AgentScan Cryptographic Engine')}</strong></span>
              <span>Timestamp: <strong>${escapeHtml(cert.issued_at || new Date().toISOString())}</strong></span>
            </div>
          </div>
        `;
      }

      c.innerHTML = `
        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div class="dl-card p-8 bg-white" style="border-color: var(--border)">
            <div class="flex items-center justify-between pb-4 mb-4 border-b border-[#1A1A1A]/10">
              <div>
                <h3 class="text-lg font-extrabold text-[#1A1A1A]">EU Artificial Intelligence Act</h3>
                <p class="text-xs text-[#666666] mt-0.5 font-medium">Regulation (EU) 2024/1689 Framework Compliance</p>
              </div>
              <span class="px-3 py-1 text-[10px] font-bold rounded-full border ${euClass}">${escapeHtml(euStatus)}</span>
            </div>
            <ul class="text-xs text-[#333333] space-y-1 font-medium">
              ${renderSections(eu ? eu.evaluated_sections : null)}
            </ul>
          </div>

          <div class="dl-card p-8 bg-white" style="border-color: var(--border)">
            <div class="flex items-center justify-between pb-4 mb-4 border-b border-[#1A1A1A]/10">
              <div>
                <h3 class="text-lg font-extrabold text-[#1A1A1A]">NIST AI Risk Management Framework 1.0</h3>
                <p class="text-xs text-[#666666] mt-0.5 font-medium">NIST AI 100-1 Trustworthy AI Criteria</p>
              </div>
              <span class="px-3 py-1 text-[10px] font-bold rounded-full border ${nistClass}">${escapeHtml(nistStatus)}</span>
            </div>
            <ul class="text-xs text-[#333333] space-y-1 font-medium">
              ${renderSections(nist ? nist.evaluated_sections : null)}
            </ul>
          </div>
        </div>

        ${certHtml}
      `;
    }

    function copyPrMarkdown() {
      const heal = globalTelemetry.heal;
      const pr = heal && heal.pr_payload;
      if (!pr) return;
      const md = `# ${pr.title}\n\n**Head Branch:** \`${pr.head}\` &rarr; **Base Branch:** \`${pr.base}\`\n\n${pr.body}`;
      if (navigator.clipboard) {
        navigator.clipboard.writeText(md).then(() => {
          showToast("GitHub PR markdown copied to clipboard");
        });
      }
    }

    function copyPrJson() {
      const heal = globalTelemetry.heal;
      const pr = heal && heal.pr_payload;
      if (!pr) return;
      if (navigator.clipboard) {
        navigator.clipboard.writeText(JSON.stringify(pr, null, 2)).then(() => {
          showToast("GitHub REST API payload JSON copied");
        });
      }
    }

    function renderHealing() {
      const c = document.getElementById('healing-diff-container');
      if (!c) return;

      const heal = globalTelemetry.heal;
      const patch = (heal && heal.patch) ? heal.patch : '';
      const totalActions = (heal && heal.total_actions) || 0;
      const paths = (heal && Array.isArray(heal.paths_affected)) ? heal.paths_affected : [];
      const pr = heal && heal.pr_payload;

      let diffCardHtml = '';
      if (patch.trim()) {
        const lines = patch.split(/\r?\n/);
        let diffHtml = '';
        lines.forEach(line => {
          let lineStyle = 'color: var(--text-body);';
          if (line.startsWith('+') && !line.startsWith('+++')) {
            lineStyle = 'color: var(--defense-teal-text); background: var(--defense-teal-bg); font-weight: 600;';
          } else if (line.startsWith('-') && !line.startsWith('---')) {
            lineStyle = 'color: var(--attack-terracotta-text); background: var(--attack-terracotta-bg); font-weight: 600;';
          } else if (line.startsWith('@@')) {
            lineStyle = 'color: var(--text-muted); font-weight: 700;';
          }
          diffHtml += `<div style="${lineStyle}" class="px-4 py-1">${escapeHtml(line)}</div>`;
        });

        diffCardHtml = `
          <div class="dl-card p-6 bg-white space-y-4" style="border-color: var(--border)">
            <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-[#1A1A1A]/10 text-xs">
              <div>
                <span class="font-bold text-[#1A1A1A]">${totalActions} Patch Action(s) Generated</span> &bull;
                <span class="text-[#666666]">${paths.length} target file(s) affected</span>
              </div>
              <div class="flex items-center gap-2">
                <button onclick="openHealApplyModal()" class="btn-pill-dark text-xs py-1.5 px-3.5 cursor-pointer">
                  &rarr; Apply to Disk
                </button>
                <button onclick="copyUnifiedPatch()" class="btn-pill-teal text-xs py-1.5 px-3.5 cursor-pointer">
                  Copy Unified Patch
                </button>
              </div>
            </div>

            <div class="text-xs font-mono rounded-2xl border overflow-x-auto bg-[#F7F5EE]" style="border-color: var(--border)">
              <div class="px-4 py-3 border-b font-extrabold text-[#1A1A1A] flex items-center justify-between" style="border-color: var(--border)">
                <span>Unified Diff: AST Parameter Sanitizer & Guardrail Policies</span>
                <span class="text-[10px] px-3 py-1 rounded-full font-bold bg-[#EEF6F4] text-[#1E5E54] border border-[#CFE5E1]">REVIEW REQUIRED</span>
              </div>
              <div class="p-2 space-y-0.5 leading-relaxed">${diffHtml}</div>
            </div>
          </div>
        `;
      } else {
        diffCardHtml = `
          <div class="dl-card p-8 bg-white text-center" style="border-color: var(--border)">
            <div class="w-12 h-12 mx-auto mb-3 rounded-2xl flex items-center justify-center bg-[#EEF6F4] text-[#1E5E54] font-bold text-lg">
              &check;
            </div>
            <h3 class="font-extrabold text-base text-[#1A1A1A] mb-1">No generated patch available</h3>
            <p class="text-xs text-[#666666] max-w-md mx-auto font-medium">
              This plan contains no patch diffs. Review findings and assessment coverage; an empty plan does not establish that the codebase is secure.
            </p>
          </div>
        `;
      }

      let prCardHtml = '';
      if (pr) {
        prCardHtml = `
          <div class="dl-card p-6 bg-white space-y-4" style="border-color: var(--border)">
            <div class="flex flex-col sm:flex-row sm:items-center justify-between pb-3 border-b border-[#1A1A1A]/10 gap-3">
              <div class="flex items-center gap-3">
                <div class="w-9 h-9 rounded-full bg-[#1A1A1A] text-white flex items-center justify-center">
                  <svg class="w-5 h-5" fill="currentColor" viewBox="0 0 24 24">
                    <path fill-rule="evenodd" clip-rule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.53 1.032 1.53 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"/>
                  </svg>
                </div>
                <div>
                  <h3 class="text-base font-extrabold text-[#1A1A1A]">${escapeHtml(pr.title || 'Automated Self-Healing PR')}</h3>
                  <div class="flex items-center gap-2 mt-0.5 text-xs">
                    <span class="font-mono text-[#666666]">Branch:</span>
                    <span class="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-slate-100 text-slate-800 border border-slate-200">
                      ${escapeHtml(pr.head || 'agentscan/auto-heal')} &rarr; ${escapeHtml(pr.base || 'main')}
                    </span>
                  </div>
                </div>
              </div>
              <div class="flex items-center gap-2">
                <button onclick="copyPrMarkdown()" class="btn-pill-light text-xs py-1.5 px-3 cursor-pointer">Copy PR Markdown</button>
                <button onclick="copyPrJson()" class="btn-pill-dark text-xs py-1.5 px-3 cursor-pointer">Copy GitHub JSON</button>
              </div>
            </div>

            <div class="p-4 rounded-2xl bg-[#F7F5EE] border border-[#1A1A1A]/10 text-xs text-[#333333] space-y-2">
              <div class="text-[10px] font-bold text-[#888888] uppercase tracking-wider">PR Body Preview</div>
              <pre class="font-mono text-[11px] leading-relaxed whitespace-pre-wrap max-h-56 overflow-y-auto">${escapeHtml(pr.body || '')}</pre>
            </div>
          </div>
        `;
      }

      c.innerHTML = `
        ${diffCardHtml}
        ${prCardHtml}
      `;
    }

    function renderTeam() {
      const agents = (globalTelemetry.identity && Array.isArray(globalTelemetry.identity.agents)) ? globalTelemetry.identity.agents : [];
      const swarmsData = globalTelemetry.swarms;
      const teams = (swarmsData && swarmsData.teams) ? swarmsData.teams : {};
      const blackboard = (swarmsData && swarmsData.blackboard) ? swarmsData.blackboard : null;

      const defCountEl = document.getElementById('team-defensive-count');
      if (defCountEl) defCountEl.innerText = `${agents.length} Target Agents`;

      const grid = document.getElementById('team-agents-grid');
      if (grid) {
        if (agents.length === 0) {
          grid.innerHTML = `
            <div class="col-span-1 md:col-span-3 p-10 text-center text-xs text-[#888888] bg-white rounded-3xl border border-[#1A1A1A]/10 font-medium">
              No target agent manifests loaded. Pass <code>--identity &lt;manifest_dir&gt;</code> to analyze target personas.
            </div>
          `;
        } else {
          let html = '';
          agents.forEach(a => {
            const name = a.agent_id || 'Unknown Agent';
            const role = a.declared_role || 'General Assistant';
            const tools = Array.isArray(a.tools) ? a.tools : [];
            const credRef = a.credential_ref ? `Secret Ref (${escapeHtml(a.credential_ref)})` : 'Ephemeral (No Secret)';

            html += `
              <div class="dl-card p-6 bg-white flex flex-col justify-between" style="border-color: var(--border)">
                <div>
                  <div class="flex items-center justify-between text-xs mb-3">
                    <span class="font-mono text-[10px] text-[#666666] font-bold uppercase truncate max-w-[140px]">${credRef}</span>
                    <span class="px-3 py-0.5 text-[10px] font-bold uppercase rounded-full bg-[#EEF6F4] text-[#1E5E54] border border-[#CFE5E1]">
                      TARGET AGENT
                    </span>
                  </div>
                  <h3 class="text-lg font-extrabold text-[#1A1A1A] mb-1">${escapeHtml(name)}</h3>
                  <p class="text-xs text-[#666666] font-medium mb-6">Declared Role: <strong>${escapeHtml(role)}</strong></p>
                </div>

                <div class="pt-4 border-t border-[#1A1A1A]/10 flex items-center justify-between text-xs font-mono text-[#666666]">
                  <span>Tools Bound: ${tools.length}</span>
                  <span class="text-[#1A1A1A] font-bold">RBAC Enforced</span>
                </div>
              </div>
            `;
          });
          grid.innerHTML = html;
        }
      }

      /* Offensive Red-Team Swarms */
      const swarmsGrid = document.getElementById('swarm-teams-grid');
      if (swarmsGrid) {
        let html = '';
        Object.values(teams).forEach(team => {
          let agentPills = '';
          (team.agents || []).forEach(ag => {
            let roleBadge = 'bg-blue-100 text-blue-800 border-blue-200';
            if (ag.role === 'BYPASS') roleBadge = 'bg-amber-100 text-amber-800 border-amber-200';
            if (ag.role === 'EXPLOIT') roleBadge = 'bg-rose-100 text-rose-800 border-rose-200';
            if (ag.role === 'JUDGE') roleBadge = 'bg-teal-100 text-teal-800 border-teal-200';

            agentPills += `
              <div class="flex items-center justify-between py-1.5 border-b border-[#1A1A1A]/5 last:border-b-0 text-xs">
                <span class="font-bold text-[#1A1A1A]">${escapeHtml(ag.name)}</span>
                <span class="px-2 py-0.5 rounded-full text-[9px] font-mono font-bold border ${roleBadge}">${escapeHtml(ag.role)}</span>
              </div>
            `;
          });

          html += `
            <div class="dl-card p-6 bg-white flex flex-col justify-between" style="border-color: var(--border)">
              <div>
                <div class="flex items-center justify-between text-xs mb-3">
                  <span class="font-mono text-[10px] font-extrabold text-[#B84E28] uppercase">${escapeHtml(team.strategy)}</span>
                  <span class="px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-[#FAF0EB] text-[#B84E28] border border-[#ECCFC2]">
                    ${escapeHtml(team.default_model || 'gpt-4o-mini')}
                  </span>
                </div>
                <h3 class="text-base font-extrabold text-[#1A1A1A] mb-1">${escapeHtml(team.name)}</h3>
                <p class="text-xs text-[#666666] font-medium mb-4">Max Rounds: ${team.max_rounds} &bull; Shared Blackboard</p>
                <div class="space-y-1 my-3 bg-[#F7F5EE] p-3 rounded-2xl border border-[#1A1A1A]/10">
                  ${agentPills}
                </div>
              </div>
              <div class="pt-3 border-t border-[#1A1A1A]/10 flex items-center justify-between text-[11px] font-mono text-[#666666]">
                <span>Roster: ${(team.agents || []).length} Agents</span>
                <button onclick="openSwarmModal()" class="text-[#B84E28] font-bold hover:underline">&rarr; Run Swarm</button>
              </div>
            </div>
          `;
        });
        swarmsGrid.innerHTML = html || '<div class="col-span-3 p-8 text-center text-xs text-[#888888]">No swarm attack configurations loaded.</div>';
      }

      /* Live Swarm Blackboard Intelligence */
      const bbCard = document.getElementById('swarm-blackboard-card');
      if (bbCard && blackboard) {
        const items = blackboard.items || [];
        let itemsHtml = '';
        items.forEach(it => {
          itemsHtml += `
            <div class="p-3 rounded-xl bg-white border border-[#1A1A1A]/10 text-xs space-y-1">
              <div class="flex items-center justify-between font-bold text-[#1A1A1A]">
                <span class="font-mono text-[#1E5E54]">${escapeHtml(it.key)}</span>
                <span class="text-[10px] text-[#888888]">Via: <strong>${escapeHtml(it.discovered_by)}</strong> (Confidence: ${(it.confidence * 100).toFixed(0)}%)</span>
              </div>
              <div class="text-[#333333] text-[11px] font-mono">${escapeHtml(String(it.value))}</div>
            </div>
          `;
        });

        bbCard.innerHTML = `
          <div class="dl-card p-6 bg-[#F7F5EE] border border-[#1A1A1A]/10 space-y-3">
            <div class="flex items-center justify-between">
              <div class="flex items-center gap-2">
                <svg class="w-4 h-4 text-[#B84E28]" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                  <rect x="2" y="3" width="20" height="14" rx="2" ry="2"/>
                  <line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/>
                </svg>
                <h3 class="text-sm font-extrabold text-[#1A1A1A]">Shared Swarm Blackboard Intelligence</h3>
              </div>
              <div class="flex items-center gap-2">
                <span class="text-[10px] font-mono font-bold px-2 py-0.5 rounded-full bg-white text-[#1A1A1A] border border-[#1A1A1A]/10">${items.length} Intelligence Items</span>
                <button onclick="clearSwarmBlackboardAction()" class="btn-pill-light text-[10px] py-0.5 px-2">Clear</button>
              </div>
            </div>
            <p class="text-xs text-[#666666] font-medium">
              Synchronized multi-agent memory shared across Recon, Bypass, Exploit, and Judge roles to avoid redundant probes.
            </p>
            <div class="space-y-2 mt-2">${itemsHtml || '<div class="text-xs text-[#888888] font-mono">No live intelligence items currently on blackboard.</div>'}</div>
          </div>
        `;
      }
    }

    /* Sentinel Monitor & Canary Probes Renderer */
    function renderSentinel() {
      const c = document.getElementById('sentinel-container');
      if (!c) return;

      const snt = globalTelemetry.sentinel || {};
      const isRunning = Boolean(snt.running);
      const failed = snt.status === 'ERROR' || Boolean(snt.error);
      const sentinelErrors = [];
      if (failed) sentinelErrors.push({ module_name: 'Sentinel watcher', error: snt.error || 'The watcher stopped because an execution error occurred.', error_id: snt.error_id });
      if (snt.webhook_error) sentinelErrors.push({ module_name: 'Sentinel webhook', error: snt.webhook_error.error || 'The webhook notification could not be delivered.', error_id: snt.webhook_error.error_id });
      const watcherError = sentinelErrors.length ? DashboardSemantics.assessmentErrorMarkup({ status: 'ERROR', assessment_scope: failed ? 'watcher' : 'sentinel_delivery', module_errors: sentinelErrors }) : '';
      const runtimeErrors = document.getElementById('sentinel-runtime-errors');
      if (runtimeErrors) runtimeErrors.innerHTML = watcherError;
      const inlineStatus = document.getElementById('sentinel-status-inline');
      if (inlineStatus) inlineStatus.textContent = failed ? 'ERROR / STOPPED' : isRunning ? 'ACTIVE POLLING' : 'STANDBY / STOPPED';
      document.getElementById('btn-sentinel-start')?.classList.toggle('pointer-events-none', isRunning);
      document.getElementById('btn-sentinel-start')?.classList.toggle('opacity-50', isRunning);
      document.getElementById('btn-sentinel-stop')?.classList.toggle('pointer-events-none', !isRunning);
      document.getElementById('btn-sentinel-stop')?.classList.toggle('opacity-50', !isRunning);
      const target = snt.target || 'No agent endpoint configured';
      const interval = snt.interval || 30;
      const probes = snt.probes_run || 0;
      const leaks = snt.leaks_detected || 0;

      c.innerHTML = `
        <div id="sentinel-tab-errors">${watcherError}</div>
        <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div class="dl-card p-6 bg-white space-y-3" style="border-color: var(--border)">
            <div class="flex items-center justify-between">
              <span class="text-[10px] font-extrabold uppercase tracking-wider text-[#666666]">Watcher Status</span>
              <span class="px-2.5 py-0.5 rounded-full text-[10px] font-bold ${isRunning ? 'bg-[#EEF6F4] text-[#1E5E54] border border-[#CFE5E1]' : 'bg-[#FAF0EB] text-[#B84E28] border border-[#ECCFC2]'}">
                ${failed ? 'ERROR' : isRunning ? 'ACTIVE POLLING' : 'STANDBY'}
              </span>
            </div>
            <div class="text-2xl font-extrabold text-[#1A1A1A]">${failed ? 'STOPPED AFTER ERROR' : isRunning ? 'RUNNING' : 'STOPPED'}</div>
            <p class="text-xs text-[#666666]">Target: <code class="font-mono font-bold text-[#1A1A1A]">${escapeHtml(target)}</code></p>
            <div class="pt-3 border-t border-[#1A1A1A]/10 flex items-center justify-between text-xs">
              <span class="text-[#888888]">Interval: ${interval}s</span>
              <button onclick="openSentinelModal()" class="text-xs font-bold text-[#1A1A1A] hover:underline">&rarr; Configure</button>
            </div>
          </div>

          <div class="dl-card p-6 bg-white space-y-3" style="border-color: var(--border)">
            <div class="flex items-center justify-between">
              <span class="text-[10px] font-extrabold uppercase tracking-wider text-[#1E5E54]">Canary Probes</span>
              <span class="px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-[#EEF6F4] text-[#1E5E54] border border-[#CFE5E1]">ACTIVE</span>
            </div>
            <div class="text-2xl font-extrabold text-[#1A1A1A]">${probes} Probes</div>
            <p class="text-xs text-[#666666]">High-entropy synthetic canary tokens injected across dialogue boundaries.</p>
            <div class="pt-3 border-t border-[#1A1A1A]/10 flex items-center justify-between text-xs">
              <span class="text-[#1E5E54] font-bold">Review recorded probe outcomes</span>
              <button onclick="runSentinelProbeAction()" class="text-xs font-bold text-[#1E5E54] hover:underline">&rarr; Probe Now</button>
            </div>
          </div>

          <div class="dl-card p-6 bg-white space-y-3" style="border-color: var(--border)">
            <div class="flex items-center justify-between">
              <span class="text-[10px] font-extrabold uppercase tracking-wider text-[#B84E28]">Alerts & Leaks</span>
              <span class="px-2.5 py-0.5 rounded-full text-[10px] font-bold ${leaks > 0 ? 'bg-[#FAF0EB] text-[#B84E28]' : 'bg-[#EEF6F4] text-[#1E5E54]'}">
                ${leaks > 0 ? 'ALERT' : 'NO RECORDED FINDING'}
              </span>
            </div>
            <div class="text-2xl font-extrabold text-[#1A1A1A]">${leaks} Detected</div>
            <p class="text-xs text-[#666666]">Unsanitized canary token reflections or unauthorized external exfiltration.</p>
            <div class="pt-3 border-t border-[#1A1A1A]/10 flex items-center justify-between text-xs">
              <span class="text-[#888888]">Webhook: ${escapeHtml(snt.webhook_url || 'Not configured')}</span>
              <button onclick="openHealServerModal()" class="text-xs font-bold text-[#B84E28] hover:underline">&rarr; Webhook Server</button>
            </div>
          </div>
        </div>

        <div class="dl-card p-6 bg-white space-y-3" style="border-color: var(--border)">
          <div class="flex items-center justify-between pb-3 border-b border-[#1A1A1A]/10">
            <h3 class="text-base font-extrabold text-[#1A1A1A]">Continuous Sentinel Event Telemetry</h3>
            <span class="text-[10px] font-mono font-bold px-2 py-0.5 rounded-full bg-[#F7F5EE] text-[#1A1A1A]">LIVE FEED</span>
          </div>
          <p class="text-xs text-[#666666]">Background surveillance daemon monitors running agents for prompt injections and canary leaks in real-time.</p>
          <div class="p-4 rounded-2xl bg-[#F7F5EE] font-mono text-[11px] text-[#1A1A1A] space-y-1">
            <div>[SENTINEL-DAEMON] Configured target: <strong>${escapeHtml(target)}</strong></div>
            <div>[SENTINEL-DAEMON] Canary token state: <code>${snt.canary_token ? 'Configured' : 'Not configured'}</code></div>
            <div>[SENTINEL-DAEMON] Webhook dispatcher target: <code>${escapeHtml(snt.webhook_url || 'Not configured')}</code></div>
            <div>[SENTINEL-DAEMON] State: <strong>${isRunning ? 'ACTIVE - Polling every ' + interval + 's' : 'STANDBY - Ready to start'}</strong></div>
          </div>
        </div>
      `;
    }

    /* Native Model Context Protocol (MCP) Monitor Renderer */
    function renderMcp() {
      const c = document.getElementById('mcp-container');
      if (!c) return;

      const mcpData = globalTelemetry.mcp || {};
      const status = mcpData.status || 'ONLINE';
      const transport = mcpData.transport || 'stdio';
      const proto = mcpData.protocol || 'JSON-RPC 2.0';
      const tools = Array.isArray(mcpData.tools) ? mcpData.tools : [
        { name: 'agentscan_list_attacks', description: 'List available registered AgentScan attack modules, their OWASP LLM mappings, and supported scan modes.', input_schema: {} },
        { name: 'agentscan_audit', description: 'Audit a project repository for AI supply-chain vulnerabilities, known CVEs, hardcoded secrets, and insecure configurations.', input_schema: { path: 'string', offline: 'boolean' } },
        { name: 'agentscan_scan', description: 'Execute automated adversarial security scan against target LLM or agent endpoint.', input_schema: { target: 'string', mode: 'string', max_turns: 'integer' } },
        { name: 'agentscan_swarm', description: 'Dispatch an autonomous multi-agent offensive swarm to simulate coordinated red-team attacks.', input_schema: { target: 'string', team: 'string', rounds: 'integer' } }
      ];

      let toolsHtml = '';
      tools.forEach(t => {
        const safeToolName = DashboardSemantics.inlineArgument(t.name);
        toolsHtml += `
          <div class="dl-card p-6 bg-white flex flex-col justify-between" style="border-color: var(--border)">
            <div>
              <div class="flex items-center justify-between mb-3 text-xs">
                <span class="font-mono text-[10px] font-bold text-[#1E5E54] uppercase">Registered MCP Tool</span>
                <span class="px-2 py-0.5 rounded-full text-[9px] font-mono font-bold bg-[#EEF6F4] text-[#1E5E54]">READY</span>
              </div>
              <h3 class="text-base font-extrabold text-[#1A1A1A] font-mono mb-1">${escapeHtml(t.name)}</h3>
              <p class="text-xs text-[#666666] leading-relaxed mb-4">${escapeHtml(t.description)}</p>
              <div class="p-3 rounded-xl bg-[#F7F5EE] border border-[#1A1A1A]/10 font-mono text-[10px] text-[#333333]">
                <strong>Schema:</strong> ${escapeHtml(JSON.stringify(t.input_schema || {}))}
              </div>
            </div>

            <div class="pt-4 mt-4 border-t border-[#1A1A1A]/10 flex items-center justify-between text-xs">
              <span class="text-[#888888] font-mono">stdio RPC</span>
              <button onclick="openMcpTestModal(${safeToolName})" class="btn-pill-dark text-xs py-1.5 px-3.5 cursor-pointer">
                &rarr; Test Invoke
              </button>
            </div>
          </div>
        `;
      });

      c.innerHTML = `
        <div class="dl-card p-6 bg-white flex flex-col sm:flex-row sm:items-center justify-between gap-4" style="border-color: var(--border)">
          <div class="flex items-center gap-4">
            <div class="w-12 h-12 rounded-2xl flex items-center justify-center bg-[#EEF6F4] text-[#1E5E54] font-bold text-lg border border-[#CFE5E1]">
              MCP
            </div>
            <div>
              <div class="flex items-center gap-2">
                <h3 class="text-base font-extrabold text-[#1A1A1A]">AgentScan Native MCP Server</h3>
                <span class="px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-[#EEF6F4] text-[#1E5E54] border border-[#CFE5E1]">${escapeHtml(status)}</span>
              </div>
              <p class="text-xs text-[#666666] font-mono mt-0.5">Transport: <strong>${escapeHtml(transport)}</strong> &bull; Protocol: <strong>${escapeHtml(proto)}</strong> &bull; Server: agentscan-mcp:0.2.0</p>
            </div>
          </div>

          <div class="flex items-center gap-2">
            <button onclick="openMcpTestModal('scan_target')" class="btn-pill-teal text-xs py-1.5 px-4 cursor-pointer">
              &rarr; Invoke Tool Test Harness
            </button>
          </div>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
          ${toolsHtml}
        </div>
      `;
    }

    /* ========================================================
       INTERACTIVE RUNNER HANDLERS (All 13 Features)
       ======================================================== */

    /* 1. Live Scan Trigger / Controller */
    function openScanModal() {
      document.getElementById('scan-external-consent').checked = false;
      const m = document.getElementById('modal-scan');
      if (m) m.classList.remove('hidden');
    }

    function closeScanModal() {
      document.getElementById('scan-external-consent').checked = false;
      const m = document.getElementById('modal-scan');
      if (m) m.classList.add('hidden');
    }

    function updateAnalysisSettings(prefix) {
      const mode = document.getElementById(`${prefix}-analysis-mode`).value;
      document.getElementById(`${prefix}-local-model-settings`).hidden = mode !== 'local';
      document.getElementById(`${prefix}-external-model-settings`).hidden = mode !== 'external';
      document.getElementById(`${prefix}-external-consent`).checked = false;
    }

    function analysisSelection(prefix) {
      const mode = document.getElementById(`${prefix}-analysis-mode`).value;
      const selection = { analysis_mode: mode, data_classification: 'sensitive' };
      if (mode === 'local') {
        selection.local_model = document.getElementById(`${prefix}-local-model`).value.trim();
      } else if (mode === 'external') {
        const consent = document.getElementById(`${prefix}-external-consent`);
        if (!consent.checked) throw new Error('Designate this scan as non-sensitive before using an external model.');
        const provider = document.getElementById(`${prefix}-external-provider`).value;
        const model = document.getElementById(`${prefix}-external-model`).value.trim();
        if (!model) throw new Error('Enter the external provider model ID.');
        selection.external_model = `${provider}/${model}`;
        selection.data_classification = 'non_sensitive';
        consent.checked = false;
      }
      return selection;
    }

    function validateSubmission(workflow, bannerId) {
      DashboardSemantics.showLaunchError(bannerId, null);
      const forms = window.AgentScanForms;
      if (!forms) {
        DashboardSemantics.showLaunchError(bannerId, 'Form validation is unavailable. Reload the dashboard before submitting.');
        return false;
      }
      forms.clear(workflow);
      const result = forms.validate(workflow);
      if (!result.valid) {
        const first = Object.values(result.errors || {})[0] || 'Review the highlighted fields.';
        DashboardSemantics.showLaunchError(bannerId, first);
        return false;
      }
      return true;
    }

    async function triggerScanAction() {
      if (!validateSubmission('scan', 'scan-launch-error')) return;
      const formValues = AgentScanForms.getValues('scan');
      const btn = document.getElementById('btn-trigger-scan');
      const cancelBtn = document.getElementById('btn-cancel-scan');
      const logBox = document.getElementById('scan-log-box');
      const badge = document.getElementById('scan-status-badge');
      const bar = document.getElementById('scan-progress-bar');

      let target;
      const mode = formValues.mode;
      const concurrency = formValues.concurrency;

      let analysis;
      try {
        target = DashboardSemantics.targetEndpoint(document.getElementById('scan-target-url').value, ['http:', 'https:', 'ws:', 'wss:', 'mcp+sse:', 'mcp+sses:']);
        analysis = analysisSelection('scan');
      } catch (error) {
        DashboardSemantics.showLaunchError('scan-launch-error', error.message);
        if (logBox) logBox.innerText = `[SCAN ERROR] ${error.message}`;
        showToast(error.message);
        return;
      }

      if (btn) btn.classList.add('opacity-50', 'pointer-events-none');
      if (cancelBtn) cancelBtn.classList.remove('opacity-50', 'pointer-events-none');
      if (badge) { badge.innerText = 'LAUNCHING'; badge.className = 'assessment-badge status-neutral'; }
      const priorErrors = document.getElementById('scan-assessment-errors');
      if (priorErrors) priorErrors.replaceChildren();
      if (bar) bar.style.width = '0%';
      if (logBox) logBox.innerText = `[SCAN-CONTROLLER] Launching ${mode} mode scan against: ${target}\n[SCAN-CONTROLLER] Analysis: ${analysis.analysis_mode}\n[SCAN-CONTROLLER] Concurrency: ${concurrency}`;

      try {
        const data = await DashboardSemantics.requestJSON('/api/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ...formValues, target_url: target, exploit: mode === 'ACTIVE', deep: mode === 'DEEP', concurrency, ...analysis })
        }, 'scan');
        if (badge) { badge.innerText = 'RUNNING'; badge.className = 'assessment-badge status-neutral'; }
        if (logBox) logBox.innerText += `\n[SCAN-CONTROLLER] Scan dispatched. Task ID: ${data.scan_id || 'Not provided'}\n[SCAN-CONTROLLER] Polling status...`;

        if (scanPollTimer) clearInterval(scanPollTimer);
        scanPollTimer = setInterval(async () => {
          try {
            const statusData = await DashboardSemantics.requestJSON('/api/scan/status');
            DashboardSemantics.showLaunchError('scan-launch-error', null);
            const evaluated = Number(statusData.tests_run) || 0;
            const selected = Number(statusData.tests_selected) || 0;
            const modalErrors = document.getElementById('scan-assessment-errors');
            if (modalErrors) modalErrors.innerHTML = DashboardSemantics.assessmentErrorMarkup({
              ...statusData,
              status: ({ completed: 'COMPLETE', failed: 'ERROR', inconclusive: 'INCONCLUSIVE', running: 'RUNNING' })[statusData.status] || statusData.status,
              module_errors: [...(Array.isArray(statusData.module_errors) ? statusData.module_errors : []), ...(statusData.error ? [{ error: statusData.error, error_id: statusData.error_id }] : [])]
            });
            if (bar) bar.style.width = `${selected ? Math.min(100, evaluated / selected * 100) : 0}%`;
            if (logBox) logBox.innerText += `\n[SCAN] Status: ${statusData.status} • Evaluated checks: ${evaluated}/${selected}`;

            if (['completed', 'inconclusive', 'failed', 'cancelled', 'idle'].includes(statusData.status)) {
              clearInterval(scanPollTimer);
              scanPollTimer = null;
              const tone = statusData.status === 'completed' ? 'complete' : statusData.status === 'failed' ? 'error' : 'warning';
              if (badge) { badge.innerText = String(statusData.status).toUpperCase(); badge.className = `assessment-badge status-${tone}`; }
              if (btn) btn.classList.remove('opacity-50', 'pointer-events-none');
              if (cancelBtn) cancelBtn.classList.add('opacity-50', 'pointer-events-none');
              if (logBox) logBox.innerText += `\n[SCAN] Execution ended: ${statusData.status}. Review assessment coverage and module errors.`;
              showToast(`Scan ${statusData.status}`);
              loadAllTelemetry();
            }
          } catch (err) {
            DashboardSemantics.showLaunchError('scan-launch-error', 'Scan status could not refresh. The scan may still be running. ' + err.message);
          }
        }, 1500);

      } catch (err) {
        DashboardSemantics.showLaunchError('scan-launch-error', err.message);
        if (badge) { badge.innerText = 'LAUNCH ERROR'; badge.className = 'assessment-badge status-error'; }
        if (logBox) logBox.innerText += `\n[SCAN ERROR] ${err.message}`;
        if (btn) btn.classList.remove('opacity-50', 'pointer-events-none');
        if (cancelBtn) cancelBtn.classList.add('opacity-50', 'pointer-events-none');
      }
    }

    async function cancelScanAction() {
      try {
        await DashboardSemantics.requestJSON('/api/scan/cancel', { method: 'POST' });
        if (scanPollTimer) clearInterval(scanPollTimer);
        const badge = document.getElementById('scan-status-badge');
        if (badge) { badge.innerText = 'CANCELLED'; badge.className = 'px-2.5 py-0.5 rounded-full font-bold bg-slate-100 text-slate-700'; }
        const logBox = document.getElementById('scan-log-box');
        if (logBox) logBox.innerText += '\n[SCAN-CONTROLLER] Scan cancelled by operator.';
        const btn = document.getElementById('btn-trigger-scan');
        const cancelBtn = document.getElementById('btn-cancel-scan');
        if (btn) btn.classList.remove('opacity-50', 'pointer-events-none');
        if (cancelBtn) cancelBtn.classList.add('opacity-50', 'pointer-events-none');
        showToast("Scan cancelled");
      } catch (err) {
        DashboardSemantics.showLaunchError('scan-launch-error', err.message);
        showToast('Cancel error: ' + err.message);
      }
    }

    /* 2. Target Discovery Wizard */
    function openDiscoveryModal() {
      const m = document.getElementById('modal-discovery');
      if (m) m.classList.remove('hidden');
    }

    function closeDiscoveryModal() {
      const m = document.getElementById('modal-discovery');
      if (m) m.classList.add('hidden');
    }

    let lastDiscoveredManifest = null;
    async function triggerDiscoveryAction() {
      if (!validateSubmission('discovery', 'discovery-launch-error')) return;
      const formValues = AgentScanForms.getValues('discovery');
      let target;
      const mode = formValues.mode;
      const autoProbe = (document.getElementById('discovery-auto-probe') || {}).checked;
      const resEl = document.getElementById('discovery-results');
      const badge = document.getElementById('discovery-count-badge');
      const saveBtn = document.getElementById('btn-save-manifest');
      const discoveryErrors = document.getElementById('discovery-assessment-errors');
      if (discoveryErrors) discoveryErrors.replaceChildren();
      lastDiscoveredManifest = null;
      if (saveBtn) saveBtn.classList.add('opacity-50', 'pointer-events-none');

      try {
        target = DashboardSemantics.targetEndpoint(document.getElementById('discovery-target').value);
        if (resEl) resEl.innerText = `[DISCOVERY] Probing ${target} via ${mode}...`;
        const data = await DashboardSemantics.requestJSON('/api/discovery', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ...formValues, target_url: target, mode, no_exploit: !autoProbe })
        }, 'discovery');
        const attemptErrors = (data.errors || []).map(item => ({ module_name: item.transport || 'Discovery', error: item.message || item.error || 'The discovery attempt could not complete.', error_id: item.error_id }));
        if (discoveryErrors) discoveryErrors.innerHTML = DashboardSemantics.assessmentErrorMarkup({ status: data.success === false ? 'ERROR' : 'COMPLETE', assessment_scope: 'discovery', module_errors: attemptErrors });
        if (data.success === false) {
          if (badge) badge.innerText = 'DISCOVERY FAILED';
          throw new Error(DashboardSemantics.responseError({ ...data, error: data.error || data.message || 'Discovery could not identify a supported agent endpoint.' }, 200));
        }
        lastDiscoveredManifest = data;
        const routes = Array.isArray(data.endpoints) ? data.endpoints : (Array.isArray(data.routes) ? data.routes : []);
        if (badge) badge.innerText = `${routes.length} Routes Discovered`;
        if (resEl) resEl.innerText = JSON.stringify(data, null, 2);
        if (saveBtn) saveBtn.classList.remove('opacity-50', 'pointer-events-none');
        showToast(`Discovered ${routes.length} target routes`);
      } catch (err) {
        DashboardSemantics.showLaunchError('discovery-launch-error', err.message);
        if (resEl) resEl.innerText = `[DISCOVERY ERROR] ${err.message}`;
      }
    }

    async function saveDiscoveredManifestAction() {
      if (!lastDiscoveredManifest) return;
      try {
        const data = await DashboardSemantics.requestJSON('/api/discovery/save', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ manifest: lastDiscoveredManifest })
        });
        showToast(data.message || "Agent manifest saved successfully");
        loadAllTelemetry();
      } catch (err) {
        DashboardSemantics.showLaunchError('discovery-launch-error', err.message);
        showToast('Save error: ' + err.message);
      }
    }

    /* 3. Static Audit Runner */
    function openAuditModal() {
      const m = document.getElementById('modal-audit');
      if (m) m.classList.remove('hidden');
    }

    function closeAuditModal() {
      const m = document.getElementById('modal-audit');
      if (m) m.classList.add('hidden');
    }

    async function triggerAuditAction() {
      if (!validateSubmission('audit', 'audit-launch-error')) return;
      const formValues = AgentScanForms.getValues('audit');
      const path = (document.getElementById('audit-codebase-path') || {}).value || '.';
      const ruleset = (document.getElementById('audit-ruleset') || {}).value || 'default';
      const resEl = document.getElementById('audit-results');
      const badge = document.getElementById('audit-findings-count');
      const auditErrors = document.getElementById('audit-assessment-errors');
      if (auditErrors) auditErrors.replaceChildren();

      if (resEl) resEl.innerText = `[AUDIT] Analyzing ${path} with ${ruleset} ruleset...`;

      try {
        const data = await DashboardSemantics.requestJSON('/api/audit', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ...formValues, path, ruleset })
        }, 'audit');
        const findings = Array.isArray(data.findings) ? data.findings : [];
        if (badge) badge.innerText = `${findings.length} Violations`;
        if (resEl) resEl.innerText = JSON.stringify(data, null, 2);
        if (auditErrors) auditErrors.innerHTML = DashboardSemantics.assessmentErrorMarkup({
          status: data.status, assessment_scope: 'audit',
          module_outcomes: (data.coverage || []).map(item => ({ module_name: item.module, status: item.status === 'NOT_ASSESSED' ? 'INCONCLUSIVE' : item.status, reason: (item.limitations || []).join('; ') }))
        });
        showToast(`Static audit ${data.status || 'status unavailable'}: ${findings.length} recorded findings`);
      } catch (err) {
        DashboardSemantics.showLaunchError('audit-launch-error', err.message);
        if (resEl) resEl.innerText = `[AUDIT ERROR] ${err.message}`;
      }
    }

    /* 4. AIBOM Export / Viewer */
    async function openAibomModal() {
      const m = document.getElementById('modal-aibom');
      if (m) m.classList.remove('hidden');
      const out = document.getElementById('aibom-json-output');
      if (out) out.innerText = "Fetching CycloneDX 1.6 AIBOM specification...";

      try {
        const data = await DashboardSemantics.requestJSON('/api/aibom');
        if (out) out.innerText = JSON.stringify(data, null, 2);
        const modelsEl = document.getElementById('aibom-model-count');
        if (modelsEl && data.metadata && data.metadata.models) {
          modelsEl.innerText = `${data.metadata.models.length} Registered`;
        }
      } catch (err) {
        if (out) out.innerText = `[AIBOM ERROR] ${err.message}`;
      }
    }

    function closeAibomModal() {
      const m = document.getElementById('modal-aibom');
      if (m) m.classList.add('hidden');
    }

    /* 5. Transitive Dependency Graph */
    async function openDependenciesModal() {
      const m = document.getElementById('modal-dependencies');
      if (m) m.classList.remove('hidden');
      const container = document.getElementById('dependencies-tree-container');
      const badge = document.getElementById('dep-count-badge');
      if (container) container.innerHTML = '<div class="text-[#888888]">Loading lockfile dependency graph...</div>';

      try {
        const data = await DashboardSemantics.requestJSON('/api/dependencies/graph');
        rawDependencyGraph = data;
        const pkgs = Array.isArray(data.packages) ? data.packages : (data.nodes || []);
        if (badge) badge.innerText = `${pkgs.length} Packages Resolved`;

        let html = '';
        pkgs.forEach(p => {
          const name = p.name || p.id || 'package';
          const ver = p.version || 'latest';
          const isVuln = Boolean(p.vulnerable);
          html += `
            <div class="p-2.5 rounded-xl bg-white border border-[#1A1A1A]/10 flex items-center justify-between">
              <div>
                <span class="font-bold text-[#1A1A1A]">${escapeHtml(name)}</span>
                <span class="text-[10px] text-[#666666] ml-2">v${escapeHtml(ver)}</span>
              </div>
              <span class="text-[10px] font-bold px-2 py-0.5 rounded-full ${isVuln ? 'bg-[#FAF0EB] text-[#B84E28] border border-[#ECCFC2]' : 'bg-[#EEF6F4] text-[#1E5E54] border border-[#CFE5E1]'}">
                ${isVuln ? 'VULNERABLE' : 'NO RECORDED FINDING'}
              </span>
            </div>
          `;
        });
        if (container) container.innerHTML = html || '<div class="text-[#888888]">No packages found in dependency graph.</div>';
      } catch (err) {
        if (container) container.innerHTML = `<div class="text-[#B84E28] font-mono">Error: ${escapeHtml(DashboardSemantics.errorText(err.message))}</div>`;
      }
    }

    function filterDependencyTree(query) {
      if (!rawDependencyGraph) return;
      const q = (query || '').toLowerCase();
      const container = document.getElementById('dependencies-tree-container');
      const pkgs = Array.isArray(rawDependencyGraph.packages) ? rawDependencyGraph.packages : (rawDependencyGraph.nodes || []);
      const filtered = pkgs.filter(p => (p.name || p.id || '').toLowerCase().includes(q));

      let html = '';
      filtered.forEach(p => {
        const name = p.name || p.id || 'package';
        const ver = p.version || 'latest';
        const isVuln = Boolean(p.vulnerable);
        html += `
          <div class="p-2.5 rounded-xl bg-white border border-[#1A1A1A]/10 flex items-center justify-between">
            <div>
              <span class="font-bold text-[#1A1A1A]">${escapeHtml(name)}</span>
              <span class="text-[10px] text-[#666666] ml-2">v${escapeHtml(ver)}</span>
            </div>
            <span class="text-[10px] font-bold px-2 py-0.5 rounded-full ${isVuln ? 'bg-[#FAF0EB] text-[#B84E28] border border-[#ECCFC2]' : 'bg-[#EEF6F4] text-[#1E5E54] border border-[#CFE5E1]'}">
              ${isVuln ? 'VULNERABLE' : 'NO RECORDED FINDING'}
            </span>
          </div>
        `;
      });
      if (container) container.innerHTML = html || '<div class="text-[#888888]">No packages matched search filter.</div>';
    }

    function closeDependenciesModal() {
      const m = document.getElementById('modal-dependencies');
      if (m) m.classList.add('hidden');
    }

    /* 6. Calibration Runner */
    function openCalibrateModal() {
      const m = document.getElementById('modal-calibrate');
      if (m) m.classList.remove('hidden');
    }

    function closeCalibrateModal() {
      const m = document.getElementById('modal-calibrate');
      if (m) m.classList.add('hidden');
    }

    async function triggerCalibrationAction() {
      if (!validateSubmission('calibration', 'calibration-launch-error')) return;
      const formValues = AgentScanForms.getValues('calibration');
      const model = document.getElementById("calibrate-local-model").value;
      const out = document.getElementById('calibrate-results');

      if (out) out.innerText = `[LOCAL MODEL] Checking synthetic controls with ${model}...`;

      try {
        const data = await DashboardSemantics.requestJSON('/api/calibrate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ...formValues, model })
        }, 'calibration');
        if (out) out.innerText = JSON.stringify(data, null, 2);
        showToast(data.passed ? "Synthetic local controls passed" : "Local controls failed or unavailable");
      } catch (err) {
        DashboardSemantics.showLaunchError('calibration-launch-error', err.message);
        if (out) out.innerText = `[CALIBRATION ERROR] ${err.message}`;
      }
    }

    /* 7. Benchmark Suite */
    function openBenchmarkModal() {
      const m = document.getElementById('modal-benchmark');
      if (m) m.classList.remove('hidden');
    }

    function closeBenchmarkModal() {
      const m = document.getElementById('modal-benchmark');
      if (m) m.classList.add('hidden');
    }

    async function triggerBenchmarkAction() {
      const out = document.getElementById('benchmark-results');

      if (out) out.innerText = '[BENCHMARK] Running built-in synthetic fixtures...';

      try {
        const data = await DashboardSemantics.requestJSON('/api/benchmark/run', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({})
        });
        if (out) out.innerText = JSON.stringify(data, null, 2);
        showToast(data.discriminates ? "Synthetic fixture check passed" : "Synthetic fixture check failed");
      } catch (err) {
        if (out) out.innerText = `[BENCHMARK ERROR] ${err.message}`;
      }
    }

    /* 8. Sentinel Watcher & Canary Probes */
    function openSentinelModal() {
      const m = document.getElementById('modal-sentinel');
      if (m) m.classList.remove('hidden');
    }

    function closeSentinelModal() {
      const m = document.getElementById('modal-sentinel');
      if (m) m.classList.add('hidden');
    }

    async function startSentinelWatcherAction() {
      if (!validateSubmission('sentinel', 'sentinel-launch-error')) return;
      const formValues = AgentScanForms.getValues('sentinel');
      let target;
      const interval = formValues.interval_seconds;
      const webhook = formValues.webhook_url;
      const badge = document.getElementById('sentinel-status-inline');

      try {
        target = DashboardSemantics.targetEndpoint(document.getElementById('sentinel-target-url').value);
        const data = await DashboardSemantics.requestJSON('/api/sentinel/start', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ...formValues, target_url: target, interval_seconds: interval, webhook_url: webhook })
        }, 'sentinel');
        if (badge) badge.innerText = 'ACTIVE POLLING';
        const startBtn = document.getElementById('btn-sentinel-start');
        const stopBtn = document.getElementById('btn-sentinel-stop');
        if (startBtn) startBtn.classList.add('opacity-50', 'pointer-events-none');
        if (stopBtn) stopBtn.classList.remove('opacity-50', 'pointer-events-none');
        showToast("Sentinel surveillance watcher started");
        loadAllTelemetry();
      } catch (err) {
        DashboardSemantics.showLaunchError('sentinel-launch-error', err.message);
        showToast("Sentinel start error: " + err.message);
      }
    }

    async function stopSentinelWatcherAction() {
      try {
        await DashboardSemantics.requestJSON('/api/sentinel/stop', { method: 'POST' });
        const badge = document.getElementById('sentinel-status-inline');
        if (badge) badge.innerText = 'STANDBY / STOPPED';
        const startBtn = document.getElementById('btn-sentinel-start');
        const stopBtn = document.getElementById('btn-sentinel-stop');
        if (startBtn) startBtn.classList.remove('opacity-50', 'pointer-events-none');
        if (stopBtn) stopBtn.classList.add('opacity-50', 'pointer-events-none');
        showToast("Sentinel surveillance watcher stopped");
        loadAllTelemetry();
      } catch (err) {
        DashboardSemantics.showLaunchError('sentinel-launch-error', err.message);
        showToast('Sentinel stop error: ' + err.message);
      }
    }

    async function runSentinelProbeAction() {
      if (!validateSubmission('sentinelProbe', 'sentinel-launch-error')) return;
      const formValues = AgentScanForms.getValues('sentinelProbe');
      try {
        const target = DashboardSemantics.targetEndpoint(document.getElementById('sentinel-target-url').value);
        showToast("Running the canary probe against your configured agent...");
        const data = await DashboardSemantics.requestJSON('/api/sentinel/probe', {
          method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ target_url: target })
        }, 'sentinelProbe');
        showToast(`Canary probe ended: ${data.status || 'Unavailable'}`);
        loadAllTelemetry();
      } catch (err) {
        DashboardSemantics.showLaunchError('sentinel-launch-error', err.message);
        showToast("Probe error: " + err.message);
      }
    }

    /* 9. Native MCP Tool Harness */
    function openMcpTestModal(toolName) {
      const m = document.getElementById('modal-mcp');
      if (m) m.classList.remove('hidden');

      const sel = document.getElementById('mcp-tool-select');
      if (sel) {
        if (globalTelemetry.mcp && Array.isArray(globalTelemetry.mcp.tools) && globalTelemetry.mcp.tools.length > 0) {
          const currentVal = toolName || sel.value;
          sel.innerHTML = globalTelemetry.mcp.tools.map(t => {
            const desc = t.description ? (t.description.length > 60 ? t.description.slice(0, 60) + '...' : t.description) : '';
            return `<option value="${escapeHtml(t.name)}">${escapeHtml(t.name)} (${escapeHtml(desc)})</option>`;
          }).join('');
          if (currentVal && Array.from(sel.options).some(o => o.value === currentVal)) {
            sel.value = currentVal;
          }
        }
        if (toolName) {
          sel.value = toolName;
        }
        updateMcpSampleArgs(sel.value);
      }
    }

    function closeMcpTestModal() {
      const m = document.getElementById('modal-mcp');
      if (m) m.classList.add('hidden');
    }

    function updateMcpSampleArgs(toolName) {
      const argsArea = document.getElementById('mcp-tool-args');
      if (!argsArea) return;
      if (toolName === 'agentscan_list_attacks') {
        argsArea.value = '{}';
      } else if (toolName === 'agentscan_audit') {
        argsArea.value = '{\n  "path": ".",\n  "offline": true\n}';
      } else if (toolName === 'agentscan_scan' || toolName === 'scan_target') {
        argsArea.value = '{\n  "target_url": "",\n  "timeout": 30\n}';
      } else if (toolName === 'agentscan_swarm') {
        argsArea.value = '{\n  "target_url": "",\n  "team": "trio",\n  "rounds": 3,\n  "offline": true\n}';
      } else {
        argsArea.value = '{}';
      }
    }

    async function invokeMcpToolAction() {
      if (!validateSubmission('mcp', 'mcp-launch-error')) return;
      const formValues = AgentScanForms.getValues('mcp');
      const tool = (document.getElementById('mcp-tool-select') || {}).value || 'scan_target';
      const argsRaw = (document.getElementById('mcp-tool-args') || {}).value || '{}';
      const out = document.getElementById('mcp-tool-response');

      let parsedArgs = {};
      try {
        parsedArgs = JSON.parse(argsRaw);
      } catch {
        DashboardSemantics.showLaunchError('mcp-launch-error', 'Invalid JSON in arguments input.');
        if (out) out.innerText = "[ERROR] Invalid JSON in arguments input.";
        return;
      }

      try {
        if (['agentscan_scan', 'scan_target', 'agentscan_swarm'].includes(tool)) {
          parsedArgs.target_url = DashboardSemantics.targetEndpoint(parsedArgs.target_url || parsedArgs.target, tool === 'agentscan_swarm' ? ['http:', 'https:'] : ['http:', 'https:', 'ws:', 'wss:', 'mcp+sse:', 'mcp+sses:']);
          delete parsedArgs.target;
        }
        if (out) out.innerText = `[MCP JSON-RPC 2.0] Dispatching invoke request for '${tool}'...`;
        const data = await DashboardSemantics.requestJSON('/api/mcp/invoke', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ...formValues, tool, arguments: parsedArgs })
        }, 'mcp');
        if (out) out.innerText = JSON.stringify(data, null, 2);
        showToast(`MCP Tool '${tool}' returned a response`);
      } catch (err) {
        DashboardSemantics.showLaunchError('mcp-launch-error', err.message);
        if (out) out.innerText = `[MCP RPC ERROR] ${err.message}`;
      }
    }

    /* 10. Offensive Swarm Runner */
    function openSwarmModal() {
      document.getElementById('swarm-external-consent').checked = false;
      const m = document.getElementById('modal-swarm');
      if (m) m.classList.remove('hidden');
    }

    function closeSwarmModal() {
      document.getElementById('swarm-external-consent').checked = false;
      const m = document.getElementById('modal-swarm');
      if (m) m.classList.add('hidden');
    }

    async function triggerSwarmAction() {
      if (!validateSubmission('swarm', 'swarm-launch-error')) return;
      const formValues = AgentScanForms.getValues('swarm');
      const strategy = formValues.team;
      const rounds = formValues.max_rounds;
      let target;
      const logBox = document.getElementById('swarm-execution-log');

      let analysis;
      try {
        target = DashboardSemantics.targetEndpoint(document.getElementById('swarm-target-url').value);
        analysis = analysisSelection('swarm');
      } catch (error) {
        DashboardSemantics.showLaunchError('swarm-launch-error', error.message);
        if (logBox) logBox.innerText = `[SWARM ERROR] ${error.message}`;
        showToast(error.message);
        return;
      }
      if (logBox) logBox.innerText = `[SWARM-RUNNER] Initializing ${strategy} at ${target}...\n[SWARM] Analysis: ${analysis.analysis_mode}`;

      try {
        const data = await DashboardSemantics.requestJSON('/api/swarms/run', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ...formValues, team: strategy, target_url: target, max_rounds: rounds, ...analysis })
        }, 'swarm');
        if (logBox) logBox.innerText = JSON.stringify(data, null, 2);
        showToast("Swarm campaign finished. Blackboard updated.");
        loadAllTelemetry();
      } catch (err) {
        DashboardSemantics.showLaunchError('swarm-launch-error', err.message);
        if (logBox) logBox.innerText += `\n[SWARM ERROR] ${err.message}`;
      }
    }

    async function clearSwarmBlackboardAction() {
      try {
        await DashboardSemantics.requestJSON('/api/swarms/blackboard/clear', { method: 'POST' });
        showToast("Swarm blackboard cleared");
        loadAllTelemetry();
      } catch (err) {
        DashboardSemantics.showLaunchError('swarm-launch-error', err.message);
        showToast('Clear error: ' + err.message);
      }
    }

    /* 11. Self-Healing Disk Patch Application */
    function openHealApplyModal() {
      const m = document.getElementById('modal-heal-apply');
      if (m) m.classList.remove('hidden');
      const listEl = document.getElementById('heal-apply-affected-files');
      const paths = (globalTelemetry.heal && Array.isArray(globalTelemetry.heal.paths_affected)) ? globalTelemetry.heal.paths_affected : [];
      if (listEl) {
        listEl.innerHTML = paths.map(p => `<li><code>${escapeHtml(p)}</code> (planned change; review the diff)</li>`).join('');
      }
    }

    function closeHealApplyModal() {
      const m = document.getElementById('modal-heal-apply');
      if (m) m.classList.add('hidden');
    }

    async function applyHealFixesAction() {
      if (!validateSubmission('healApply', 'heal-apply-launch-error')) return;
      const formValues = AgentScanForms.getValues('healApply');
      const backup = (document.getElementById('heal-apply-backup-check') || {}).checked;
      const resEl = document.getElementById('heal-apply-results');
      if (resEl) resEl.innerText = "[AUTO-HEAL] Writing AST modifications to disk...";

      try {
        const data = await DashboardSemantics.requestJSON('/api/heal/apply', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ...formValues, backup })
        }, 'healApply');
        if (resEl) resEl.innerText = JSON.stringify(data, null, 2);
        showToast("Patch application returned a result. Review applied and skipped changes.");
        loadAllTelemetry();
      } catch (err) {
        DashboardSemantics.showLaunchError('heal-apply-launch-error', err.message);
        if (resEl) resEl.innerText = `[HEAL ERROR] ${err.message}`;
      }
    }

    /* 12. Autonomous Self-Healing Server Simulator */
    async function openHealServerModal() {
      const m = document.getElementById('modal-heal-server');
      if (m) m.classList.remove('hidden');
      const badge = document.getElementById('heal-server-status-badge');
      try {
        const data = await DashboardSemantics.requestJSON('/api/heal/server/status');
        if (badge) badge.innerText = data.status || 'UNKNOWN';
      } catch (err) {
        if (badge) badge.innerText = 'UNAVAILABLE';
        DashboardSemantics.showLaunchError('heal-simulation-launch-error', err.message);
      }
    }

    function closeHealServerModal() {
      const m = document.getElementById('modal-heal-server');
      if (m) m.classList.add('hidden');
    }

    async function simulateHealAlertAction() {
      if (!validateSubmission('healSimulation', 'heal-simulation-launch-error')) return;
      const formValues = AgentScanForms.getValues('healSimulation');
      const file = (document.getElementById('heal-sim-file') || {}).value || 'tests/fixtures/sample_agent.py';
      const vulnClass = (document.getElementById('heal-sim-type') || {}).value || 'PROMPT_INJECTION';
      const evidence = (document.getElementById('heal-sim-evidence') || {}).value || 'Adversarial payload breached boundary';
      const out = document.getElementById('heal-sim-output');

      if (out) out.innerText = '[SIMULATOR] Running the configured local healing simulation...';

      try {
        const data = await DashboardSemantics.requestJSON('/api/heal/server/simulate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ...formValues, file, vulnerability_type: vulnClass, evidence })
        }, 'healSimulation');
        if (out) out.innerText = JSON.stringify(data, null, 2);
        showToast("Simulation completed. Review its recorded outcome.");
        loadAllTelemetry();
      } catch (err) {
        DashboardSemantics.showLaunchError('heal-simulation-launch-error', err.message);
        if (out) out.innerText = `[SIMULATION ERROR] ${err.message}`;
      }
    }

    /* 13. Telemetry Event Injection */
    function openEventInjectModal() {
      const m = document.getElementById('modal-event-inject');
      if (m) m.classList.remove('hidden');
    }

    function closeEventInjectModal() {
      const m = document.getElementById('modal-event-inject');
      if (m) m.classList.add('hidden');
    }

    async function injectEventAction() {
      if (!validateSubmission('event', 'event-launch-error')) return;
      const formValues = AgentScanForms.getValues('event');
      const evType = (document.getElementById('event-inject-type') || {}).value || 'finding';
      const payloadRaw = (document.getElementById('event-inject-payload') || {}).value || '{}';

      let parsedPayload = {};
      try {
        parsedPayload = JSON.parse(payloadRaw);
      } catch {
        DashboardSemantics.showLaunchError('event-launch-error', 'Invalid JSON payload.');
        showToast("Invalid JSON payload");
        return;
      }

      try {
        const data = await DashboardSemantics.requestJSON('/api/events', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ...formValues, type: evType, data: parsedPayload })
        }, 'event');
        showToast(`Dispatched '${evType}' event to SSE bus`);
        closeEventInjectModal();
      } catch (err) {
        DashboardSemantics.showLaunchError('event-launch-error', err.message);
        showToast("Injection error: " + err.message);
      }
    }

    /* 14. Network Traffic Frame Modal */
    function openTrafficFrameModal(seq) {
      const m = document.getElementById('modal-traffic-frame');
      if (!m) return;

      const entries = (globalTelemetry.traffic && Array.isArray(globalTelemetry.traffic.entries)) ? globalTelemetry.traffic.entries : [];
      const frame = entries.find(e => e.seq === seq) || entries[seq] || {};

      const titleEl = document.getElementById('traffic-frame-title');
      if (titleEl) titleEl.innerText = `Traffic Frame #${seq !== undefined ? seq : 0}`;
      const subEl = document.getElementById('traffic-frame-subtitle');
      if (subEl) subEl.innerText = `Module: ${escapeHtml(frame.module_name || frame.module_id || 'http_tracer')} • Kind: ${escapeHtml(frame.kind || 'REQUEST')}`;

      const reqEl = document.getElementById('traffic-frame-req');
      if (reqEl) reqEl.innerText = JSON.stringify(frame.request || {}, null, 2);
      const respEl = document.getElementById('traffic-frame-resp');
      if (respEl) respEl.innerText = JSON.stringify(frame.response || {}, null, 2);

      m.classList.remove('hidden');
    }

    function closeTrafficFrameModal() {
      const m = document.getElementById('modal-traffic-frame');
      if (m) m.classList.add('hidden');
    }

    /* Fix Bug 5: Dynamic SSE Status Indicator attached to EventSource events */
    function updateSseStatus(status) {
      const dot = document.getElementById('sse-indicator-dot');
      const text = document.getElementById('sse-indicator-text');
      if (!dot || !text) return;

      if (status === 'connected') {
        dot.className = 'w-2 h-2 rounded-full bg-emerald-500 animate-pulse';
        text.className = 'text-[11px] font-mono font-bold text-[#1E5E54]';
        text.innerText = 'Live SSE Connected';
        DashboardSemantics.showLaunchError('dashboard-stream-error', null);
      } else if (status === 'error') {
        dot.className = 'w-2 h-2 rounded-full bg-rose-500';
        text.className = 'text-[11px] font-mono font-bold text-[#B84E28]';
        text.innerText = 'SSE Reconnecting...';
        DashboardSemantics.showLaunchError('dashboard-stream-error', 'Live event updates disconnected. The browser is reconnecting. Refresh to fetch the current status; the event stream does not provide a detailed failure cause.');
      } else {
        dot.className = 'w-2 h-2 rounded-full bg-amber-400 animate-pulse';
        text.className = 'text-[11px] font-mono font-bold text-[#666666]';
        text.innerText = 'SSE Connecting...';
      }
    }

    function initEventStream() {
      if (typeof EventSource === 'undefined') return;
      try {
        const es = new EventSource('/api/events');

        es.onopen = () => {
          updateSseStatus('connected');
        };

        es.onerror = () => {
          updateSseStatus('error');
        };

        es.addEventListener('ping', () => {
          updateSseStatus('connected');
        });

        const refreshEvents = [
          'scan:complete', 'scan:inconclusive', 'scan:error', 'scan:cancel', 'sentinel:alert', 'sentinel:error', 'sentinel:stop',
          'swarm:turn', 'swarm:intel', 'swarm:intel_clear',
          'heal:applied', 'heal:alert_ingested', 'reload', 'finding'
        ];
        refreshEvents.forEach(evt => {
          es.addEventListener(evt, (e) => {
            loadAllTelemetry();
            if (evt === 'scan:complete') showToast('Scan execution completed');
            if (evt === 'scan:inconclusive') showToast('Scan coverage is incomplete. Review module outcomes.');
            if (evt === 'scan:error') showToast('Scan execution failed. Review module errors.');
            if (evt === 'sentinel:error') showToast('Sentinel watcher failed. Review its error and diagnostic reference.');
            if (evt === 'sentinel:alert') showToast('Sentinel canary leak detected!');
            if (evt === 'heal:applied') showToast('Self-healing patch applied');
            if (evt === 'reload') showToast('Live update received from scanner');
            if (evt === 'finding') showToast('New vulnerability finding detected');
          });
        });

        es.addEventListener('scan:start', () => {
          globalTelemetry.report = null;
          globalTelemetry.findings = [];
          renderOverview();
          showToast('Scan execution started');
        });

        es.addEventListener('scan:progress', (e) => {
          try {
            const data = JSON.parse(e.data);
            if (data && data.progress !== undefined) {
              const pBar = document.getElementById('scan-progress-bar');
              if (pBar) pBar.style.width = `${data.progress}%`;
            }
          } catch {}
        });

        es.addEventListener('sentinel:probe', () => {
          showToast('Sentinel probe executed');
        });

        es.addEventListener('sentinel_alert', () => {
          showToast('Sentinel canary leak alert received!');
          loadAllTelemetry();
        });

        es.addEventListener('probe', () => {
          showToast('Test probe executed');
        });
      } catch (err) {
        console.warn('SSE stream init warning:', err);
        updateSseStatus('error');
      }
    }

    /* Font Switching & Persistence */
    function switchWebsiteFont(fontChoice) {
      const rootBody = document.body;
      const monoEls = document.querySelectorAll('.font-mono, code, pre, kbd, samp');
      const select = document.getElementById('font-switcher-select');
      if (select && select.value !== fontChoice) select.value = fontChoice;

      if (fontChoice === 'geist-pixel') {
        rootBody.style.fontFamily = "'Geist Pixel', -apple-system, sans-serif";
        monoEls.forEach(el => el.style.setProperty('font-family', "'Geist Pixel', monospace", 'important'));
        localStorage.setItem('agentscan_font', 'geist-pixel');
      } else if (fontChoice === 'geist-mono') {
        rootBody.style.fontFamily = "-apple-system, sans-serif";
        monoEls.forEach(el => el.style.setProperty('font-family', "'Geist Mono', monospace", 'important'));
        localStorage.setItem('agentscan_font', 'geist-mono');
      } else if (fontChoice === 'ibm-plex') {
        rootBody.style.fontFamily = "-apple-system, sans-serif";
        monoEls.forEach(el => el.style.setProperty('font-family', "'IBM Plex Mono', monospace", 'important'));
        localStorage.setItem('agentscan_font', 'ibm-plex');
      } else if (fontChoice === 'original') {
        rootBody.style.fontFamily = "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif";
        monoEls.forEach(el => el.style.setProperty('font-family', "'Geist Mono', monospace", 'important'));
        localStorage.setItem('agentscan_font', 'original');
      }
    }

    /* Theme Switching & Persistence */
    function initTheme() {
      const savedTheme = localStorage.getItem('agentscan_theme');
      const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
      const isDark = savedTheme ? (savedTheme === 'dark') : prefersDark;
      applyTheme(isDark);
    }

    function applyTheme(isDark) {
      if (isDark) {
        document.documentElement.classList.add('dark');
        document.body.classList.add('dark');
      } else {
        document.documentElement.classList.remove('dark');
        document.body.classList.remove('dark');
      }
      const icon = document.getElementById('theme-toggle-icon');
      if (icon) {
        icon.innerText = isDark ? '☼' : '☾';
      }
    }

    function toggleTheme() {
      const isDark = document.documentElement.classList.contains('dark');
      const newTheme = isDark ? 'light' : 'dark';
      localStorage.setItem('agentscan_theme', newTheme);
      applyTheme(!isDark);
    }

    /* Modal Focus Trap & Accessible Keyboard Management */
    let lastFocusedElement = null;

    function getActiveModal() {
      const modals = document.querySelectorAll('div[id^="modal-"]');
      for (const m of modals) {
        if (!m.classList.contains('hidden')) return m;
      }
      return null;
    }

    function initModalFocusManagement() {
      const modalObserver = new MutationObserver((mutations) => {
        for (const m of mutations) {
          if (m.type === 'attributes' && m.attributeName === 'class') {
            const target = m.target;
            if (target.id && target.id.startsWith('modal-')) {
              if (!target.classList.contains('hidden')) {
                lastFocusedElement = document.activeElement;
                setTimeout(() => {
                  const focusables = Array.from(target.querySelectorAll(
                    'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
                  )).filter(el => el.offsetParent !== null);
                  if (focusables.length > 0) {
                    const firstInput = focusables.find(el => ['INPUT', 'SELECT', 'TEXTAREA'].includes(el.tagName));
                    (firstInput || focusables[0]).focus();
                  }
                }, 50);
              } else if (lastFocusedElement && !getActiveModal()) {
                if (typeof lastFocusedElement.focus === 'function') {
                  lastFocusedElement.focus();
                }
                lastFocusedElement = null;
              }
            }
          }
        }
      });

      document.querySelectorAll('div[id^="modal-"]').forEach(modal => {
        modalObserver.observe(modal, { attributes: true, attributeFilter: ['class'] });
      });
    }

    /* Initialization */
    window.addEventListener('DOMContentLoaded', () => {
      initTheme();
      initModalFocusManagement();
      if (window.AgentScanForms) AgentScanForms.attach();

      const savedFont = localStorage.getItem('agentscan_font') || 'original';
      switchWebsiteFont(savedFont);

      const initialTab = getTabFromUrl();
      switchTab(initialTab);
      loadAllTelemetry();
      initEventStream();

      const searchInput = document.getElementById('top-search-input');
      if (searchInput) {
        searchInput.addEventListener('input', (e) => executeSpotlightSearch(e.target.value));
        searchInput.addEventListener('focus', (e) => executeSpotlightSearch(e.target.value));
      }

      window.addEventListener('keydown', (e) => {
        const activeModal = getActiveModal();
        if (e.key === 'Tab' && activeModal) {
          const focusables = Array.from(activeModal.querySelectorAll(
            'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
          )).filter(el => el.offsetParent !== null);
          if (focusables.length > 0) {
            const firstEl = focusables[0];
            const lastEl = focusables[focusables.length - 1];
            if (e.shiftKey) {
              if (document.activeElement === firstEl || !activeModal.contains(document.activeElement)) {
                e.preventDefault();
                lastEl.focus();
              }
            } else {
              if (document.activeElement === lastEl) {
                e.preventDefault();
                firstEl.focus();
              }
            }
          }
        }

        if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
          e.preventDefault();
          if (searchInput) searchInput.focus();
        }
        if (e.key === 'Escape') {
          closeTopSearch();
          closeProfileModal();
          closeFindingInspector();
          closeScanModal();
          closeDiscoveryModal();
          closeAuditModal();
          closeAibomModal();
          closeDependenciesModal();
          closeCalibrateModal();
          closeBenchmarkModal();
          closeSentinelModal();
          closeMcpTestModal();
          closeSwarmModal();
          closeHealApplyModal();
          closeHealServerModal();
          closeEventInjectModal();
          closeTrafficFrameModal();
        }
        if (e.key === '[' && document.activeElement !== searchInput) {
          toggleSidebar();
        }
      });

      document.addEventListener('click', (e) => {
        const topSearchWrapper = document.getElementById('top-search-wrapper');
        if (topSearchWrapper && !topSearchWrapper.contains(e.target)) {
          closeTopSearch();
        }
      });
    });

