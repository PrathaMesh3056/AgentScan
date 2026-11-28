

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
      gateway: null,
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

    const MOBILE_SIDEBAR_MEDIA = '(max-width: 1023px)';

    function isMobileSidebarViewport() {
      return typeof window.matchMedia === 'function'
        ? window.matchMedia(MOBILE_SIDEBAR_MEDIA).matches
        : window.innerWidth < 1024;
    }

    /* The off-canvas drawer is hidden on mobile, so it must not stay in the
       tab order or the accessibility tree while closed. On desktop the same
       sidebar is always visible and must remain interactive. */
    function syncSidebarA11y(forceOpen) {
      const sb = document.getElementById('sidebar');
      if (!sb) return;
      const trigger = document.getElementById('btn-mobile-menu');
      const isOpen = typeof forceOpen === 'boolean'
        ? forceOpen
        : sb.classList.contains('mobile-open');
      const isHidden = isMobileSidebarViewport() && !isOpen;

      if (isHidden) {
        sb.setAttribute('inert', '');
        sb.setAttribute('aria-hidden', 'true');
      } else {
        sb.removeAttribute('inert');
        sb.removeAttribute('aria-hidden');
      }

      if (trigger) {
        trigger.setAttribute('aria-controls', 'sidebar');
        trigger.setAttribute('aria-expanded', String(isMobileSidebarViewport() && isOpen));
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
      syncSidebarA11y(isOpen);
    }

    syncSidebarA11y();
    if (window.matchMedia) {
      const mobileSidebarMedia = window.matchMedia(MOBILE_SIDEBAR_MEDIA);
      if (typeof mobileSidebarMedia.addEventListener === 'function') {
        mobileSidebarMedia.addEventListener('change', syncSidebarA11y);
      } else if (typeof mobileSidebarMedia.addListener === 'function') {
        mobileSidebarMedia.addListener(syncSidebarA11y);
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
        await loadGatewayStatus();
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
        { name: 'Native MCP Protocol Monitor', id: 'mcp', cat: 'Protocols' },
        { name: 'Runtime Gateway', id: 'gateway', cat: 'Runtime' }
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

    async function loadGatewayStatus() {
      try {
        const data = await DashboardSemantics.requestJSON('/api/gateway/status');
        globalTelemetry.gateway = data;
      } catch (err) {
        globalTelemetry.gateway = { configured: false, status: 'request_failed', reason: 'status_request_failed', health: null, readiness: null, checked_at: null };
      }
      renderGateway();
    }

    function gatewayStatusMeta(status) {
      const raw = status === null || status === undefined ? '' : String(status);
      const recognized = ['ready', 'not_ready', 'unreachable', 'unhealthy', 'misconfigured', 'not_configured', 'request_failed'].includes(raw);
      const value = recognized ? raw : raw;
      const tones = { ready: 'status-complete', not_ready: 'status-warning', unreachable: 'status-error', unhealthy: 'status-error', misconfigured: 'status-error', not_configured: 'status-neutral', request_failed: 'status-error' };
      const labels = { ready: 'Ready', not_ready: 'Not ready', unreachable: 'Unreachable', unhealthy: 'Unhealthy', misconfigured: 'Misconfigured', not_configured: 'Not configured', request_failed: 'Status request failed' };
      return { value, tone: tones[value] || 'status-neutral', label: recognized ? (labels[value] || value) : value, recognized };
    }

    function renderGateway() {
      const c = document.getElementById('gateway-status-container');
      if (!c) return;
      const gw = globalTelemetry.gateway || {};
      const meta = gatewayStatusMeta(gw.status);
      const configured = gw.configured === true;
      const health = gw.health && typeof gw.health === 'object' ? gw.health : null;
      const readiness = gw.readiness && typeof gw.readiness === 'object' ? gw.readiness : null;
      const healthStatus = health ? health.status : null;
      const readinessStatus = readiness ? readiness.status : null;
      const healthHttpStatus = health ? health.http_status : null;
      const readinessHttpStatus = readiness ? readiness.http_status : null;
      const healthLatency = health ? health.latency_ms : null;
      const readinessLatency = readiness ? readiness.latency_ms : null;
      const readinessReason = readiness ? readiness.reason : null;
      const lastChecked = gw.checked_at || null;
      const badgeText = meta.label.toUpperCase();

      const honest = 'Health and readiness only. This panel does not evaluate policy, receipts, or tool decisions. /readyz fails closed until Phase 5 wires the runtime.';
      const notConfiguredCopy = 'AGENTSCAN_GATEWAY_URL=http://127.0.0.1:8765 is the expected loopback gateway value. The gateway serve command arrives in Phase 5.';
      const misconfiguredCopy = 'The configured AGENTSCAN_GATEWAY_URL is not a valid loopback gateway endpoint. Fix the environment value before retrying.';
      const requestFailedCopy = 'The dashboard could not reach its own status API. This says nothing about gateway health.';
      const unrecognizedCopy = `Unrecognized gateway status value: ${meta.value}. No probe conclusions were drawn.`;
      const notReadyCopy = `The gateway process is reachable but its readiness probe is failing. Bounded readiness reason: ${readinessReason || 'unknown_reason'}.`;

      const probedStates = new Set(['ready', 'not_ready', 'unhealthy', 'unreachable']);
      const showProbeCards = configured && probedStates.has(meta.value) && (health !== null || readiness !== null);

      if (meta.value === 'request_failed') {
        c.innerHTML = `
          <div class="dl-card p-6 bg-white space-y-3" style="border-color: var(--border)">
            <div class="flex items-center justify-between">
              <span class="text-[10px] font-extrabold uppercase tracking-wider text-[#666666]">Runtime Gateway</span>
              <span class="assessment-badge ${meta.tone}">${escapeHtml(badgeText)}</span>
            </div>
            <div class="text-2xl font-extrabold text-[#1A1A1A]">${escapeHtml(meta.label)}</div>
            <p class="text-xs text-[#666666]">${escapeHtml(requestFailedCopy)}</p>
          </div>`;
        return;
      }

      if (!meta.recognized) {
        c.innerHTML = `
          <div class="dl-card p-6 bg-white space-y-3" style="border-color: var(--border)">
            <div class="flex items-center justify-between">
              <span class="text-[10px] font-extrabold uppercase tracking-wider text-[#666666]">Runtime Gateway</span>
              <span class="assessment-badge ${meta.tone}">${escapeHtml(badgeText)}</span>
            </div>
            <div class="text-2xl font-extrabold text-[#1A1A1A]">${escapeHtml(meta.value)}</div>
            <p class="text-xs text-[#666666]">${escapeHtml(unrecognizedCopy)}</p>
          </div>`;
        return;
      }

      if (meta.value === 'not_configured') {
        c.innerHTML = `
          <div class="overview-empty-state">
            <span class="empty-state-symbol" aria-hidden="true">◎</span>
            <strong>Runtime gateway not configured</strong>
            <p>${escapeHtml(notConfiguredCopy)}</p>
          </div>`;
        return;
      }

      if (meta.value === 'misconfigured') {
        c.innerHTML = `
          <div class="dl-card p-6 bg-white space-y-3" style="border-color: var(--border)">
            <div class="flex items-center justify-between">
              <span class="text-[10px] font-extrabold uppercase tracking-wider text-[#666666]">Runtime Gateway</span>
              <span class="assessment-badge ${meta.tone}">${escapeHtml(badgeText)}</span>
            </div>
            <div class="text-2xl font-extrabold text-[#1A1A1A]">${escapeHtml(meta.label)}</div>
            <p class="text-xs text-[#666666]">${escapeHtml(misconfiguredCopy)}</p>
          </div>`;
        return;
      }

      const healthCard = health !== null ? `
            <div class="dl-card p-6 bg-white space-y-3" style="border-color: var(--border)">
              <div class="flex items-center justify-between">
                <span class="text-[10px] font-extrabold uppercase tracking-wider text-[#666666]">Health /healthz</span>
                <span class="text-2xl font-extrabold text-[#1A1A1A]">${escapeHtml(healthHttpStatus ?? '—')}</span>
              </div>
              <p class="text-xs text-[#666666]">Status: ${escapeHtml(healthStatus || 'unknown')} · Latency: ${escapeHtml(String(healthLatency ?? '—'))} ms</p>
            </div>` : '';
      const readinessCard = readiness !== null ? `
            <div class="dl-card p-6 bg-white space-y-3" style="border-color: var(--border)">
              <div class="flex items-center justify-between">
                <span class="text-[10px] font-extrabold uppercase tracking-wider text-[#666666]">Readiness /readyz</span>
                <span class="text-2xl font-extrabold text-[#1A1A1A]">${escapeHtml(readinessHttpStatus ?? '—')}</span>
              </div>
              <p class="text-xs text-[#666666]">Status: ${escapeHtml(readinessStatus || 'unknown')} · Latency: ${escapeHtml(String(readinessLatency ?? '—'))} ms · Reason: ${escapeHtml(readinessReason || 'unknown_reason')}</p>
            </div>` : '';
      const probeCards = showProbeCards ? `
          <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
            ${healthCard}
            ${readinessCard}
          </div>` : '';

      c.innerHTML = `
        <div class="dl-card p-6 bg-white space-y-3" style="border-color: var(--border)">
          <div class="flex items-center justify-between">
            <span class="text-[10px] font-extrabold uppercase tracking-wider text-[#666666]">Runtime Gateway</span>
            <span class="assessment-badge ${meta.tone}">${escapeHtml(badgeText)}</span>
          </div>
          <div class="text-2xl font-extrabold text-[#1A1A1A]">${escapeHtml(meta.label)}</div>
          <p class="text-xs text-[#666666]">${configured && gw.url ? escapeHtml(gw.url) : 'Not configured'}</p>
          <p class="text-xs text-[#666666]">${escapeHtml(honest)}</p>
          <p class="text-xs text-[#666666]">Last checked: ${escapeHtml(lastChecked || 'Not checked yet')}</p>
        </div>
        ${probeCards}
        ${meta.value === 'not_ready' ? `<p class="text-xs text-[#666666]">${escapeHtml(notReadyCopy)}</p>` : ''}
      `;
    }

