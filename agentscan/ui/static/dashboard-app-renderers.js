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

      const hasData = globalTelemetry.sentinel !== null && typeof globalTelemetry.sentinel === 'object';
      const snt = hasData ? globalTelemetry.sentinel : {};
      const isRunning = snt.running === true;
      const status = String(snt.status || '').toUpperCase();
      const watcherFailed = status === 'ERROR' || Boolean(snt.error);
      const watcherState = !hasData ? 'UNAVAILABLE'
        : watcherFailed ? 'ERROR'
        : isRunning ? 'RUNNING'
        : status === 'STOPPED' ? 'STOPPED'
        : status === 'IDLE' ? 'NOT STARTED'
        : 'UNKNOWN';

      const integerOrNull = value => typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? value : null;
      const probes = integerOrNull(snt.probes_run);
      const probesFailed = integerOrNull(snt.probes_failed);
      const lastProbeStatus = ['PASS', 'ALERT', 'ERROR'].includes(String(snt.last_probe_status || '').toUpperCase())
        ? String(snt.last_probe_status).toUpperCase() : null;
      const lastProbeAt = typeof snt.last_probe_at === 'string' && snt.last_probe_at ? snt.last_probe_at : null;
      const alertRecords = Array.isArray(snt.alerts)
        ? snt.alerts.filter(item => item && typeof item === 'object' && String(item.status || '').toUpperCase() === 'ALERT')
        : null;
      const leakCount = alertRecords ? alertRecords.length : integerOrNull(snt.leaks_detected);
      const probeFailedNow = lastProbeStatus === 'ERROR';

      const sentinelErrors = [];
      if (watcherFailed) sentinelErrors.push({ module_name: 'Sentinel watcher', error: snt.error || 'The watcher stopped because an execution error occurred.', error_id: snt.error_id });
      if (snt.webhook_error) sentinelErrors.push({ module_name: 'Sentinel webhook', error: snt.webhook_error.error || 'The webhook notification could not be delivered.', error_id: snt.webhook_error.error_id });
      if (probeFailedNow && !watcherFailed) sentinelErrors.push({ module_name: 'Sentinel probe', error: snt.last_probe_error || 'The last Sentinel probe failed.', error_id: snt.last_probe_error_id });
      const watcherError = sentinelErrors.length ? DashboardSemantics.assessmentErrorMarkup({ status: 'ERROR', assessment_scope: watcherFailed ? 'watcher' : undefined, module_errors: sentinelErrors }) : '';
      const runtimeErrors = document.getElementById('sentinel-runtime-errors');
      if (runtimeErrors) runtimeErrors.innerHTML = watcherError;
      const inlineStatus = document.getElementById('sentinel-status-inline');
      if (inlineStatus) inlineStatus.textContent = watcherState;
      document.getElementById('btn-sentinel-start')?.classList.toggle('pointer-events-none', isRunning);
      document.getElementById('btn-sentinel-start')?.classList.toggle('opacity-50', isRunning);
      document.getElementById('btn-sentinel-stop')?.classList.toggle('pointer-events-none', !isRunning);
      document.getElementById('btn-sentinel-stop')?.classList.toggle('opacity-50', !isRunning);

      const target = typeof snt.target === 'string' && snt.target ? snt.target : 'No agent endpoint configured';
      const interval = integerOrNull(snt.interval);
      const badgeClass = tone => tone === 'error' ? 'bg-[#FAF0EB] text-[#B84E28] border border-[#ECCFC2]'
        : tone === 'warn' ? 'bg-[#F7F5EE] text-[#8A5A1E] border border-[#E5D6BF]'
        : tone === 'ok' ? 'bg-[#EEF6F4] text-[#1E5E54] border border-[#CFE5E1]'
        : 'bg-[#F7F5EE] text-[#666666] border border-[#1A1A1A]/10';
      const watcherTone = watcherFailed ? 'error' : isRunning ? 'ok' : 'neutral';
      const watcherHeadline = watcherFailed ? 'STOPPED AFTER ERROR'
        : isRunning ? 'RUNNING'
        : watcherState === 'STOPPED' ? 'STOPPED'
        : watcherState === 'NOT STARTED' ? 'NOT STARTED'
        : 'UNAVAILABLE';

      let probeBadge = 'UNAVAILABLE';
      let probeTone = 'neutral';
      let probeSummary = 'Probe evidence unavailable';
      let probeDetail = 'No probe evidence is available.';
      if (hasData) {
        if (probeFailedNow) { probeBadge = 'PROBE ERROR'; probeTone = 'error'; }
        else if (probes === null) { probeBadge = 'UNKNOWN'; }
        else if (probes === 0) { probeBadge = 'NO PROBES'; }
        else { probeBadge = 'RECORDED'; probeTone = 'ok'; }
        probeSummary = probes === null ? 'Probe count unavailable' : `${probes} Probe${probes === 1 ? '' : 's'}`;
        if (probesFailed !== null && probesFailed > 0) probeSummary += ` · ${probesFailed} failed`;
        probeDetail = lastProbeAt || lastProbeStatus
          ? `Last probe: ${lastProbeAt || 'time not recorded'}${lastProbeStatus ? ' · ' + lastProbeStatus : ''}`
          : 'No probe recorded yet.';
      }

      let alertBadge = 'UNAVAILABLE';
      let alertTone = 'neutral';
      let alertSummary = 'Alert count unavailable';
      if (hasData) {
        if (leakCount === null) {
          alertBadge = 'UNKNOWN';
          alertSummary = 'Alert count unavailable';
        } else if (leakCount > 0) {
          alertBadge = 'ALERT';
          alertTone = 'error';
          alertSummary = `${leakCount} Detected`;
        } else if (probeFailedNow || (probes !== null && probes > 0 && probesFailed === probes)) {
          alertBadge = 'INCONCLUSIVE';
          alertTone = 'warn';
          alertSummary = 'No alert recorded; probe coverage is incomplete.';
        } else if (probes !== null && probes > 0 && probesFailed !== null && probesFailed > 0) {
          alertBadge = 'PARTIAL COVERAGE';
          alertTone = 'warn';
          alertSummary = `0 Detected · ${probesFailed} failed probe${probesFailed === 1 ? '' : 's'}`;
        } else if (probes !== null && probes > 0) {
          alertBadge = 'NO RECORDED FINDING';
          alertTone = 'ok';
          alertSummary = '0 Detected';
        } else {
          alertBadge = 'NOT EVALUATED';
          alertSummary = 'No alert history';
        }
      }

      const feedBadge = watcherState === 'RUNNING' ? 'WATCHER RUNNING'
        : watcherState === 'ERROR' ? 'WATCHER ERROR'
        : watcherState === 'STOPPED' ? 'WATCHER STOPPED'
        : watcherState === 'NOT STARTED' ? 'NO WATCHER RUNNING'
        : 'STATUS UNAVAILABLE';

      let alertLines;
      if (!hasData) {
        alertLines = '<div>[SENTINEL-DAEMON] No Sentinel status available.</div>';
      } else if (alertRecords && alertRecords.length) {
        alertLines = alertRecords.slice(0, 3).map(alert => {
          const findings = integerOrNull(alert.findings_count);
          return `<div>[ALERT] ${escapeHtml(alert.timestamp || 'time not recorded')} · ${findings === null ? 'finding count unavailable' : findings + ' finding(s)'} · ${escapeHtml(alert.target || target)}</div>`;
        }).join('');
      } else if (leakCount === null) {
        alertLines = '<div>[SENTINEL-DAEMON] Alert history unavailable.</div>';
      } else if (probeFailedNow) {
        alertLines = '<div>[SENTINEL-DAEMON] No alert recorded; probe coverage is incomplete.</div>';
      } else if (probes !== null && probes > 0) {
        alertLines = probesFailed !== null && probesFailed > 0
          ? `<div>[SENTINEL-DAEMON] No canary leakage recorded in ${probes} probe${probes === 1 ? '' : 's'}; ${probesFailed} failed.</div>`
          : `<div>[SENTINEL-DAEMON] No canary leakage recorded in ${probes} probe${probes === 1 ? '' : 's'}.</div>`;
      } else {
        alertLines = '<div>[SENTINEL-DAEMON] No probes recorded. No alert history.</div>';
      }

      c.innerHTML = `
        <div id="sentinel-tab-errors">${watcherError}</div>
        <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div class="dl-card p-6 bg-white space-y-3" style="border-color: var(--border)">
            <div class="flex items-center justify-between">
              <span class="text-[10px] font-extrabold uppercase tracking-wider text-[#666666]">Watcher Status</span>
              <span class="px-2.5 py-0.5 rounded-full text-[10px] font-bold ${badgeClass(watcherTone)}">
                ${watcherState}
              </span>
            </div>
            <div class="text-2xl font-extrabold text-[#1A1A1A]">${watcherHeadline}</div>
            <p class="text-xs text-[#666666]">Target: <code class="font-mono font-bold text-[#1A1A1A]">${escapeHtml(target)}</code></p>
            <div class="pt-3 border-t border-[#1A1A1A]/10 flex items-center justify-between text-xs">
              <span class="text-[#888888]">Interval: ${interval === null ? 'Not configured' : interval + 's'}</span>
              <button onclick="openSentinelModal()" class="text-xs font-bold text-[#1A1A1A] hover:underline">&rarr; Configure</button>
            </div>
          </div>

          <div class="dl-card p-6 bg-white space-y-3" style="border-color: var(--border)">
            <div class="flex items-center justify-between">
              <span class="text-[10px] font-extrabold uppercase tracking-wider text-[#1E5E54]">Canary Probes</span>
              <span class="px-2.5 py-0.5 rounded-full text-[10px] font-bold ${badgeClass(probeTone)}">${probeBadge}</span>
            </div>
            <div class="text-2xl font-extrabold text-[#1A1A1A]">${probeSummary}</div>
            <p class="text-xs text-[#666666]">${escapeHtml(probeDetail)}</p>
            <div class="pt-3 border-t border-[#1A1A1A]/10 flex items-center justify-between text-xs">
              <span class="text-[#1E5E54] font-bold">Review recorded probe outcomes</span>
              <button onclick="runSentinelProbeAction()" class="text-xs font-bold text-[#1E5E54] hover:underline">&rarr; Probe Now</button>
            </div>
          </div>

          <div class="dl-card p-6 bg-white space-y-3" style="border-color: var(--border)">
            <div class="flex items-center justify-between">
              <span class="text-[10px] font-extrabold uppercase tracking-wider text-[#B84E28]">Alerts & Leaks</span>
              <span class="px-2.5 py-0.5 rounded-full text-[10px] font-bold ${badgeClass(alertTone)}">${alertBadge}</span>
            </div>
            <div class="text-2xl font-extrabold text-[#1A1A1A]">${alertSummary}</div>
            <p class="text-xs text-[#666666]">Unsanitized canary token reflections or unauthorized external exfiltration.</p>
            <div class="pt-3 border-t border-[#1A1A1A]/10 flex items-center justify-between text-xs">
              <span class="text-[#888888]">Webhook: ${escapeHtml(snt.webhook_url || 'Not configured')}</span>
              <button onclick="openHealServerModal()" class="text-xs font-bold text-[#B84E28] hover:underline">&rarr; Webhook Server</button>
            </div>
          </div>
        </div>

        <div class="dl-card p-6 bg-white space-y-3" style="border-color: var(--border)">
          <div class="flex items-center justify-between pb-3 border-b border-[#1A1A1A]/10">
            <h3 class="text-base font-extrabold text-[#1A1A1A]">Sentinel Probe & Alert Telemetry</h3>
            <span class="text-[10px] font-mono font-bold px-2 py-0.5 rounded-full ${badgeClass(watcherTone)}">${feedBadge}</span>
          </div>
          <p class="text-xs text-[#666666]">Recorded Sentinel probe and alert outcomes. Only events written by the backend are shown.</p>
          <div class="p-4 rounded-2xl bg-[#F7F5EE] font-mono text-[11px] text-[#1A1A1A] space-y-1">
            <div>[SENTINEL-DAEMON] Watcher state: <strong>${watcherState}</strong></div>
            <div>[SENTINEL-DAEMON] Probes recorded: <strong>${probes === null ? 'Unavailable' : probes}</strong>${probesFailed !== null && probesFailed > 0 ? ` · ${probesFailed} failed` : ''}</div>
            <div>[SENTINEL-DAEMON] Last probe: <strong>${lastProbeAt ? escapeHtml(lastProbeAt) : 'None recorded'}</strong>${lastProbeStatus ? ` · ${lastProbeStatus}` : ''}</div>
            <div>[SENTINEL-DAEMON] Alerts recorded: <strong>${leakCount === null ? 'Unavailable' : leakCount}</strong></div>
            <div>[SENTINEL-DAEMON] Configured target: <strong>${escapeHtml(target)}</strong></div>
            <div>[SENTINEL-DAEMON] Canary token state: <code>${snt.canary_token ? 'Configured' : 'Not configured'}</code></div>
            <div>[SENTINEL-DAEMON] Webhook dispatcher target: <code>${escapeHtml(snt.webhook_url || 'Not configured')}</code></div>
            ${alertLines}
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
