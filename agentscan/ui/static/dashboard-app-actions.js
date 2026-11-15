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
      loadGatewayStatus();
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

  