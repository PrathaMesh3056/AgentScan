# QA-035: False assurance and status labels

- **Issue:** [AgentScan #35](https://github.com/PrathaMesh3056/AgentScan/issues/35) - `[P2] False assurance and status labels`
- **Base:** `origin/main` at `7c17743` (`refactor(ui): modularize dashboard scripts and dedupe page routes`)
- **Branch:** `fix/qa-035-false-assurance`
- **Status:** draft plan -> implementation (docs first, then failing tests, then fix)

## Problem

The dashboard and CLI assert that controls are active, enforced, ready, or clean without
checking any evidence. Three concrete mechanisms cause this:

1. **Static labels in the dashboard shell.** `index.html` ships `3 TEAMS READY` as literal
   markup even when no swarm preset has loaded.
2. **Fallback labels in the renderer.** `dashboard-app-renderers.js` paints `ACTIVE`,
   `ENFORCED`, `READY`, `RBAC Enforced`, and `NO RECORDED FINDING` from boolean-ish defaults
   or with no input at all. For example the guardrail cards show `ACTIVE` / `ENFORCED` while
   `/api/guardrails` only *exports* YAML/JSON templates that were never deployed.
3. **Missing evidence in API payloads.** Endpoints such as `/api/sentinel/status` never emit
   `probes_run` or `leaks_detected`, so the renderer defaults them to `0` and then presents
   `NO RECORDED FINDING` as if a clean probe had run.

This is the product-level trust problem in the issue: an operator cannot distinguish
"checked and clean" from "never checked" or "never deployed".

## Reproduction

From a clean clone at `7c17743` with the UI extra installed:

```powershell
$env:PYTHONDONTWRITEBYTECODE='1'
& 'D:\prathamesh\AgentScan-gw-impl\.venv\Scripts\python.exe' -c "from fastapi.testclient import TestClient; from agentscan.ui.app import create_app; from pathlib import Path; c=TestClient(create_app(project_root=Path('.'))); import json; print(json.dumps(c.get('/api/sentinel/status').json())); print(json.dumps({k:v for k,v in c.get('/api/mcp').json().items() if k!='tools'}))"
```

Observed before the fix:

```text
{"running": false, "target": null, "interval": 60, "canary_token": null, "webhook_url": null, "alerts": []}
{"status": "ONLINE", "protocol_version": "2024-11-05", "transport": "stdio / JSON-RPC 2.0", "tools_count": 4}
```

No sentinel has ever run and no canary token is configured, yet the Sentinel tab renders
`Canary Probes: ACTIVE` and `Alerts & Leaks: NO RECORDED FINDING`. Likewise `/api/guardrails`
returns generated export templates when `findings_count == 0`, after which the tab renders
`LiteLLM Proxy: ACTIVE` and `Cloudflare AI Gateway: ENFORCED` - neither gateway is deployed or
configured by AgentScan.

## Label inventory

| # | Surface | Current label | Evidence available | New behaviour / fallback |
|---|---------|---------------|--------------------|--------------------------|
| 1 | `dashboard-app-renderers.js` LiteLLM guardrail card | `ACTIVE` | `/api/guardrails` only exports a template; no deployment receipt exists | `deployment.litellm.label`: `Exported - not deployed` when a template exists, `Not deployed` when it does not, `Unknown` when telemetry is missing |
| 2 | `dashboard-app-renderers.js` Cloudflare guardrail card | `ENFORCED` | same as #1 | `deployment.cloudflare.label` with the same fallbacks |
| 3 | `dashboard-app-renderers.js` Sentinel canary card | `ACTIVE` | `running`, `canary_token` from `/api/sentinel/status` | `canary_monitoring.label`: `Monitoring` only when running **and** a token is configured; otherwise `Configured - not running`, `No canary token`, or `Not deployed` |
| 4 | `dashboard-app-renderers.js` Alerts & Leaks card | `NO RECORDED FINDING` | probe/cycle records in `alerts[]` | `canary_leaks.label`: `Not assessed` when no probe evidence exists, `No leaks recorded` when probes ran with zero leaks, `Alert` otherwise |
| 5 | `dashboard-app-renderers.js` RBAC matrix status column | `ENFORCED` | identity manifests plus role policies only prove a *declared* role; no runtime enforcement test exists | per-node `enforcement.label`: `Declared - not verified` when a role policy matches, `Not assessed` when policies are missing or the role is unmatched |
| 6 | `dashboard-app-renderers.js` target-agent card footer | `RBAC Enforced` | same as #5, via `/api/identity` | per-agent `enforcement.label` with the same fallbacks |
| 7 | `dashboard-app-renderers.js` MCP tool card | `READY` | tool metadata is registered, but no invocation/health evidence is collected per tool | `tool_status.label`: `Registered - not verified` when metadata exists, `Unknown` otherwise |
| 8 | `dashboard-app-renderers.js` MCP server status fallback | `ONLINE` when payload missing | `/api/mcp` response | fallback becomes `Unknown`; the API still reports `ONLINE` because the same process is answering |
| 9 | `dashboard-app-renderers.js` Sentinel daemon line | `STANDBY - Ready to start` | `running` flag | `STANDBY - Not monitoring` |
| 10 | `index.html` swarm section badge | `3 TEAMS READY` | `/api/swarms` teams payload | `#swarm-teams-count` is filled from the payload (`N teams configured`) or `Unknown` |
| 11 | `agentscan/_cli/commands/misc.py` `watch` cycle | `Canary secure, 0 findings.` | one probe cycle returned no finding | `No canary leak detected in this cycle.` (a clean single cycle is not proof of security) |

All evaluated labels must also honour the issue fallbacks `Not assessed`, `Not deployed`, and
`Unknown`; the three words are exposed as constants in `agentscan/ui/status_labels.py`.

## Deferred labels (documented, not changed)

- **Bedrock guardrail card `ENTERPRISE`** - an edition/format tag, not a status claim;
  changing it would be unrelated churn. Its deployment state is covered by #1/#2 only if the
  card is used as a status surface; it is not today.
- **`ACTIVE POLLING` in Sentinel/traffic pollers** - already derived from `running` /
  `enabled` flags in the payload. These remain, but the flags themselves are now backed by
  `canary_monitoring` evidence for the canary card.
- **`RECORDING ON` / traffic recorder** - derived from `traffic.enabled`, not a hardcoded
  claim; left unchanged.
- **`ONLINE` from `/api/mcp`** - the dashboard is served by the process that hosts the MCP
  tool registry, so the server is answering. The false part is the per-tool `READY` claim,
  addressed in #7.
- **Compliance pack statuses** - already emit `NOT_ASSESSED` when no findings were mapped
  (`agentscan/reporting/compliance_pack.py`); no change needed.
- **Scan report template** - already defaults module outcomes to `UNVERIFIED`
  (`agentscan/reporting/templates/scan_report.html.j2`); no change needed.
- **`webhook_receiver_status: "online"` in `agentscan/ui/state.py`** - not rendered as a
  status claim in the reviewed tabs and it reflects the in-process receiver; out of this
  bounded subset.

## Scope

Changed files planned:

- `agentscan/ui/status_labels.py` (new): pure, testable label derivation.
- `agentscan/ui/routers/sentinel.py`: attach `canary_monitoring`, `canary_leaks`,
  `probes_run`, and `leaks_detected` to `/api/sentinel/status`.
- `agentscan/ui/routers/reports.py`: attach `deployment` to `/api/guardrails` and
  per-node `enforcement` to `/api/rbac`.
- `agentscan/ui/routers/identity.py`: attach per-agent `enforcement` to `/api/identity`.
- `agentscan/ui/routers/mcp.py`: attach `tool_status` to `/api/mcp`.
- `agentscan/ui/static/dashboard-app-renderers.js`, `agentscan/ui/static/index.html`: render
  the evidence-derived labels above.
- `agentscan/_cli/commands/misc.py`: one `watch` message.
- `tests/test_ui_status_labels.py` (new) and a CLI regression in `tests/test_cli.py`.
- `docs/qa/issue-035-false-assurance.md` (this file).

Not touched: `agentscan/core/`, `agentscan/action/`,
`agentscan/reporting/audit_verifier.py`, `docs/RUNTIME_GATEWAY.md`, and the P1 issue files.

## Test plan

New tests, one per changed label group, must fail on `7c17743` and pass after the fix:

1. `test_sentinel_status_without_evidence_is_not_assessed` - empty sentinel status yields
   `canary_monitoring.state == "not_deployed"` and `canary_leaks.state == "not_assessed"`;
   the response contains neither `ACTIVE` nor `NO RECORDED FINDING`.
2. `test_sentinel_status_with_probe_evidence` - synthetic `state.sentinel_status` with
   `alerts` records yields `Monitoring` + `No leaks recorded`, and `Alert` + leaked count
   when a record reports findings.
3. `test_guardrails_report_export_only_deployment` - `/api/guardrails` labels both templates
   `Exported - not deployed`, never `ACTIVE` / `ENFORCED`; the pure helper returns
   `Not deployed` for missing config.
4. `test_mcp_tools_are_registered_not_ready` - `/api/mcp` exposes
   `tool_status.state == "registered"` and no `READY` string.
5. `test_rbac_nodes_and_identity_agents_derive_enforcement` - `/api/rbac` and
   `/api/identity` label a matched role `Declared - not verified` and an unmatched role
   `Not assessed`; no `ENFORCED` / `RBAC Enforced`.
6. `test_dashboard_sources_do_not_hardcode_assurance_labels` - the static shell/renderer no
   longer contain the literal badges removed above.
7. `test_watch_does_not_claim_canary_is_secure` - `agentscan watch` prints
   `No canary leak detected in this cycle` and not `Canary secure`.

Commands (venv wrapper with a unique `--basetemp`):

```powershell
$env:PYTHONDONTWRITEBYTECODE='1'
& 'D:\prathamesh\AgentScan-gw-impl\.venv\Scripts\python.exe' -c "import os,sys; _m=os.mkdir; os.mkdir=lambda p,m=0o777,*a,**k:_m(p,0o777,*a,**k); import pytest; sys.exit(pytest.main(['tests/test_ui_status_labels.py','tests/test_cli.py','tests/test_ui.py','tests/test_ui_structure.py','tests/test_ui_gateway_status.py','-q','-p','no:cacheprovider','--basetemp',r'C:\Users\prath\.deepai-code\scratch\2026-11-24-so-dont-touch-this-issue-c82a4f9a\bt-qa35']))"
python -m ruff check --no-cache agentscan/ui/status_labels.py agentscan/ui/routers/sentinel.py agentscan/ui/routers/reports.py agentscan/ui/routers/identity.py agentscan/ui/routers/mcp.py agentscan/_cli/commands/misc.py tests/test_ui_status_labels.py
python -m ruff format --check agentscan/ui/status_labels.py agentscan/ui/routers/sentinel.py agentscan/ui/routers/reports.py agentscan/ui/routers/identity.py agentscan/ui/routers/mcp.py agentscan/_cli/commands/misc.py tests/test_ui_status_labels.py
```

Only loopback/synthetic fixtures are used: `TestClient`, in-memory state, and synthetic
canary strings. No live providers, credentials, or customer data.

## Risks and mitigations

| Risk | Mitigation |
|------|-----------|
| API payload additions break consumers | Fields are additive only; existing keys (`running`, `alerts`, `status`, `tools`) are unchanged. |
| Renderer receives an older payload (no assessment fields) | Renderer falls back to `Unknown`, never to a positive claim. |
| RBAC labels imply enforcement when a role matches | Label is explicitly `Declared - not verified`; no state is named `ENFORCED`. |
| Guardrail template presence mistaken for deployment | Label is `Exported - not deployed`; only `deployment_verified` would justify more, and AgentScan never observes deployment. |
| Test counts drift in the full suite | Changes touch rendering strings and additive payload fields; `tests/test_ui.py` already asserts `status == "ONLINE"` for `/api/mcp`, which is preserved. |

## Review notes

- Owner reviews and merges; this branch is never force-pushed or force-merged.
- The docs commit lands first so the PR is draft until tests are green.
- Any label that would need `agentscan/core/` or `agentscan/action/` evidence is documented
  above instead of implemented.

