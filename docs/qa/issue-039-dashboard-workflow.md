# Issue #39 - Dashboard workflow and state (P2)

Branch: `fix/qa-039-dashboard-workflow`, based on `origin/main` at `7c17743`.
Source: QA review IDs QA-143, QA-147, QA-148, QA-149, QA-150, QA-153, QA-154, QA-155, QA-156.

## Problem

The dashboard's live-scan workflow is not backed by a single, guarded state machine and loses evidence while a
scan is running:

1. `agentscan/ui/routers/scan.py` assigns `state.scan_status` ad hoc on every path (start, success, failure,
   cancel). `POST /api/scan/cancel` unconditionally writes `cancelled`, even when no scan is running or the
   scan already finished, and a task cancelled before its coroutine starts never gets a terminal state.
2. Findings are rendered in report order. A report whose CRITICAL findings come last buries them, both in the
   findings grid and in the four-card overview preview (QA-147).
3. The launch modal has no target-authentication control. The `/api/scan` contract already accepts and
   validates `auth_header`, and `Target.auth_header` is consumed by the frozen core connectors, but dashboard
   users cannot supply it (QA-149).
4. Starting a scan sets `state.report = None`, and the `scan:start` SSE handler clears
   `globalTelemetry.report`/`findings`. A running scan therefore blanks the previous report, and a failed
   scan leaves the dashboard with no evidence at all (QA-148).
5. Nothing rehydrates the scan controller after a page reload. A running scan keeps running server-side while
   the refreshed UI sits at IDLE with an empty progress bar (QA-150).

## Reproduction

All fixtures are synthetic; no real credentials or external providers are used.

1. Load a report with a LOW finding before a CRITICAL finding and open Findings: CRITICAL is listed after LOW.
2. Start a scan with `run_scan_multi` monkeypatched to block, then GET `/api/report`: it returns
   `{"report": null}` instead of the previous report.
3. POST `/api/scan/cancel` with no scan running: the status flips to `cancelled`. Finish a scan and cancel
   again: the completed status is overwritten by `cancelled`.
4. Start a scan, reload the dashboard: the controller shows IDLE, 0 %, and the previous report.
5. Inspect the launch modal: there is no target-authentication field (`scan-auth-header`).

## Scope

In scope (this PR):

* `agentscan/ui/state.py`: explicit scan state machine (`SCAN_TRANSITIONS`, `ScanStateError`), helpers for
  begin/finish/cancel, idempotent terminal transitions, ISO `started_at`/`finished_at`, and a snapshot copy.
* `agentscan/ui/routers/scan.py`: route start/terminal/cancel through the state machine, keep the previous
  report on start, expose the guarded status from `/api/scan/status`, and cancel only a running scan.
* `agentscan/ui/static/dashboard.js`: `severityRank`/`sortFindings` (stable CRITICAL-first order) and
  `scanStatusView`/`scanProgressPercent` clients for the workflow; the overview preview uses the same order.
* `agentscan/ui/static/dashboard-app-core.js`, `dashboard-app-renderers.js`, `dashboard-app-actions.js`: sort
  findings after normalization, keep the previous report on `scan:start`, and rehydrate the controller from
  `/api/scan/status` on load (badge, bar, log, terminal handling, polling resume).
* `agentscan/ui/static/form-validation.js` + `index.html`: optional `scan-auth-header` field with a `header`
  field type (printable ASCII, `Name: value` shape) and propagation through the existing form values.
* Tests: new `tests/test_ui_scan_workflow.py` and updated `tests/test_ui_lifecycle.py`/`tests/test_ui.py`.

Out of scope (deliberately):

* Any edit to `agentscan/core/` or `agentscan/action/`. Target auth already reaches the core consumers.
* The accessibility drawer/toast/touch-target work from #40.
* P1 issues #20-#34 and their files; `agentscan/reporting/audit_verifier.py`; `docs/RUNTIME_GATEWAY.md`.
* Broad refactors, formatting churn, or a new front-end framework.

### Blocked frozen-core consumer

Live per-module progress needs a callback from `agentscan/core/runner.py` (`run_scan_multi`) while modules run;
the frozen core exposes none and `agentscan/core/` may not be edited here. This PR therefore derives progress
from the authoritative status (`tests_run`/`tests_selected`, plus the existing `scan:progress` event contract)
and documents the missing core hook instead of guessing progress in the UI.

## Test plan

1. `tests/test_ui_scan_workflow.py` (new, targeted):
   * state machine: legal transitions, rejected illegal transitions, cancel ignored when idle/finished,
     terminal status idempotent, previous scan id preserved until the new terminal state.
   * report retention: a blocking scan keeps `state.report` and `/api/report` on the previous report; a
     failed scan also keeps it; the completed scan replaces it with the new report.
   * target auth: POST `/api/scan` with `auth_header` reaches `Target.auth_header` (synthetic value) and the
     field is rejected when it contains control/non-ASCII characters.
   * severity ordering: Node loads `dashboard.js` and asserts CRITICAL/HIGH/MEDIUM/LOW/INFO/PASS/
     UNCLASSIFIED order, stable ties, and unknown severities last.
   * rehydration: Node asserts `scanStatusView`/`scanProgressPercent` map running/terminal/unknown statuses and
     clamp progress; Python asserts the dashboard boot path calls `rehydrateScanState`.
   * UI contract: the launch modal exposes `scan-auth-header` and the form inventory includes it.
2. Existing related tests: `tests/test_ui_lifecycle.py`, `tests/test_ui.py`, `tests/test_ui_form_validation.py`,
   `tests/test_ui_structure.py`, `tests/test_ui_scan_diagnostics.py`, `tests/test_ui_target_selection.py`.
3. Lint: Ruff check + format check on every changed Python file; `node --check` on every changed JS file.
4. Full suite if feasible; environment-only failures reported verbatim, not hidden.

Each regression test is written first and run against the pre-fix tree to confirm it fails, then re-run after
the fix. Fixtures are synthetic (monkeypatched runners, loopback URLs, fake tokens).

## Risks

* Existing tests and integrations assert the old clearing behaviour or unconditional `cancelled` status; they
  are updated in the same commit (intentional contract change, called out in the PR).
* A retained report can be stale; the controller keeps the last completed `scan_id` and marks the running
  state, so the UI never presents a running scan's old report as current evidence. Final report replacement
  happens only on a new terminal success.
* The state machine is in-process only (same as today); concurrent multi-worker deployments still need the
  queue-backed API, which is out of scope.
* The status remains backwards compatible: existing keys (`status`, `scan_id`, `target`, `progress`,
  `tests_run`, `module_errors`, `module_outcomes`) keep their names and meanings.

## Done

* Comment on #39 with the scope (posted).
* This plan committed first and pushed; draft PR opened.
* Implementation with failing-before/passing-after regression tests, targeted suite, Ruff check/format,
  `node --check`, and a conventional commit referencing #39.

## Verification

Local environment: Python 3.12.7 (`D:\prathamesh\AgentScan-gw-impl\.venv`), Node v25.4.0. Fixtures are
synthetic; the scan runner is monkeypatched and targets are loopback URLs.

* Failing-before: `tests/test_ui_scan_workflow.py` on the pre-fix tree -> `8 failed, 1 passed` (the passing
  case is the API guard that already forwarded `auth_header`).
* Passing-after, one run over `tests/test_ui_scan_workflow.py`, `tests/test_ui_lifecycle.py`,
  `tests/test_ui.py`, `tests/test_ui_form_validation.py`, `tests/test_containment_security.py`,
  `tests/test_ui_structure.py`, `tests/test_ui_scan_diagnostics.py` and
  `tests/test_ui_target_selection.py` -> `436 passed, 1 skipped`.
* `ruff check` and `ruff format --check` pass on the changed Python files; `node --check` passes on every
  changed JavaScript file.
