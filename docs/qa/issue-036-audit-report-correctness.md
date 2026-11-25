# QA-036 - Audit and report correctness

**Issue:** [#36 [P2] Audit and report correctness](https://github.com/PrathaMesh3056/AgentScan/issues/36)
**Branch:** `fix/qa-036-audit-report-correctness`
**PR:** [#55](https://github.com/PrathaMesh3056/AgentScan/pull/55) (Draft)
**Base:** `main` at `7c17743`
**Status:** Bounded implementation and regression tests complete; PR remains Draft for owner review.

## Summary

Static audits previously described themselves differently depending on the surface, dropped the fact that
modules were skipped or failed, and could present a partial run as a clean result. This change introduces
one coverage/status model and one orchestration path shared by the CLI, MCP server, and dashboard; makes
skipped and errored modules explicit in the serialized report and HTML; labels mixed audit scopes correctly;
and gates clean-result claims on full scope and complete status.

The change is deliberately bounded. It does not touch `agentscan/core/`, `agentscan/action/`,
`agentscan/reporting/audit_verifier.py`, `docs/RUNTIME_GATEWAY.md`, or any P1 (#20-#34) files.

## Problem and impact

- The CLI, MCP server, and dashboard assembled audit output independently. The same target could yield
  different status, coverage, and finding representations (dashboard returned an ad-hoc dict; MCP used the
  risk band as `status` and had no coverage; the CLI wrote an identity-shaped report).
- Reports only carried modules that happened to record coverage. Modules that were not selected, produced
  no record, or raised were indistinguishable from modules that ran and found nothing.
- A single scanner exception aborted the whole audit on the CLI (exit 1), the dashboard (HTTP 500), and MCP
  (tool error), losing any partial result.
- Audit titles, HTML headings, and empty states were hardcoded to identity/RBAC language even when only
  supply-chain or code rules ran. A clean subset could be rendered as "Zero Identity Vulnerabilities
  Detected" with no indication that other modules were never assessed.
- Multi-mode runs (`assessment_scope == "mixed"`) were presented as the first mode only in the HTML report.

## Reproduction

Pre-fix symptoms reproduced with a synthetic fixture (loopback/synthetic data only):

1. CLI vs dashboard vs MCP: run `audit <fixture> --scan-config --scan-secrets --scan-identity` through each
   surface and compare JSON. Pre-fix, the CLI report only had the selected modules, the dashboard returned a
   different dict shape, and MCP reported the risk band in `status` with no coverage at all.
2. Module failure: patch `agentscan.supply_chain.config_auditor.scan_config` to raise `RuntimeError`.
   Pre-fix: CLI exit 1, dashboard HTTP 500, MCP `isError: true`; the partial result was lost.
3. Partial clean audit: run only `--scan-config` on a clean fixture. Pre-fix HTML titled itself an identity
   audit and could claim "Zero Identity Vulnerabilities Detected" while seven modules never ran.
4. Mixed mode: a `ScanReport` with `assessment_scope="mixed"` was rendered as `SCAN Mode` with no mixed
   scope qualifier.

## What changed

### 1. Explicit coverage/status model (`agentscan/reporting/audit_coverage.py`, new)

- One catalog of the eight audit modules (`scan_deps`, `scan_config`, `scan_secrets`, `scan_typo`,
  `scan_mcp`, `scan_identity`, `scan_frameworks`, `scan_semgrep`) with stable keys, families, and labels.
- `build_coverage(selected, records, errors)` returns one entry per catalog module, in catalog order, with
  `module`, `module_key`, `label`, `status`, `source`, `checks_run`, `inputs_selected`, `limitations`.
  Ran records are preserved verbatim; a raised module becomes `ERROR` with the exception text in
  `limitations`; a missing record becomes `NOT_ASSESSED`; every unselected module is appended as `SKIPPED`
  (`source: "not_selected"`). Skipped modules can no longer disappear from a report.
- Statuses are the existing `COMPLETE` / `INCONCLUSIVE` / `NOT_ASSESSED` values plus `SKIPPED` and `ERROR`.
  `assessment_status` only returns `COMPLETE` when at least one check ran and every non-skipped entry is
  `COMPLETE`; any skip/error/missing record makes the assessment `INCONCLUSIVE`.
- `assessment_label` derives an honest title: `Identity & RBAC Entitlement Audit`,
  `Supply-Chain Static Audit`, `Code Rules Static Audit`, or
  `Mixed Static Audit (Supply-Chain + Identity)`; `scope_complete` is true only for an all-eight selection.

### 2. One orchestration path (`agentscan/reporting/audit_runner.py`, new)

- `run_static_audit(path, selected, offline=..., show_transitive=..., rules_path=...)` runs the selected
  modules sequentially and catches per-module exceptions into `module_errors`
  (`{"module", "module_name", "error"}`) instead of aborting.
- `AuditRun.payload()` is the canonical static-audit payload: `status`, `score`, `risk_band`,
  `assessment_label`, `scope_complete`, `coverage`, `coverage_counts`, `coverage_scope_note`,
  `module_errors`, `total_checks`. `score` is `None` unless the assessment is `COMPLETE`, so partial runs
  cannot present a number as a verdict.
- CLI (`agentscan/_cli/commands/audit.py`), MCP (`agentscan/mcp/server.py`), and dashboard
  (`agentscan/ui/routers/audit.py`) now all call this runner. The CLI writes `run.to_identity_report()`;
  MCP and dashboard return `run.payload()` plus their surface-specific extras (`audit_path`, `findings`,
  `band`).

### 3. Report schema (`agentscan/identity/models.py`)

Additive fields only; existing keys are retained:

- `assessment_label` (default `Identity & RBAC Entitlement Audit`)
- `scope_complete` (default `False`)
- `module_errors` (default `[]`)
- `total_checks` (default `0`)

`audit_coverage`, `status`, and `identity_score` keep their existing names and meanings. Properties
`modules_ran`, `modules_skipped`, `modules_errored`, `coverage_summary`, `score_label`, and
`coverage_scope_note` summarize the preserved entries. Serialized JSON now retains SKIPPED and ERROR
entries and module errors (regression test asserts the round-trip).

### 4. Correct labels for mixed and non-identity audits

- `IdentityReport` HTML (`templates/identity_report.html.j2`) uses `assessment_label` in the title and
  header, a generic subtitle, and a score card labelled `Identity Score` only for identity-only runs,
  otherwise `Audit Score`.
- The coverage card renders every module with a status badge, checks run, source/limitations, and a red
  module-errors block.
- `ScanReport` HTML (`templates/scan_report.html.j2`) appends
  `- Mixed scan scope (module outcomes cover multiple modes)` when `assessment_scope == "mixed"`.

### 5. Qualified claims instead of overclaims

The findings section no longer emits a clean claim unless the evidence supports it:

- Full scope and `COMPLETE` -> "No Findings in the Full Audited Scope".
- Partial scope and `COMPLETE` -> "No Findings in the Assessed Modules" plus "Only N of M coverage entries
  were assessed... This is a partial result, not a clean bill of health."
- Any other status -> "Assessment Inconclusive" with the ran/skipped/errored counts.

Hardcoded identity-only claims ("Zero Identity Vulnerabilities Detected", the identity title, and the
least-privilege assertion) were removed or made conditional on the actual label/status/scope.

### 6. MCP `checks` selection and shared output

- `agentscan_audit` accepts an optional `checks` array of the eight module keys (defaults to the seven
  built-in modules; semgrep is opt-in). Unknown/empty selections are rejected as tool errors.
- The response keeps `score`, `checks_run`, `findings_count`, `findings`, and `audit_path`, and adds
  `coverage`, `coverage_counts`, `coverage_scope_note`, `assessment_label`, `scope_complete`,
  `module_errors`, `risk_band`, and `total_checks`.

### Behavior changes to note for consumers

- MCP `agentscan_audit`: `status` is now the assessment status (`COMPLETE` / `INCONCLUSIVE` /
  `NOT_ASSESSED`), not the risk band. Read `risk_band` for the old band, and expect `score: null` when the
  assessment is incomplete. The default module set now matches the CLI/dashboard built-in set; semgrep is
  opt-in via `checks`.
- CLI JSON: gains `assessment_label`, `scope_complete`, `module_errors`, `total_checks`; `audit_coverage`
  now also contains SKIPPED entries for unselected modules (selected entries stay first, so existing
  first-entry assertions still hold); `identity_score` remains the score field.
- Dashboard `/api/audit`: keeps `band`, adds `risk_band`, and now returns the shared coverage/label/scope
  fields. On-disk reports call the coverage array `audit_coverage`, while API payloads call it `coverage`;
  entries are identical.

## Tests and results

All commands were run from the clone on Windows with the project venv, `PYTHONDONTWRITEBYTECODE=1`,
`PYTHONPATH=<repo>`, a unique `--basetemp`, and `-p no:cacheprovider`.

New regression tests:

- `tests/test_reporting/test_audit_coverage_model.py` (8 tests): skipped/error/missing-record preservation,
  status semantics, labels, full-scope check, unknown-module rejection, and JSON round-trip of coverage +
  module errors.
- `tests/test_reporting/test_audit_surfaces.py` (6 tests): CLI/MCP/dashboard parity on one synthetic fixture;
  per-surface module-exception preservation; qualified HTML for a partial clean audit; mixed scan-scope
  label.

Results:

- New coverage-model tests: `8 passed in 0.05s`.
- New surface tests: `6 passed` (two Starlette/httpx deprecation warnings only).
- Broad related slice (`tests/test_reporting`, `tests/test_supply_chain/test_audit_coverage.py`,
  `tests/test_cli.py`, `tests/test_mcp`, `tests/test_identity`, `tests/test_ui.py`):
  `190 passed, 3 skipped in 13.39s`.
- Failing-before check: a detached worktree at base `7c17743` with only the new reporting modules and new
  tests copied in produced `7 failed, 7 passed`; failures were the JSON round-trip, parity, all three
  module-exception tests, the qualified-HTML test, and the mixed-scope label. The seven passing tests are
  unit tests of the new coverage helpers, which did not exist at base.
- Ruff: `ruff check --no-cache <8 changed Python files>` -> `All checks passed!`;
  `ruff format --check` -> `8 files already formatted`.

## Remaining work and follow-ups

This PR implements the coverage/status/parity/overclaim subset. It does not claim to close every item in
#36 by ID; the remaining checklist items (QA-038, QA-039, QA-047, QA-048, QA-049, QA-050, QA-054, QA-057,
QA-058, QA-059, QA-061, QA-085, QA-096, QA-111, QA-157, QA-158, QA-159, QA-161, QA-162) still need
individual verification, and some are outside this change:

- `core.runner.run_scan_multi` still sets `scan_mode` to the first mode (read-only area). The HTML now
  labels mixed assessment scope, but the canonical model field needs a core-side fix.
- MCP does not expose a rules path for semgrep, and its default module set changed as documented above;
  consumers should pin `checks` if they depend on the old implicit set.
- Module errors set the assessment to `INCONCLUSIVE` but do not create findings, so `--fail-on`-style gates
  do not trigger on an errored module; the status/coverage fields are the signal.
- The report field remains `audit_coverage` for backward compatibility while API payloads use `coverage`.
  Unifying the name would be a consumer-visible change and is left for a follow-up.
- Full-suite CI and owner review remain; this PR stays Draft.

## Files changed

| File | Change |
| --- | --- |
| `agentscan/reporting/audit_coverage.py` | New: module catalog, coverage builder, status/label/scope helpers |
| `agentscan/reporting/audit_runner.py` | New: shared bounded orchestration, error capture, canonical payload |
| `agentscan/identity/models.py` | Additive assessment/coverage fields and summary properties |
| `agentscan/_cli/commands/audit.py` | Use shared runner; print/emit coverage-qualified output |
| `agentscan/mcp/server.py` | Use shared runner; `checks` selection; shared payload keys |
| `agentscan/ui/routers/audit.py` | Use shared runner; return shared payload |
| `agentscan/reporting/templates/identity_report.html.j2` | Dynamic title/score/coverage table, qualified claims |
| `agentscan/reporting/templates/scan_report.html.j2` | Mixed assessment-scope qualifier |
| `tests/test_reporting/test_audit_coverage_model.py` | New regression tests |
| `tests/test_reporting/test_audit_surfaces.py` | New parity/error/qualification tests |
| `docs/qa/issue-036-audit-report-correctness.md` | This report |

## Review checklist

- [x] Reproduction recorded before the fix.
- [x] Failing-before tests added (7 fail at base `7c17743`).
- [x] One coverage model shared by CLI/MCP/dashboard.
- [x] Module errors preserved and surfaced.
- [x] Mixed modes labeled correctly (audit label; scan HTML qualifier).
- [x] Overclaims qualified.
- [x] Targeted tests and Ruff pass.
- [x] No changes under `agentscan/core/`, `agentscan/action/`, `agentscan/reporting/audit_verifier.py`,
      `docs/RUNTIME_GATEWAY.md`, or P1 files.
- [ ] Full suite in CI (owner review; PR stays Draft).
