# Dashboard attack charts: implementation and evidence contract

**Status: complete for the reviewed chart scope, verified 10 October 2026** using
gstack's engineering review and QA.
The overview's **Scan evidence** section renders recorded coverage, severity,
module status and whole-scan duration from the existing authenticated report.
Rendering uses local JavaScript and CSS, with no chart library or analytics service.

The charts retain exact counts and explanations. Native severity buttons open
the findings view, clear its search and focus its selected filter. Module IDs,
assessment scopes and unavailable counts remain visible in the scrollable table.
Malformed module/finding records cannot prevent the report overview from rendering.

| Chart | Source and interpretation | Required behavior |
| --- | --- | --- |
| Horizontal coverage bars per module | `module_outcomes`: selected and evaluated checks | Show both counts and assessment scope. Unevaluated checks stay visible. A negative applies only to the stated criterion. |
| Finding severity bars | Actual findings grouped by CRITICAL/HIGH/MEDIUM/LOW/INFO | Label the axis **findings**, because several findings can come from one check. Provide filtering into the existing findings list. |
| Module status summary | COMPLETE, INCONCLUSIVE, ERROR and SKIPPED outcomes | Distinct text labels and colors. Preserve reasons and confirmed findings even when a module ends with an error. |
| Scan elapsed time | Valid `started_at` and `completed_at` timestamps | Show observed whole-scan duration; missing or invalid timestamps mean unavailable. This is not per-request latency. |

Use the existing authenticated local report endpoint and render locally. Charts
require no prompts, replies, private references, provider calls or analytics service.
Keep an equivalent accessible table, keyboard-accessible filters, readable labels
and consistent severity/status colors. Handle loading, no report, no findings,
legacy reports, partial scans and malformed counts explicitly. Missing data must
not become an invented zero or a clean result. Inconsistent counts should show
unavailable with guidance instead of silently repairing the denominator.

## Metrics that need additional evidence

Do not divide finding counts by selected checks to produce an attack-success or
resistance percentage. Current reports do not retain one typed outcome per attempt,
and operational failures are not defended attacks. A COMPLETE module describes
execution of the scoped checks, not a certified secure agent.

Family outcome rates require a future per-attempt contract with stable module,
variant and family identifiers, criterion version/scope, delivered/evaluated states,
positive/negative/unknown/error disposition and finding references. Mutations must
retain their original-family provenance. History charts also require retained,
comparable scans; per-request latency needs measured timing. Detector accuracy
requires independently labeled outcomes rather than scan findings alone.

## Acceptance checks

1. Render complete, partial, all-error, no-reference and legacy synthetic reports.
2. Show selected/evaluated differences without counting failures as resistance.
3. Verify a check with multiple findings does not invent multiple attempted attacks.
4. Keep confirmed findings visible after budget exhaustion or later errors.
5. Verify filters, keyboard navigation, mobile layout and equivalent table values.
6. Confirm the chart path sends no sensitive content or telemetry externally.

The [82 native analytics contracts](../tests/test_ui_analytics.py) check strict
counts, incomplete/error results, scope, timestamps, safe rendering and filters.
All 82 passed and are included in the 1,627-pass ordinary regression. All 18 actual
Chromium chart checks passed using synthetic reports, including keyboard filtering,
375px layout, dark theme, operational errors and malformed reports; no console
errors or off-origin requests were observed. The 32 skipped and 8 deselected slow
tests in the ordinary regression remain explicit. See
[completion verification](modules/prompt_injection.md#completion-verification).
The [earlier engineering assessment](../internal_docs/diagrams/atk001-final-engineering-review.md)
remains the planning/implementation record for the bounded detector. See
[ATK-001 criteria and limits](modules/prompt_injection.md). Chart implementation
does not establish an independent detector certification or deployment readiness.
