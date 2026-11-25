# Issue #40 — Accessibility: mobile drawer, toasts, and touch targets

Status: implementation plan (draft PR)
Issue: [#40](https://github.com/PrathaMesh3056/AgentScan/issues/40) (P2, labels: bug)
QA IDs: QA-183, QA-184, QA-185, QA-186, QA-187
Base: `origin/main` at `7c17743`
Branch: `fix/qa-040-accessibility`

## Problem

The dashboard ships a mobile navigation drawer, a transient toast, and a set of
small inline actions. None of them currently meet the accessibility exit
conditions in issue #40:

1. **Drawer focus management (QA-183).** `toggleSidebarMobile()` only toggles a
   `mobile-open` class and the backdrop. Opening the drawer leaves focus on the
   hamburger button behind the overlay, Tab walks out of the drawer into the
   page beneath it, Escape does nothing, and closing never restores focus.
2. **Drawer semantics (QA-184).** The hamburger (`#btn-mobile-menu`) has no
   `aria-expanded` or `aria-controls`, and the open drawer is not exposed as a
   modal dialog, so assistive technology cannot tell that navigation is open or
   what the button controls.
3. **Silent toasts (QA-185).** `showToast()` builds a plain `div` with no live
   region, `role`, or announcement semantics. Messages such as "Report download
   failed." are visible only.
4. **No active-page state (QA-186).** `switchTab()` styles the active nav link
   with classes but never sets `aria-current`, so the current page is conveyed
   only by color.
5. **Undersized targets (QA-187).** Inline actions such as `.coverage-link`
   (11px text, 3px vertical padding) are shorter than the 24x24 CSS px minimum
   in WCAG 2.2 SC 2.5.8.

## Reproduction

Environment: dashboard at `http://127.0.0.1:<port>/` with synthetic fixtures
only (`tests/fixtures/...`); no real credentials, customers, or external
providers.

1. Narrow the viewport below `1024px` (mobile layout) and reload the dashboard.
2. Activate the hamburger (`#btn-mobile-menu`). Observe: focus stays on the
   hamburger behind the drawer; `aria-expanded` is absent.
3. Press Tab repeatedly. Observe: focus leaves the drawer and enters the page
   content underneath the backdrop.
4. Press Escape. Observe: the drawer stays open.
5. Close the drawer (backdrop or hamburger). Observe: focus is not returned to
   the opener.
6. Trigger a toast (for example, download a report before loading an
   assessment). Observe: no live region, no screen-reader announcement.
7. Switch tabs. Inspect the active `.sidebar-nav-item`: no `aria-current`.
8. Inspect `.coverage-link` in the Overview coverage card: rendered height is
   about 17px, below the 24px minimum.

## Scope

In scope (single accessibility-only change set):

- New focused module `agentscan/ui/static/dashboard-a11y.js` with:
  - `createDrawerController(...)` — focus entry, Tab/Shift+Tab trap, Escape,
    focus restore, `aria-expanded`, `aria-controls`, and dialog semantics
    (`role="dialog"`, `aria-modal="true"`) while open.
  - `announce(...)` — live-region toast announcements, including re-announcing
    repeated identical messages.
  - `setActiveNavItem(...)` — `aria-current="page"` on the active nav link.
- Minimal wiring: `dashboard-app-core.js` delegates `toggleSidebarMobile()`,
  `showToast()`, and the active nav state in `switchTab()` to the module, with
  the existing behavior preserved when the module is absent.
- `index.html`: module script tag, `aria-expanded`/`aria-controls` on the
  hamburger, labelled navigation landmark and drawer, persistent live-region
  toast container, and initial `aria-current="page"` on the Overview link.
- `dashboard.css`: explicit 24x24 CSS px minimum target rules for buttons,
  role=button controls, summaries, and inline text actions.

Out of scope (intentionally not touched):

- Any scan workflow/state machine, severity ordering, target authentication,
  or report-retention behavior from issue #39.
- P1 issues #20-#34 and their files.
- `agentscan/core/`, `agentscan/action/`, `docs/RUNTIME_GATEWAY.md`,
  `agentscan/reporting/audit_verifier.py`, and the Python back end at large.
- Desktop modal dialogs, sidebar collapse behavior, and visual redesign.

## Test plan

Regression tests must fail on `7c17743` and pass after the change.

1. **Node keyboard/DOM tests** (`tests/js/test_dashboard_a11y.mjs`, run with
   `node --test`) against a deterministic in-memory DOM stub. They assert:
   - opening the drawer moves focus to the first focusable element and sets
     `aria-expanded="true"`, `role="dialog"`, `aria-modal="true"`;
   - Tab at the last focusable wraps to the first, Shift+Tab at the first wraps
     to the last, and focus cannot leave the drawer;
   - Escape closes the drawer, restores focus to the opener, and removes dialog
     semantics;
   - closing via the backdrop/controller restores focus;
   - `announce()` writes to the live region (`role="status"`,
     `aria-live="polite"`, `aria-atomic="true"`) and re-announces repeats;
   - `setActiveNavItem()` sets exactly one `aria-current="page"`.
2. **Python DOM/wiring tests** (`tests/test_ui_accessibility.py`) parse
   `index.html`, the dashboard scripts, and `dashboard.css` to assert the static
   contract: `aria-controls`, initial `aria-expanded="false"`, labelled nav,
   live-region container, script load order, module wiring, and the 24px
   target-size rules. The module also invokes the Node keyboard tests so a
   single pytest run covers both layers.
3. **Targeted checks**:
   - `python -m pytest tests/test_ui_accessibility.py -q`
   - `python -m pytest tests/test_ui_structure.py tests/test_ui_form_validation.py tests/test_ui.py -q`
   - `ruff check agentscan tests` and `ruff format --check` on changed Python
     files (the test file; no production Python changes are expected).
   - `node --check agentscan/ui/static/dashboard-a11y.js` and
     `node --check agentscan/ui/static/dashboard-app-core.js`.

## Risks

- `toggleSidebarMobile()` is called from several places (backdrop click, brand
  click, tab switch). Restoring focus unconditionally on close could move focus
  unexpectedly during tab navigation; the controller restores focus only when
  the close is user-initiated (Escape, backdrop, explicit close), and falls
  back to the hamburger opener.
- The dialog role is applied only while the drawer is open on mobile, so the
  desktop sidebar keeps its navigation-landmark semantics.
- Minimum target-size rules could shift dense toolbars by a few pixels; the
  rules are scoped to interactive controls and use `min-height`/`min-width`
  without changing padding, typography, or layout widths.
- The persistent live region is visually hidden by the existing toast classes
  until a message arrives; it is empty on load and does not add noise.
- Node is required for the JS regression test; the Python test skips the Node
  layer when `node` is unavailable and still enforces the static contract.
