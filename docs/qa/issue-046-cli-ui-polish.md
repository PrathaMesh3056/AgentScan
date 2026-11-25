# Issue #46 — CLI and UI polish plan

- **Issue:** [#46](https://github.com/PrathaMesh3056/AgentScan/issues/46) (P3)
- **Branch:** `fix/qa-046-cli-ui-polish`
- **Base:** `origin/main` at `7c17743`
- **Status:** plan committed before implementation; draft PR opens against this plan.

## Scope

This is a bounded polish pass over six independently reproducible defects. It does not
change scan behavior, report schemas, gateway state, or the frozen `agentscan/core/` and
`agentscan/action/` trees.

| QA ID | Defect at base | User-visible symptom |
|---|---|---|
| QA-028 | Typer and Click both append command suggestions | `agentscan audt` prints `Did you mean 'audit'? Did you mean 'audit'?` |
| QA-029 | Loguru keeps its default `DEBUG` sink | Every registry import prints `DEBUG ... Registered: <...>` before normal output |
| QA-126 | Rich help table is width-constrained to 80 columns | `scan --help` renders `--allow-unverified-completi…` |
| QA-127 | Only `--help` is registered, and `heal-server` claims `-h` for host | `-h` fails on most commands and is misparsed on `heal-server` |
| QA-176 | Readiness card always appends a reason fallback | A gateway with `status: ready` still renders `Reason: unknown_reason` |
| QA-178 | MCP opener assigns the `scan_target` alias directly to the selector | The harness button opens the modal with no valid tool selected |

## Implementation

### 1. Duplicate suggestions (QA-028)

`agentscan/_cli/_shared.py` creates the Typer apps with `suggest_commands=False`.
Click 8.4 already adds a `NoSuchCommand.possibilities` suggestion, so Typer's extra
append was redundant. The native suggestion remains:

```text
No such command 'audt'. Did you mean 'audit'?
```

The same setting is applied to `api_app` so nested commands behave consistently.

### 2. Default logging (QA-029)

`agentscan/_cli/_shared.py` configures the default Loguru sink once at CLI import:

- default level: `INFO`;
- override: `AGENTSCAN_LOG_LEVEL` (validated against Loguru level names, falling back
  to `INFO` for an unknown value);
- only the default handler is replaced, so explicit user sinks are not removed.

This removes import-time `DEBUG` noise while retaining warnings about optional extras.
`AGENTSCAN_LOG_LEVEL=DEBUG` restores the old detail for troubleshooting.

### 3. Truncated option names (QA-126)

Typer's Rich help console defaults to the terminal width, which is 80 columns in a
non-TTY or narrow terminal. `agentscan/_cli/_shared.py` raises the help width floor to
100 columns (respecting a wider `TERMINAL_WIDTH`/terminal). The longest command option,
`--allow-unverified-completion` (29 characters), then renders in full.

### 4. Consistent `-h` (QA-127)

The root Typer app is created with
`context_settings={"help_option_names": ["-h", "--help"]}`. Click propagates the help
option names to child contexts, so subcommands accept `-h` without editing every
decorator. `heal-server` loses its `-h` host alias (its `--host` long form and `-p`
port alias are unchanged; the documented examples already use `--host`).

### 5. Ready state (QA-176)

`agentscan/ui/static/dashboard-app-core.js` builds the readiness reason separately:

- when readiness is `ready`, render no reason fragment, even if a stale
  `unknown_reason` was supplied;
- when readiness is not ready and a reason is present, render it;
- when readiness is not ready and no reason is present, keep the bounded
  `unknown_reason` fallback.

The 2xx probe card still shows status and latency; the main not-ready copy is unchanged.

### 6. MCP preselection (QA-178)

`agentscan/ui/static/dashboard-app-actions.js` normalizes the legacy `scan_target`
alias to `agentscan_scan`, then selects the requested tool only when it is a member of
the current option list. Otherwise it keeps the current valid selection or falls back to
the first real catalog tool. Arguments are refreshed from the final selection.
`dashboard-app-renderers.js` uses `agentscan_scan` for the harness button so the normal
path needs no alias.

## Deferred to #40 (PR #60)

Verified at `7c17743`:

- `aria-current` is absent from `agentscan/ui/` and its tests.
- Only `.coverage-link` has a 24px `min-height`; there is no general 24px touch-target
  rule.

Both are owned by [#40](https://github.com/PrathaMesh3056/AgentScan/issues/40) and
[PR #60](https://github.com/PrathaMesh3056/AgentScan/pull/60). This branch does not
duplicate that implementation.

## Regression tests

New focused tests, one failing-before/passing-after case per item:

| Test | Item |
|---|---|
| `test_mistyped_command_suggests_once` | duplicate suggestion appears exactly once |
| `test_default_logging_is_not_debug` | subprocess `list-attacks` emits no `DEBUG` lines |
| `test_help_does_not_truncate_long_option_names` | full `--allow-unverified-completion` in `scan --help` |
| `test_dash_h_is_help_everywhere` | root, `scan`, `heal-server`, and `api serve` all accept `-h` |
| `test_ready_gateway_status_omits_unknown_reason` | ready card has no `unknown_reason`; not-ready fallback remains |
| `test_mcp_modal_selects_a_real_tool` | alias maps to `agentscan_scan` and unknown names fall back to the first real tool |

The CLI tests use Typer's `CliRunner`. The two dashboard tests execute the static
JavaScript in Node's `vm` with a minimal DOM stub; they skip when `node` is unavailable.

## Verification

```powershell
$env:PYTHONDONTWRITEBYTECODE='1'
& 'D:\prathamesh\AgentScan-gw-impl\.venv\Scripts\python.exe' -c "... pytest tests/test_cli_polish.py tests/test_ui_polish.py ..."
& 'D:\prathamesh\AgentScan-gw-impl\.venv\Scripts\python.exe' -m pytest tests/test_cli.py tests/test_ui_structure.py tests/test_ui_gateway_status.py -q
& 'D:\prathamesh\AgentScan-gw-impl\.venv\Scripts\ruff.exe' check <changed Python>
& 'D:\prathamesh\AgentScan-gw-impl\.venv\Scripts\ruff.exe' format --check <changed Python>
& 'D:\prathamesh\AgentScan-gw-impl\.venv\Scripts\mypy.exe' <changed Python>
```

Environment-only failures (if any) are reported verbatim and checked against the base
commit; they are not treated as regressions.

## Non-goals and constraints

- No changes to `agentscan/core/`, `agentscan/action/`,
  `agentscan/reporting/audit_verifier.py`, or `docs/RUNTIME_GATEWAY.md`.
- No work on P1 #20–#34, #43, #45, #47, #48, or #49.
- No merge, force push, or force merge.
- Synthetic fixtures and loopback targets only; no credentials or external providers.

## Risks

- Raising the help width floor can make help lines wrap on terminals narrower than 100
  columns, but option names remain intact and copyable.
- Removing `heal-server -h` is a deliberate CLI correction; scripts should use
  `--host` (already the documented form).
- Logging can be restored with `AGENTSCAN_LOG_LEVEL=DEBUG`; application code that
  configures Loguru explicitly still owns its sinks.
