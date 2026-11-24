# QA-038 - Reliability and error handling

**Issue:** [#38 - [P2] Reliability and error handling](https://github.com/PrathaMesh3056/AgentScan/issues/38)
**Status:** Draft - written plan committed first; implementation follows on this branch.
**Base:** main at 7c17743
**Constraint:** no changes under `agentscan/core/`, `agentscan/action/`,
`agentscan/reporting/audit_verifier.py`, or `docs/RUNTIME_GATEWAY.md`; no P1 (#20-#34) files.

## Summary

Issue #38 collects nine QA findings about failures that surface as raw tracebacks, as a
success banner that is printed before the service actually listens, or as an unbounded
wall of module-level error lines with no operator guidance. This branch fixes the
highest-value bounded subset and records the rest as explicitly deferred.

The issue text lists IDs only (QA-079, QA-101, QA-133, QA-137, QA-140, QA-141, QA-151,
QA-160, QA-179). The mapping below comes from the issue theme (bind failures, missing
Playwright, wrong-typed profiles, target 500s, cancel races) and from reproductions on
this clone. Where an ID could plausibly belong to more than one class the class notes it;
the owner can re-point an ID without changing the code.

| ID | Class | Observed before the fix | This PR |
| --- | --- | --- | --- |
| QA-079 | Dashboard bind failure | Banner printed, raw uvicorn `[Errno 10048]` line, exit 3 | Fixed: bind first, then banner; bounded error |
| QA-133 | Dashboard bind failure (address/port) | Same path: invalid or occupied address/port surfaces uvicorn's raw bind error | Fixed with QA-079 |
| QA-151 | Dashboard bind failure (no false success) | Same path: operator sees a URL that never served | Fixed with QA-079 |
| QA-137 | Wrong-typed profile values | `ValueError`/`TypeError` traceback from `browser`, `attacker_turns`, `request_template`, `framework`, `output` | Fixed: bounded profile field validation |
| QA-140 | Wrong-typed profile/options | Same tracebacks; invalid `framework` string also escapes as `ValueError` | Fixed with QA-137 |
| QA-101 | Missing Playwright | `agentscan init --browser` traceback; `agentscan scan --browser-url` shows only `Status: ERROR` with zero explanation | Fixed: pre-work bounded error + failure guidance |
| QA-141 | Target HTTP 500 | 75 raw ERROR lines, 14 module errors, generic `Status: ERROR`, exit 3, no bounded cause | Fixed: bounded failure summary |
| QA-160 | Target connection error | Same shape with `ConnectError`; operator gets no bounded endpoint guidance | Fixed with QA-141 |
| QA-179 | Cancel race | `POST /api/scan/cancel` overwrites a finished scan's terminal status with `cancelled`, and marks an idle dashboard `cancelled` | Fixed: cancel is a no-op unless a scan is actually running |

## Reproductions (recorded on this clone, synthetic loopback only)

### A. Bind failure prints a success banner and a raw uvicorn error (QA-079/133/151)

Occupy a loopback port with a plain listening socket, then start the dashboard on it:

```
agentscan ui --port <occupied-port>
AgentScan UI: http://127.0.0.1:51463
ERROR:    [Errno 10048] error while attempting to bind on address ('127.0.0.1', 51463):
          [winerror 10048] only one usage of each socket address ...
```

Exit code 3, with the URL announced before any listener existed. The same path handles
an invalid bind address or an out-of-range port: uvicorn's message is the only feedback.

### B. Wrong-typed target profile raises raw tracebacks (QA-137/140)

`agentscan scan --config bad.yaml` with a unique-key YAML mapping whose values have the
wrong type. All of these exit 1 with a Rich-formatted Python traceback:

```
browser: "yes"                -> ValueError: dictionary update sequence element #0 has length 1; 2 is required
attacker_turns: many          -> ValueError: invalid literal for int() with base 10: 'many'
request_template: 5           -> TypeError: RequestTemplate() argument after ** must be a mapping, not int
framework: [a, b]             -> ValueError: ['a', 'b'] is not a valid Framework
output: 123                   -> TypeError: argument should be a str or an os.PathLike object ...
```

### C. Missing Playwright is a traceback or an unexplained failure (QA-101)

```
agentscan init --browser http://127.0.0.1:9/
  ... traceback ...
  agentscan/core/discovery.py:217 in discover_widget
  ModuleNotFoundError: No module named 'playwright'

agentscan scan --browser-url http://127.0.0.1:9/chat --input-selector '#i' --response-selector '#r'
  ... Status: ERROR; evaluated 0/0 selected tests (exit 3, no explanation)
```

On the scan path the report does record `Scan setup: No module named 'playwright'`, but the
terminal output never states it, so the operator has no actionable next step.

### D. Target HTTP 500 / connection failures are unbounded (QA-141/160)

`agentscan scan http://127.0.0.1:<port>/chat` against a loopback fixture that always
returns 500:

```
2026-11-25 ... | ERROR | agentscan.attacks.scan.runner:_test_one:240 - Error testing variant OH-001: Target returned HTTP 500
2026-11-25 ... | ERROR | agentscan.attacks.scan.runner:_test_one:240 - Error testing variant OH-002: Target returned HTTP 500
  ... 75 such lines on stderr ...
Status: ERROR; evaluated 0/0 selected tests
Assessment is incomplete. Review module outcomes and errors in the report ...
Report written to ... (14 module errors, all target-side)
```

Exit code 3. The dominant cause (the target answered 500 to every request) is only
visible by reading the JSON report; the terminal gives no bounded operator guidance.
The connection-refused case is the same shape with `ConnectError`.

### E. Cancel overwrites a finished scan's status (QA-179)

With the dashboard idle or with a scan already completed:

```
POST /api/scan/cancel (scan completed) -> 200 {"status": "cancelled"}; state.scan_status["status"] == "cancelled"
POST /api/scan/cancel (idle)           -> 200 {"status": "cancelled"}; state.scan_status["status"] == "cancelled"
```

A cancel that races a finishing scan (or that arrives late) therefore replaces the
terminal `completed`/`failed` status with `cancelled`, and a stray cancel on an idle
dashboard invents a cancelled scan. It does not raise or hang, but it corrupts the only
status the dashboard shows.

## Scope

1. `agentscan ui`: bind the listening socket before announcing the dashboard URL and
   convert bind failures (port in use, invalid address, permission denied) into one
   bounded message with a next step.
2. `agentscan scan --config`: validate known profile keys before any scan work; wrong
   types and invalid enum values become bounded `BadParameter` errors (exit 2).
3. Browser dependency: check Playwright availability before a browser-backed scan or
   browser discovery starts, and make the post-scan failure summary name the missing
   package and the install commands.
4. Target failures: after an incomplete scan, print one bounded line naming the dominant
   target-side cause (HTTP status code or connection failure) and a next step, instead of
   leaving the operator with repeated module-level log lines.
5. Cancel: only a running scan can be cancelled; a late or duplicate cancel leaves the
   terminal status untouched and reports the current state.

## Non-goals / deferred

- `agentscan/core/` and `agentscan/action/` are off-limits for this branch. The scanners
  therefore still run on the CLI event loop and module-level error logging inside
  `agentscan/core/runner.py` is unchanged; the exit condition
  "All scanners run off the event loop" needs core approval and is deferred.
- Profile schema validation stays CLI-side; the `Target` model in core is unchanged.
- No new report fields, no dashboard redesign, no changes to cancel semantics for the
  REST API worker (postgres-backed jobs have their own cancellation contract).
- No real network targets or credentials are used: reproductions use loopback sockets and
  a synthetic 500 responder only.

## Proposed change

- `agentscan/_cli/_preflight.py` (new): profile field type validation, Playwright
  availability check with the install commands, and a bounded failure summary derived
  from `ScanReport.module_errors`.
- `agentscan/_cli/commands/scan.py`: validate the profile immediately after YAML load;
  validate `framework` as a bounded enum error; require the browser runtime when a
  browser connector is configured; print the bounded failure summary before the generic
  incomplete-scan message.
- `agentscan/_cli/commands/misc.py`: pass an `on_bound` callback to `serve_app` so the
  dashboard URL is printed only after the socket is listening; bound `RuntimeError` from
  the bind.
- `agentscan/ui/app.py`: add `bind_socket()` (bounded `RuntimeError` on failure) and
  change `serve_app()` to bind, invoke `on_bound(host, port)` with the actual bound port,
  then hand the listening socket to uvicorn.
- `agentscan/ui/routers/scan.py`: make `/api/scan/cancel` a no-op for idle/finished
  scans, use `Task.cancel()`'s return value to close the check/cancel race, and return
  `cancelled: false` with the current status.

## Test plan

- Bind: occupied loopback port -> exit 1, no `AgentScan UI:` banner, bounded message;
  `serve_app` with a patched `bind_socket` failure never calls `on_bound`; successful
  bind reports the actual port and passes the listening socket to uvicorn.
- Profile: each wrong-typed field exits 2 with a bounded message and no exception; a
  valid profile with a mocked runner still scans.
- Playwright: a browser-backed scan and `init --browser` exit 2 with the install
  guidance when the package is unavailable; the scan summary names the missing package
  when the failure is reported instead.
- Target failures: a report whose module errors are dominated by `HTTP 500` or
  `Connection failed` prints one bounded line, keeps exit 3, and does not echo raw
  exception bodies.
- Cancel: cancel after completion and cancel while idle keep the terminal status;
  cancelling a running task still returns `cancelled` and publishes `scan:cancel`.
- Regression tests are added first in `tests/test_qa038_reliability.py`; each fails on
  the base commit and passes after the change.
- Targeted + related suite: `pytest tests/test_qa038_reliability.py tests/test_cli.py
  tests/test_ui.py tests/test_ui_lifecycle.py -q`; Ruff on changed files.

## Risks and rollback

- Risk: pre-binding the socket changes how uvicorn starts the dashboard. Mitigation: the
  socket is only handed to `uvicorn.Server.run(sockets=[...])`, the supported uvicorn
  hook, and the dashboard tests still create the app through `create_app()`.
- Risk: profile validation rejects a profile that previously worked by accident.
  Mitigation: validate only known keys and only their container/primitive type; accept
  numeric strings for integer fields; unknown keys are ignored.
- Risk: the failure summary could mislabel a mixed-cause scan. Mitigation: it only fires
  for a non-`COMPLETE` report, counts bounded matches, and gives a generic fallback when
  no known cause dominates.
- Risk: cancel semantics change for clients that relied on `cancelled` always being
  returned. Mitigation: the response still returns 200 with a `status` field, adds
  `cancelled`, and accepts cancel only while a scan is running.
- Rollback: revert the four touched modules and delete `agentscan/_cli/_preflight.py`;
  the new tests pin the previous behaviour so the revert is visible.

## Remaining after this PR

- Moving every scanner off the event loop (core/action change; blocked by the issue
  constraint).
- Declarative profile schema shared with the dashboard API (core model change).
- REST API worker cancellation review (separate idempotency/cancellation contract).

## Review checklist

- [x] Written plan committed before implementation (this file).
- [ ] Regression test per failure class.
- [ ] Targeted tests and Ruff pass.
- [ ] No changes under agentscan/core/, agentscan/action/, audit_verifier.py, or
      docs/RUNTIME_GATEWAY.md.
- [ ] Commit messages reference #38.