# AgentScan Runtime Gateway v1 — Implementation Progress

**Last updated:** 2026-11-14
**Phase 0 commits:** `8654034` (skeleton), `2721a15` (strengthened test + gate evidence), `d074c9d` (coordinator evidence)
**CI commit:** `1393c88` (gateway extra, pre-commit, CLI smoke)
**Worktree:** `D:\prathamesh\AgentScan-gw-impl`
**Branch:** `feat/runtime-gateway-v1`
**Base:** `origin/main` @ `1ed8942` (`docs: mark runtime gateway spec approved`)

This file tracks phase gates, evidence, and decisions. It is not a security
approval, and it does not replace `docs/RUNTIME_GATEWAY.md`.

---

## Phase status

| Phase | Scope | Status | Evidence |
|---|---|---|---|
| 0 | Dependency gate, config/skeleton, import boundary | Verified and committed | Dependency/API gate and import-boundary test below |
| 1 | Policy bundle, signing/verification, evaluation | Approved (`1265516`); CI green (`a21ccd7`) | Phase 1 approval below |
| 2 | Receipts, chain, WAL, writer lease/epoch | Approved (`3c8579b`); CI green | Phase 2 approval below |
| 3 | Idempotency, recovery, reconciliation | Approved (`468e603`, fix `43357c8`); CI green | Phase 3 review/approval below |
| 4 | Identity, sessions, MCP server, protocol pin | Checkpoint complete | Phase 4 checkpoint below |
| 5 | Upstream client, mock upstream, end-to-end | Checkpoint complete (`870c72b`); CI green (`43349900818`) | Phase 5 checkpoint below |
| 6 | CI, docs/runbook, benchmark/soak, hot-path fix, draft PR | Accepted (`2262701`, `f7fc7e8`); CI green (`43587927683`); one-hour soak passed | Phase 6 checkpoint below |

Implementation stops at each user-requested checkpoint. Phases 1-3 are approved.
Phases 4-5 are checkpointed and CI-green. Phase 6 performance acceptance is
complete: the authorized hot-path fix reduces gateway overhead p99 from
78.628 ms to 9.864 ms against the 40 ms budget, and the full one-hour soak
passed. See the Phase 6 checkpoint for evidence.

---

## Phase 0 summary

Handoff §4's clean-worktree snapshot was stale at takeover: Luna's uncommitted
Phase 0 files (`pyproject.toml`, `uv.lock`, the gateway package, and the
import-boundary test) were already present. They were preserved, then committed
as the Phase 0 checkpoint.

The Phase 0 checkpoint contains:

- `pyproject.toml`: `agentscan-gateway` script, `gateway` extra, and `gateway`
  added to `full`.
- `uv.lock`: gateway extra metadata only; `mcp` remains `1.30.0`; 203 packages.
- `agentscan/gateway/`: eight Python modules — `__init__`, `__main__`, `cli`,
  `config`, `canonical`, `models`, `errors`, `logging`.
- `tests/test_gateway/test_import_boundary.py`.


---

## Phase 0 checkpoint

Committed as the Phase 0 checkpoint after the user confirmed Phase 0 and
requested a stronger import test and exact gate evidence. Contents:

- `pyproject.toml` — gateway extra/script, `full` union.
- `uv.lock` — gateway metadata only.
- `agentscan/gateway/` — Phase 0 skeleton; no security-critical logic.
- `tests/test_gateway/test_import_boundary.py` — imports every discovered
  gateway submodule in a subprocess and verifies the forbidden modules stay
  unloaded.
- `PROGRESS.md` — this file.

The checkpoint is **not** a claim that the v1 security gates are met.

Checkpoint commits:

- `8654034` — skeleton: script/extra, gateway package, import-boundary test,
  initial `PROGRESS.md`.
- `2721a15` — strengthened import-boundary test and captured gate evidence.
- `d074c9d` — coordinator rerun evidence and stale-handoff correction.

---

## Phase 0 verification

The dependency/API gate commands and their captured outputs:

```powershell
uv sync --locked --extra gateway --dev
Resolved 203 packages in 1ms
Checked 118 packages in 14ms

uv run --no-sync python -c "import mcp; from mcp.types import LATEST_PROTOCOL_VERSION; from mcp.server.streamable_http_manager import StreamableHTTPSessionManager; from mcp.server.auth.provider import AccessToken, TokenVerifier; from mcp.server.auth.middleware.bearer_auth import BearerAuthBackend, AuthenticatedUser; from mcp.client.streamable_http import streamable_http_client; from mcp.client.session import ClientSession; assert LATEST_PROTOCOL_VERSION == '2025-11-25'; print('mcp gate ok')"
mcp gate ok

uv run --no-sync python -m pytest -q tests/test_gateway/test_import_boundary.py
.                                                                        [100%]
1 passed in 0.37s

uv run --no-sync python -m agentscan.gateway --help
usage: agentscan-gateway [-h] [{serve,verify,policy,reconcile}]

positional arguments:
  {serve,verify,policy,reconcile}
                        gateway operation (implemented in subsequent phases)

options:
  -h, --help            show this help message and exit

git diff --check
(no output; exit code 0)

gh pr view 12 --json state,isDraft,mergedAt
{"isDraft":false,"mergedAt":null,"state":"OPEN"}
```

`mcp` was `1.30.0`; `uv.lock` added gateway extra metadata without changing
locked package versions. Windows Application Control blocked direct execution
of the generated `pytest` and `agentscan-gateway` executables, so the Python
module commands above were used and passed.

### Coordinator rerun (2026-11-10)

The coordinator independently re-ran the gate after commit `2721a15`:

```text
uv sync --locked --extra gateway --dev
Resolved 203 packages in 1ms
Checked 118 packages in 8ms

MCP API gate
mcp gate ok

uv run --no-sync python -m pytest -q tests/test_gateway/test_import_boundary.py
.                                                                        [100%]
1 passed in 0.46s

gh pr view 12 --json state,isDraft,mergedAt
{"isDraft":false,"mergedAt":null,"state":"OPEN"}
```

The direct `pytest` launcher remains blocked by Windows Application Control;
the Python module invocation was used instead. No policy, identity, receipt,
session, or upstream code was written.


---

## CI (Phase 0 follow-up)

`.github/workflows/validate.yml` was updated in `1393c88` to:

- install the `gateway` extra in both `uv sync` and `uv export`;
- run `pre-commit run --all-files --show-diff-on-failure`, so the mypy,
  check-toml, and check-merge-conflict hooks that Windows Application Control
  blocked locally now execute in CI;
- keep the explicit `mypy agentscan` step;
- smoke-test `agentscan-gateway --help`.

The gateway export was verified locally: 2,102 lines, including `mcp==1.30.0`,
`cryptography==50.0.1`, and `pyjwt==2.15.1`.

---

## Phase 1 authorization and gate

**Status:** authorized for Luna; not started.
**Implementer:** Luna (Codex). The coordinator reviews and runs tests; it does
not write policy verification code.

Authorized scope, and nothing beyond it:

- signed policy-bundle YAML envelope;
- YAML loader that rejects duplicate keys and anchor/alias use;
- Ed25519 signature verification **before** constructing any policy object;
- key-ID derivation;
- bundle/schema validation, including unknown-field rejection;
- deterministic rule precedence, including overlapping rules;
- redaction configuration;
- `policy sign` and `policy verify`;
- unit tests for: expired bundle, tenant mismatch, key mismatch, duplicate YAML
  keys, anchors/aliases, invalid regex, unknown fields, overlapping rules, and
  key rotation.

Required invariants for review:

1. Signature is verified over the exact signed bytes before YAML policy
   structures are materialized into policy objects.
2. The loader rejects duplicate keys at every mapping depth.
3. Anchors and aliases are rejected, not silently expanded.
4. Unknown fields are errors, not ignored.
5. Precedence is deterministic and tested for overlapping rules.
6. Key rotation selects a trusted key by derived key ID and fails closed on an
   unknown or mismatched key.

**Hard stop:** Phase 1 ends with a checkpoint. Do not start Phase 2
(receipts/WAL/sessions) until the coordinator has inspected the full Phase 1
diff, run the policy test matrix, ruff, and mypy, and reported the evidence.

Phase 1 protected areas:

- `docs/RUNTIME_GATEWAY.md` is the approved spec. It must not be edited to
  match the implementation; conflicts stop the phase and are reported.
- `agentscan/cli.py` is a read-only reference. It must not be edited, and the
  gateway must not import it.
- Phase 1 CLI work is limited to `policy sign` and `policy verify`. No serve
  behavior, config fields, identity code, or server wiring.
- Policy models may live in `agentscan/gateway/models.py` if needed, with a
  minimal change.
- `agentscan/core/`, `agentscan/action/`, the action-verification spike, and
  PR #12 remain untouched.

### Phase 1 schema-validation decision (2026-11-10)

The v1 envelope carries only `schema_hash`; it contains no tool schema, and
`policy sign`/`policy verify` accept no schema input. Prompt §6.2's
argument-name-to-schema membership check therefore cannot run in Phase 1.
Phase 1 validates all bundle-contained structure and defers that check to
Phase 5, where the upstream catalog provides `inputSchema`. Phase 5 must reject
the policy/catalog pairing and fail closed before serving or dispatching when a
rule names an argument absent from the schema. This is a sequencing deferral,
not a waiver. The approved spec is not edited.

### Phase 1 review (2026-11-10)

**Commit:** `4534330` (`feat(gateway): implement Phase 1 signed policies`).
**Verdict:** not approved yet; Phase 2 remains blocked.

Scope is correct: only `agentscan/gateway/policy.py`,
`agentscan/gateway/cli.py`, and `tests/test_gateway/test_policy.py` changed.
`docs/RUNTIME_GATEWAY.md`, `PROGRESS.md`, dependencies, and protected areas
were untouched. The worktree is clean.

Independent checks:

- `python -m pytest tests/test_gateway -q` -> `67 passed`.
- `ruff check agentscan/gateway tests/test_gateway` -> `All checks passed!`.
- `ruff format --check ...` -> `11 files already formatted`.
- Direct mypy remains blocked by Windows Application Control. Mypy 1.19.1 was
  run from a pure-Python copy of the installed package (`compiled: no`):
  `mypy agentscan` -> 20 errors, all in `agentscan/gateway/policy.py`; no
  errors elsewhere.

Blocking mypy errors:

- `_fail` is annotated `-> None`; it must be `NoReturn` so validation branches
  narrow types after raising.
- `compose_node` must handle the base-class `Node | None` return.
- Validated `decision`, `risk`, `enforcement`, and
  `resource_tenant_enforced` values need explicit `Literal` casts (or
  equivalent) before constructing `PolicyRule`/`ToolPolicy`.

Phase 2 must not start until Luna fixes these, reruns the tests/ruff/mypy, and
the coordinator verifies the new commit. CI/pre-commit must still run on the
draft PR.

### Phase 1 approval (2026-11-10)

**Fix commit:** `1265516` (`fix(gateway): narrow validated policy types`).
**Verdict:** approved. Phase 2 is authorized to start from this checkpoint.

The fix changes only `agentscan/gateway/policy.py` (+13/-7): `_fail` is now
`NoReturn`, `compose_node` rejects a `None` node, and the four validated values
are cast to their declared `Literal` types before model construction. No
validation branch, test, dependency, spec, or protected file changed.

Independent checks on `1265516`:

- `python -m pytest tests/test_gateway -q` -> `67 passed`.
- `ruff check agentscan/gateway tests/test_gateway` -> `All checks passed!`.
- `ruff format --check ...` -> `11 files already formatted`.
- Mypy 1.19.1 (pure-Python copy, `compiled: no`) `mypy agentscan` ->
  `Success: no issues found in 199 source files`.

CI and the full pre-commit suite passed on `0f305f7` in draft PR #15
(<https://github.com/PrathaMesh3056/AgentScan/actions/runs/42769268471>):
`validation / test (3.12)` and `validation / test (3.13)` both succeeded. The
jobs cover pre-commit, mypy, the gateway CLI smoke test, the full test suite,
the dependency audit, and the build/artifact smoke tests.

The intervening change is `0f305f7` (`fix(ci): preserve Markdown line breaks in
pre-commit`). It adds `--markdown-linebreak-ext=md` so the approved spec's
deliberate two-space Markdown line breaks are not rewritten. The spec itself is
unchanged. This `PROGRESS.md` update is documentation-only.

---

PR #12 is open and unmerged. Its `isDraft` value is `false`; the query was
read-only and did not modify the PR.

---

## Phase 2 review (2026-11-10)

**Scope:** staged additions only — `agentscan/gateway/receipts.py` (+780) and
`tests/test_gateway/test_receipts.py` (+531). HEAD remains `a21ccd7`; no Phase 2
commit exists. `PROGRESS.md` is modified only by the coordinator.

**Verdict:** not approved. The five prior findings are substantively fixed and
have regression tests, but two CI-gating defects and one receipt-state gap
remain. Phase 3 stays blocked.

Verified independently:

- `pytest tests/test_gateway -q` -> `103 passed`.
- `ruff check` and `ruff format --check` on the gateway and its tests -> clean.
- Windows `mypy agentscan` -> 200 files clean.
- `mypy --platform linux agentscan` -> 5 errors in `receipts.py`
  (`ctypes.WinDLL`, `ctypes.WinError`, `ctypes.get_last_error`). CI runs mypy on
  Ubuntu, so the staged diff would fail CI as-is.
- Windows `_fsync_directory` probe on a temporary directory succeeds.
- Full local suite: `42 failed, 3117 passed, 32 skipped`. Every failure is a
  frozen benchmark-digest mismatch in untouched files, caused by the Windows
  CRLF checkout; after CRLF-to-LF normalization the frozen digests match for
  ATK-002, ATK-008, ATK-009, and ATK-011. Those failures are environmental and
  do not block Phase 2.

Fix coverage: mixed tenant/gateway/chain identity, foreign WAL replay (including
a full-proposal check before any JSONL write), and expired retention lookup each
have dedicated tests; the `require_approval` model check and parent-directory
fsync have tests as well.

Blocking:

1. **Linux mypy.** Guard the Windows branch with `sys.platform == "win32"` and
   keep the `ctypes`/`wintypes` imports inside it. Mypy narrows `sys.platform`,
   so Linux skips the Windows-only attributes while Windows still checks them.
   The pattern was validated against mypy 1.19.1 with `--platform linux` and the
   Windows default.
2. **Time-dependent retention test.**
   `test_retention_index_expires_entries_by_receipt_timestamp` calls `lookup()`
   without `now`, so it reads the wall clock. Its 29-day-old receipt expires at
   `2026-11-11T12:00Z`, and the test fails from then on. Pass `now=NOW` to both
   lookups.
3. **`require_approval` state.** The validator requires deny and blocked but
   still accepts `result.status == "pending"`. Spec §10 defines `pending` as an
   allowed call awaiting an outcome and a deny as terminal, so a v1
   `require_approval` receipt must record `denied`. Enforce it and extend the
   test to cover the forwarded-only case.

After the fixes: rerun the gateway tests, ruff, `mypy agentscan`, and
`mypy --platform linux agentscan`; commit only the two Phase 2 files; report the
hash without pushing. The coordinator re-reviews before CI.

Open note (not blocking): `response_hash` remains nullable for every phase. The
two-phase audit rule implies a decision receipt cannot carry a response hash,
but §10 does not state that rule explicitly. Decide before Phase 3 rather than
inventing a constraint now.

### Phase 2 approval (2026-11-10)

**Fix commit:** `3c8579b` (`feat(gateway): add receipt chain and WAL`).
**Verdict:** approved. Phase 3 is authorized to start from this checkpoint.

The commit contains only `agentscan/gateway/receipts.py` (+784) and
`tests/test_gateway/test_receipts.py` (+550). It resolves all three review
blockers:

- The Windows durability branch is scoped to `sys.platform == "win32"` with the
  `ctypes`/`wintypes` imports inside it.
- Both retention lookups pass `now=NOW`, so the test no longer reads the wall
  clock.
- `require_approval` requires `denied`, `blocked`, and terminal status, with
  invalid and valid regression cases.

Independent checks on `3c8579b`:

- `pytest tests/test_gateway -q` -> `103 passed`.
- `ruff check` and `ruff format --check` -> clean.
- `mypy --no-incremental agentscan` -> 200 files clean.
- `mypy --no-incremental --platform linux agentscan` -> 200 files clean.
- `git show --name-status 3c8579b` -> only the two Phase 2 files.

CI is green in run `42780293528`
(<https://github.com/PrathaMesh3056/AgentScan/actions/runs/42780293528>):
`validation / test (3.12)` and `validation / test (3.13)` both succeeded,
covering pre-commit, ruff, mypy, the CLI smoke, the full test suite, the
dependency audit, and the build/artifact smoke.

This `PROGRESS.md` update is a separate documentation commit; it is not part of
`3c8579b`. PR #15 remains a draft, and PR #12 remains untouched.

---

## Phase 3 review (2026-11-10)

**Scope:** `252f7d2..468e603` (`feat(gateway): add idempotency and recovery
state machine`), exactly four new files: `agentscan/gateway/idempotency.py`
(+501), `agentscan/gateway/recovery.py` (+269),
`tests/test_gateway/test_idempotency.py` (+586), and
`tests/test_gateway/test_recovery.py` (+621). `PROGRESS.md` is modified only by
the coordinator.

**Verdict:** approved. No spec conflict. Phase 4 may start after the CI run on
the review-fix commit is green.

Verified independently on `468e603`:

- `pytest tests/test_gateway -q` -> `129 passed`.
- `ruff check agentscan/gateway tests/test_gateway` -> clean.
- `ruff format --check agentscan/gateway tests/test_gateway` -> 17 files
  already formatted.
- mypy 1.19.1 as pure Python (the mypyc `lookup` DLL is blocked by Windows
  Application Control): `mypy --no-incremental agentscan` -> 202 files clean.
- `mypy --no-incremental --platform linux agentscan` -> 202 files clean.

Contract coverage:

- `hash_key` hashes exact UTF-8 bytes, enforces 1..`max_key_bytes`, and never
  stores or logs the raw key. `compute_request_hash` binds tenant, principal,
  agent, tool identity, and canonical arguments while excluding trace/RPC IDs,
  timestamps, and the key.
- `pair_receipts` rejects orphans, duplicate decision trace IDs,
  decision/outcome identity mismatches, denied decisions with outcomes, invalid
  outcome transitions, missing `sha256:` response hashes, and `no_effect`
  without an explicit confirmation note. The Phase 2 `validate_phase_status`
  model check already rejects `pending`/`denied` outcome receipts, so the
  suspected Phase 3 outcome-status gap is not a defect.
- `IdempotencyIndex` is rebuilt from durable receipts, is scoped by
  `(tenant, principal, tool_identity_hash, key_hash)`, returns conflict on a
  changed request hash, replays completed outcomes, denies pending/unknown
  retries, applies the same-content/new-key guard only while a prior state is
  pending or unknown, and expires with the retention window. Denied decisions
  are not dedupe entries.
- `append_outcome` requires the held writer lease and a stored decision,
  enforces the pending/unknown/terminal state machine and response-hash/null
  rules, and writes through the WAL/JSONL chain.
- `recover` verifies the chain and store cache, requires the lease, closes each
  pending decision once as `unknown` with a reconciliation note, never queries
  or retries upstream, and aborts without serving if an append fails.
- `reconcile` requires a validated authenticated `UpstreamConfirmation`,
  matches both key and request hashes, rejects a plain dict, refuses denied or
  completed decisions, appends `no_effect` only on an explicit `no_effect`
  confirmation, and keeps `unknown` for `applied`/`unknown` confirmations. No
  `--force` or assume-no-effect path exists.

Non-blocking Phase 4 invariant: `GatewayReceipt` does not couple
`result.status` to `effective_action` and `authorization.decision`. Phase 4
must construct coherent decision receipts (enforce deny =
`denied`/`blocked`/`deny`; allow and shadow/observe = `pending`/`forwarded`)
and test each mode. If the durable validator should enforce that coupling,
add it with a dedicated pairing test rather than inferring it in Phase 4.

### Phase 3 approval (2026-11-10)

**Fix commit:** `43357c8` (`test(gateway): avoid pytest module name collisions`).
**Verdict:** approved. Phase 4 is authorized to start from this checkpoint.

The first CI run on `468e603` failed before executing tests: pytest's default
prepend import mode loaded the new `tests/test_gateway/test_idempotency.py` and
`test_recovery.py` by basename, colliding with the existing
`tests/api/test_idempotency.py` and `tests/test_remediation/test_recovery.py`.
`43357c8` renames the two Phase 3 modules to `test_gateway_idempotency.py` and
`test_gateway_recovery.py`; no production code changed. Full-suite collection
now reports `3219 tests collected`.

Independent checks after the rename:

- `pytest tests/test_gateway -q` -> `129 passed`.
- `pytest tests .github/tests --collect-only -q` -> `3219 tests collected`.
- `ruff check` / `ruff format --check` -> clean.
- `mypy --no-incremental agentscan` -> 202 files clean.
- `mypy --no-incremental --platform linux agentscan` -> 202 files clean.

CI is green in run `42819566348`
(<https://github.com/PrathaMesh3056/AgentScan/actions/runs/42819566348>):
`validation / test (3.12)` and `validation / test (3.13)` both succeeded,
covering pre-commit, ruff, mypy, the gateway CLI smoke, the full test suite,
the dependency audit, and the build/artifact smoke. The phase-approval docs
commit `dcb8b0a` is also green in run `42820211660`
(<https://github.com/PrathaMesh3056/AgentScan/actions/runs/42820211660>).

This `PROGRESS.md` update is a separate documentation commit. PR #15 remains a
draft, and PR #12 remains untouched.

---

## CI hardening backlog (deferred, 2026-11-10)

Recorded for planning on 2026-11-10. The first pass was merged in PR #16
(`401c874`); the remaining gaps are listed below. CI changes were kept out of
the Phase 2 and Phase 3 review scopes.

What CI already enforces (`.github/workflows/validate.yml`, Python 3.12 and
3.13): pre-commit (ruff lint/format, mypy, YAML/TOML, conflict markers), ruff
lint and format check, `mypy agentscan`, the gateway CLI smoke, `pytest tests
.github/tests`, the hashed `pip-audit` dependency audit, wheel/sdist build, and
the artifact-install smoke.

Implemented and merged in PR #16 (`401c874`, 2026-11-10):

1. **Coverage gate.** Global total floor at 82% against the measured 83.46%
   baseline.
2. **Secret scanning.** A gitleaks CI job with a fixture allowlist, on pull
   requests and main pushes.
3. **Windows job.** A `windows-latest` job that verifies the frozen input
   digests, including the nested ATK-001 manifest.
4. **Maintenance.** Grouped weekly Dependabot updates for `uv` and
   GitHub Actions, plus `concurrency` cancellation for superseded runs.

Still open after #16:

- Per-module coverage floor for `agentscan/gateway/policy.py` and
  `agentscan/gateway/receipts.py`.
- A gitleaks pre-commit hook and a periodic full-history audit.
- A Windows job that runs the gateway tests and mypy, not only the digest
  regression.
- CODEOWNERS and required human approval, blocked until a second collaborator
  exists.

Repository setting applied on 2026-11-10, independent of PR #16: the active
`Protect main branch` ruleset requires pull requests, the four `validation`
checks, review-thread resolution, up-to-date branches, and squash-only merges;
it blocks deletion and non-fast-forward pushes. Bypass actors are empty, so
administrators are enforced. Zero required approvals is intentional while there
is one collaborator.

All four checks were green on the PR head `a48fbe5` in run `42821689769`
(<https://github.com/PrathaMesh3056/AgentScan/actions/runs/42821689769>).
PR #16 was squash-merged as `401c874` at 2026-11-10T13:23:01Z, and the
post-merge `main` CI run `42824011774`
(<https://github.com/PrathaMesh3056/AgentScan/actions/runs/42824011774>)
passed all four jobs. The gateway branch was then updated from `main` in merge
commit `bea2814`, which brings the four-check workflow onto PR #15; its checks
run on the new head.

Deferred for evaluation after the items above: a scoped Semgrep self-scan over
`agentscan/gateway` (the `semgrep` extra is installed for the product, not as a
self-check).

Not planned: extra Python/OS matrix combinations, external coverage upload
services, docs/changelog jobs, nightly suites, or per-PR mutation testing.
Each adds maintenance and false-positive cost without covering a threat in the
gateway threat model.

---

## Phase 4 checkpoint (2026-11-11)

**Scope:** identity verification, session binding, MCP transport guards, protocol
pinning, metrics, and the dashboard read-only gateway status surface.

Modules added:
- `agentscan/gateway/identity.py` — Ed25519 identity verification and tenant/principal binding.
- `agentscan/gateway/sessions.py` — session registry, identity binding, expiry.
- `agentscan/gateway/middleware.py` — authentication backend and strict MCP guards.
- `agentscan/gateway/server.py` — Streamable HTTP MCP app, `/healthz`, `/readyz`, `/metrics`.
- `agentscan/gateway/metrics.py` — bounded in-process metrics registry.

Readiness stays fail-closed: `Readiness` defaults false and `/readyz` returns 503
with one bounded reason (`issues[0]`) until Phase 5 wires policy/receipt/upstream
catalog state.

Identity-mismatch metric behavior: `IDENTITY_MISMATCH` increments
`agentscan_gateway_identity_mismatches_total{reason="identity_mismatch"}` and does
not increment `agentscan_gateway_protocol_failures_total` for the same reason.

Dashboard status surface: read-only `GET /api/gateway/status` plus the Runtime
Gateway tab rendering; misconfigured and unrecognized states render honest
explanations without probe cards, and dashboard fetch failures render a distinct
`request_failed` state.

Verification:
- `python -m pytest tests/test_gateway tests/test_ui_gateway_status.py tests/test_ui_features.py -q` -> `310 passed`.
- Full suite `python -m pytest tests -q` -> `3234 passed`, `48 failed`, `38 skipped`; failures are pre-existing frozen benchmark digest mismatches on Windows (CRLF), not gateway/UI changes.
- `python -m ruff check agentscan tests .github` -> `All checks passed!`.
- `python -m ruff format --check agentscan tests .github` -> `419 files already formatted`.
- `python -m mypy --no-incremental agentscan/gateway agentscan/ui` -> blocked by
  Windows Application Control (`ImportError: DLL load failed ... semanal_infer`); CI mypy is authoritative.
- `node --check` on the extracted inline script -> passed.

Follow-up fixes (commit `efa8672`): contained runtime exceptions as bounded `UPSTREAM_ERROR`, status-aware rejection counters, metrics mypy fix, and request-context extraction cast.

Audit fixes (commit `cae3247`): removed the duplicate CI pre-commit step; changed the readiness probe fallback to `is not None`; added fail-closed tests for default, non-`Readiness`, raising, and falsy probe/runtime cases.

Final CI run `42977747672` at `cae3247`: all four jobs passed (`validation / test (3.12)` and `(3.13)` -> `3358 passed, 32 skipped, 8 deselected`, 84.06% coverage; plus `validation / windows` and `validation / secrets`).

PR #15 remains draft; PR #12 remains untouched.

Phase 5 operational limit: the session registry removes expired records on access and exposes `prune_expired`, but no background scheduler invokes it; the MCP transport caps concurrent sessions at the SDK default (10,000). Phase 5 must schedule registry pruning or enforce a registry cap before production. This is not fixed in Phase 4. Closed in Phase 5 by `870c72b`; see below.

## Phase 5 checkpoint (2026-11-13)

**Scope:** authenticated upstream client, loopback mock upstream, upstream
catalog and schema-drift gating, receipt-backed dispatch, crash recovery,
`serve`/`reconcile` CLI wiring, and scheduled session pruning.

Modules added:
- `agentscan/gateway/upstream.py` — bounded MCP Streamable HTTP client with a TCP
  preflight, typed unavailability/timeout/protocol errors, and an authenticated
  `check_effect` status call.
- `agentscan/gateway/mock_upstream.py` — loopback-only mock CRM with fake data,
  constant-time credential and tenant checks, and idempotent effect records.
- `agentscan/gateway/catalog.py` — immutable catalog snapshot, canonical schema
  hashes, tool identity hashes, and policy/catalog mismatch detection
  (`server_mismatch`, `missing_upstream`, `schema_drift`,
  `rule_argument_missing`).
- `agentscan/gateway/runtime.py` — tool dispatcher with identity/session checks,
  catalog refresh, schema-drift denial and `tools/list` filtering, idempotency
  replay/conflict/unknown guards, shadow and observe enforcement, durable
  decision/outcome receipts, bounded upstream error mapping, and readiness.
- `agentscan/gateway/cli.py` — `serve` and `reconcile` commands with signed-bundle
  verification, credential environment lookup, startup recovery, writer lease
  ownership, catalog load, uvicorn/TLS wiring, and bounded session pruning.

Behavior:
- Decision receipts are durable before dispatch. The outcome is appended after
  the upstream call; an append failure falls back to `unknown`, returns
  `OUTCOME_UNKNOWN` to the caller, and marks the sink unhealthy. A failed sink
  short-circuits later calls with `GATEWAY_UNAVAILABLE`.
- Missing idempotency keys on high-risk tools deny with `IDEMPOTENCY_REQUIRED`;
  the denied receipt uses `reason="idempotency_required"`. Reuse with different
  arguments denies `IDEMPOTENCY_CONFLICT`; a different key with the same content
  while pending or unknown denies `OUTCOME_UNKNOWN` without dispatch.
- Schema drift and rule-argument mismatches deny `SCHEMA_DRIFT`, are removed from
  `tools/list`, and preserve the policy's observe enforcement mode.
- `require_approval` stays blocked in v1, including shadow mode. Shadow forwarding
  applies only to `deny`.
- Startup recovery closes pending decisions as `unknown`. `reconcile` queries the
  authenticated upstream `status_operation` and records `no_effect` only from
  `pending`/`unknown` when the upstream confirms it.
- The MCP client's own 408 `McpError` maps to `UpstreamTimeout`, matching the
  outer deadline path.
- The `serve` lifecycle starts a bounded pruner at `min(60s, idle/2)` and stops it
  before releasing the upstream session and writer lease.

Phase 5 commits: `ccb7fe5`, `8283c28`, `7dcd58e`, `72c0cc2`, `692671a`, `870c72b`.

Verification:
- `pytest tests/test_gateway -q` -> `329 passed` (Phase 5 adds 54 tests: 18
  upstream/catalog/mock, 19 runtime, 10 CLI, 7 end-to-end serve).
- `ruff check agentscan/gateway tests/test_gateway` -> clean;
  `ruff format --check` -> 37 files formatted.
- Local mypy remains blocked by Windows Application Control
  (`ImportError: DLL load failed ... semanal_infer`); CI mypy is authoritative.
- CI run `43349900818` at `870c72b`: all four jobs passed
  (`validation / test (3.12)`, `validation / test (3.13)`,
  `validation / windows`, `validation / secrets`). Both Linux test jobs report
  `3420 passed, 32 skipped, 8 deselected` and 84.16% coverage against the 82%
  floor.

No changes to `agentscan/core/`, `agentscan/action/`, the action-verification
spike, or PR #12. PR #15 remains draft.

## Phase 6 checkpoint (2026-11-14)

**Status:** checkpoint delivered; **performance acceptance passed**. The
gateway-overhead p99 blocker was fixed on 2026-11-14 (`2262701`) and the full
one-hour soak passed, so Phase 6 is recorded as accepted.

**Scope:** latency and soak harnesses, operations runbook, Windows gateway
CI, per-module coverage floors, stale dashboard-doc corrections, draft-PR
packaging, and the owner-authorized hot-path fix in the approved Phase 2/3
receipt and idempotency modules.

Files added:
- `benchmarks/runtime_gateway/bench_gateway.py` and `README.md`.
- `benchmarks/runtime_gateway/soak_gateway.py`.
- `tests/test_gateway/test_gateway_phase6_performance.py` (4 slow-marked tests).
- `docs/RUNTIME_GATEWAY_RUNBOOK.md`.

Files changed:
- `.github/workflows/validate.yml` - Windows installs the gateway extra and
  runs `pytest tests/test_gateway -q`; Linux adds per-module coverage floors
  (`policy.py` >= 90%, `receipts.py` >= 84%).
- `docs/dashboard_feature_matrix.md` - removed the stale "serve not wired until
  Phase 5" / "readyz fails closed until then" statements only. No dashboard
  behavior, CSS, markup, or JavaScript changed, and PR #18 does not touch this
  file.
- `agentscan/gateway/receipts.py` and `agentscan/gateway/idempotency.py` -
  incremental retention/trace indexes and trace-scoped outcome validation
  (`2262701`). This is the owner-authorized hot-path fix; behavior and receipt
  format are unchanged.
- `uv.lock` - `opentelemetry-api` 1.45.1 -> 1.45.2 to clear CVE-2026-126360
  in the required dependency audit (`f7fc7e8`).

### Benchmark

Command (full run, exact; 2026-11-14):

```text
.\.venv\Scripts\python.exe benchmarks\runtime_gateway\bench_gateway.py --samples 500 --policy-samples 5000 --warmup 50 --out C:\Users\prath\AppData\Local\Temp\opencode\agentscan-bench-hotpath-20261114.json
```

Host: `Windows-11-10.0.26200-SP0`, AMD64, 12 CPUs, Python 3.12.7. Sample
counts: policy 5000, append 500, gateway 500; warm-up 50 per metric; 550
upstream calls. Raw samples and the full host profile are in the JSON report.
Both chains verified (550 decision receipts; 1100 gateway receipts); no receipt
was lost; `all_within_budget: true`.

| Metric | p50 | p99 | Mean | Max | Budget p99 | Result |
|---|---:|---:|---:|---:|---:|---|
| Policy decision | 0.002 ms | 0.005 ms | 0.003 ms | 0.132 ms | < 10 ms | PASS |
| Decision-receipt append | 1.972 ms | 3.756 ms | 2.104 ms | 8.391 ms | < 20 ms | PASS |
| Gateway overhead | 6.796 ms | **9.864 ms** | 6.671 ms | 47.531 ms | < 40 ms | PASS |

The approved gate is the p99; one gateway sample (47.531 ms) exceeds 40 ms and
is recorded unadjusted. Before the fix, the same harness at `4fb2bb6` measured
gateway overhead p99 78.628 ms (p50 27.027 ms), with scaling 9.867 ms at 100
samples, 38.350 ms at 250, and 78.628 ms at 500. The pre-fix cost grew with
chain length, so the blocker was structural rather than host noise.

Root cause measured at 1003 receipts: `RetentionDedupeIndex.rebuild` took
18.89 ms, a plain durable `append` took 16.18 ms, and `append_outcome` took
20.48 ms. Each gateway call appends two receipts, and each append rebuilt the
retention index over the whole chain; `IdempotencyIndex.record` also rebuilt
all pairs and indexes on every receipt; `append_outcome` re-paired the whole
chain twice. These were O(n) operations per append on the hot path.

Fix (`2262701`):
- `ReceiptChainStore` updates the retention index and a new per-trace receipt
  index for each appended receipt instead of rebuilding; the trace index is
  rebuilt when the writer lease is acquired.
- `IdempotencyIndex.record` updates only the affected key/content scopes. The
  per-pair outcome update replaces just that pair.
- `append_outcome` validates only `store.receipts_for_trace(trace_id)` through
  `_validate_pair`, instead of two whole-chain `pair_receipts` passes.

Seven regression tests cover incremental retention pruning, per-trace lookup,
scope indexing, outcome replacement, and trace-scoped outcome validation.
Receipt format, chain hashes, validation rules, and CLI behavior are unchanged.

### Soak

Shortened smoke (run before the hot-path fix; 60 s, exact):

```text
.\.venv\Scripts\python.exe benchmarks\runtime_gateway\soak_gateway.py --seconds 60 --rate 5 --receipt-dir .benchmarks/soak-smoke --out .benchmarks/soak_smoke.json
```

Result: **PASS** for chain and memory. 281 decisions in 60.125 s, 0 failures,
562 receipts, 6 chain checks, chain verified from disk against the in-memory
head, all outcomes terminal, 0 lost receipts. Heap growth 2,690,946 B total /
9,576.3 B per decision against the 32,768 B per-decision bound (workingset RSS
+19,099,648 B). Latency with `tracemalloc` enabled was p50 152.95 ms and p99
304.10 ms, consistent with the pre-fix O(n) append path.

Full one-hour soak (run 2026-11-14, exact):

```text
.\.venv\Scripts\python.exe benchmarks\runtime_gateway\soak_gateway.py --seconds 3600 --rate 2 --receipt-dir C:\Users\prath\AppData\Local\Temp\opencode\agentscan-soak-1h-20261114 --out C:\Users\prath\AppData\Local\Temp\opencode\agentscan-soak-1h-20261114.json
```

Result: **PASS**. Ran 7,100 decisions in 3,620.594 s at 2.0/s, 0 failures.
14,200 receipts (14,200 durable; two per decision), 143 chain checks, chain
verified from disk against the in-memory head, all outcomes terminal, 0 lost
receipts, final head
`sha256:fbe40e811f9c257687f1f172781bf9dca989ff8e27efbcbdcf6ab948a9232686`.
Heap growth 72,854,423 B total / 10,261.2 B per decision against the 32,768 B
bound; peak 351,157,198 B; working-set RSS +578,621,440 B. Latency with
`tracemalloc` enabled: p50 13.06 ms, p99 33.96 ms, max 132.11 ms. The JSON
report and the 14,200-receipt chain remain under the recorded temp paths.

The one-hour soak is the Phase 6 acceptance evidence; it exercises the fixed
retention, trace, and idempotency indexes over a 14,200-receipt chain.

### Verification

- `python -m pytest tests/test_gateway -q` -> `340 passed` (includes the four
  slow Phase 6 tests).
- `python -m pytest tests/test_gateway/test_gateway_phase6_performance.py -q -m slow`
  -> `4 passed`.
- `python -m pytest tests -q -m "not slow"` -> `48 failed, 3303 passed, 32
  skipped, 12 deselected` in 515.87 s. All 48 are the known Windows CRLF
  frozen-input digest failures in untouched files (42 ATK evaluation failures
  from `Frozen ATK-002/005/008/009/011 cases changed`, plus 6
  `test_frozen_benchmark_digests.py` cases); none is in gateway code or the new
  harnesses.
- `python -m ruff check agentscan tests .github benchmarks` -> `All checks passed!`.
- `python -m ruff format --check agentscan tests .github benchmarks` -> `454
  files already formatted`.
- Local `python -m mypy agentscan` remains blocked by Windows Application
  Control (`ImportError: DLL load failed ... semanal_infer`); CI mypy is
  authoritative. The local pre-commit `mypy` and `check-yaml` hooks were skipped
  only after both failed with the same Application Control block
  (`WinError 4551` for the YAML hook); `validate.yml` was parsed directly with
  PyYAML, and CI runs both hooks authoritatively.
- CLI help verified for `agentscan-gateway --help`, `serve --help`, `reconcile
  --help`, `policy sign --help`, and `policy verify --help`; the runbook quotes
  those exact interfaces.
- CI run `43587927683` at `f7fc7e8`: all four jobs passed (`validation / test
  (3.12)`, `validation / test (3.13)`, `validation / windows`, `validation /
  secrets`). Linux gateway runs: `336 passed, 4 deselected`; `policy.py` 90.85%
  against the 90% floor and `receipts.py` 85.79% against the 84% floor. Full
  Linux suite: `3427 passed, 32 skipped, 12 deselected`, 84.17% coverage against
  the 82% floor. Windows gateway job: `340 passed` (the four slow Phase 6 tests
  run on Windows because that job omits `-m "not slow"`).
- The required dependency audit reports `No known vulnerabilities found` at
  `f7fc7e8`; `opentelemetry-api` 1.45.2 clears CVE-2026-126360, and `uv lock
  --check` passes.

### Remaining owner actions

1. Owner review/approval of `2262701`, which changes two previously approved
   Phase 2/3 modules. Receipt format, chain hashes, and validation rules are
   unchanged; the seven new regression tests, the 500-sample benchmark, and the
   one-hour soak are the acceptance evidence.
2. Merge remains an owner action. PR #15 stays draft in this work; do not mark
   it ready or merge from here. Credential rotation, the full-history gitleaks
   audit, and CODEOWNERS/human review remain owner actions.

Both Linux coverage floors and the Windows gateway job are confirmed in run
`43587927683`; no floor adjustment is needed.

No changes to `agentscan/core/`, `agentscan/action/`, the action-verification
spike, or PR #12. PR #15 remains draft.
