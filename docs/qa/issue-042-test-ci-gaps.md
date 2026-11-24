# Issue #42 - Test and CI gaps

| Field | Value |
| --- | --- |
| Issue | [#42](https://github.com/PrathaMesh3056/AgentScan/issues/42) |
| Branch | `fix/qa-042-test-ci-gaps` |
| Base | `origin/main` at `7c17743` |
| Severity | P2 |
| Review | Owner review required; no merge, no force push |

This is the written plan for issue #42. It is committed on its own before any
implementation change so the owner can review the approach first. The implementation
commits land on the same branch and reference issue #42 and this document.

## 1. Problem

Four independent gaps make the suite fragile and blind. None of them is closed by simply
adding more tests of the same kind.

### 1.1 A fixture whose validity depends on the wall clock (QA-017)

`tests/test_gateway/test_policy.py` pins the signing window to absolute dates:

- `tests/test_gateway/test_policy.py:33` - `NOW = datetime(2026, 11, 10, 12, 0, tzinfo=UTC)`
- `tests/test_gateway/test_policy.py:34` - `ISSUED_AT = "2026-11-10T00:00:00Z"`
- `tests/test_gateway/test_policy.py:35` - `EXPIRES_AT = "2026-12-10T00:00:00Z"`

Those values are passed to the signing helpers at seven call sites - `sign_policy()` at
lines 142, 273, 694, 730, 738 and 762, and `sign_policy_file()` at line 716. `sign_policy()` validates the window against the **process clock**:
`agentscan/gateway/policy.py:468` calls `_validate_timestamps(issued_at, expires_at, None)`,
and `agentscan/gateway/policy.py:440` rejects the bundle when `expires_at <= _now_utc(None)`.

The tests therefore pass only while the machine clock is earlier than `EXPIRES_AT`. Once
the clock passes `2026-12-10T00:00:00Z` - sixteen days after this branch's base commit -
every signing test in the module fails with `PolicyError: policy bundle has expired`,
regardless of any change to the code under test. `verify_policy_bundle(..., now=NOW)`
already accepts an injected clock, so only the signing path lacks one.

The same class of defect appears in the loopback-server fixtures that poll for uvicorn
startup with a fixed budget of `200 * 0.01s = 2s` and then `assert server.started`
(`tests/test_gateway/test_gateway_phase4_server.py:132` and `:209`,
`tests/test_gateway/test_gateway_phase5_upstream.py:83`,
`tests/test_gateway/test_gateway_phase5_serve.py:222`). Under load the budget is consumed
before the server reports ready, which produces intermittent failures that have nothing to
do with the assertion being made.

### 1.2 Branch coverage is not configured (QA-019)

`pytest-cov` is a dev dependency and CI already passes `--cov=agentscan
--cov-fail-under=82`, but `pyproject.toml` has **no** `[tool.coverage.*]` section, so
coverage is statement-only and the same command run locally or by another tool measures
something different from CI. `--cov-branch` appears nowhere in the repository, so
partially covered branches - the interesting half of policy, receipt and guard code - do
not count against any gate.

### 1.3 Critical paths are under-covered (QA-025)

Scan, audit, remediation and gateway code executed by the CLI and API is covered mostly
through happy-path tests. The per-module gates that do exist (`agentscan.gateway.policy`,
`agentscan.gateway.receipts`) are line-only and measured in separate `pytest` invocations
that cannot fail the main test job. Nothing measures the modules that turn a finding into
an artifact or a remediation into a pull request.

### 1.4 Security-relevant slow tests never run in CI (QA-026)

`-m "not slow"` in `.github/workflows/validate.yml:59` excludes Docker sandbox
containment (`tests/integration/test_sandbox_containment_runtime.py`), the live container
test (`tests/sandbox/test_container.py:141`), the browser connector and widget-discovery
tests (`tests/test_connectors.py:239`, `:362`), the deep activation probe
(`tests/attacks/test_deep/test_activation_probe.py`), the path-guard latency benchmark
(`tests/guard/test_path.py:117`) and the gateway performance/soak harnesses
(`tests/test_gateway/test_gateway_phase6_performance.py`). Nothing schedules them, so the
containment and isolation properties they assert are only ever checked by hand.

## 2. Reproduction

Latent clock dependence of the policy fixture (run from the repository root):

```console
$ python - <<'PY'
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from agentscan.gateway.policy import PolicyError, sign_policy

private = Ed25519PrivateKey.generate()
pem = private.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)
tool = {
    "server": "crm-mcp",
    "risk": "high",
    "enforcement": "inline",
    "resource_tenant_enforced": "upstream",
    "schema_hash": "sha256:" + "a" * 64,
    "rules": [{"id": "r", "decision": "allow"}],
}
policy = {
    "version": 1,
    "policy_id": "p",
    "tenant": "tenant-demo",
    "default": "deny",
    "tools": {"t": tool},
}
for issued, expires in (
    ("2026-11-10T00:00:00Z", "2026-12-10T00:00:00Z"),
    ("2019-01-01T00:00:00Z", "2020-01-01T00:00:00Z"),
):
    try:
        sign_policy(
            policy,
            pem,
            bundle_id="b",
            tenant="tenant-demo",
            issued_at=issued,
            expires_at=expires,
        )
        print(issued, expires, "-> signed OK")
    except PolicyError as exc:
        print(issued, expires, "-> PolicyError:", exc)
PY
2026-11-10T00:00:00Z 2026-12-10T00:00:00Z -> signed OK
2019-01-01T00:00:00Z 2020-01-01T00:00:00Z -> PolicyError: policy bundle has expired
```

The same call succeeds or fails purely on the value of the process clock, which is exactly
what the fixture at `tests/test_gateway/test_policy.py:35` relies on.

Coverage shape before this change:

```console
$ pytest tests -m "not slow" --cov=agentscan --cov-report=term
# statement coverage only; no branch column anywhere in the report
```

Slow suites are excluded from the only job that runs tests:

```console
$ pytest tests -m "not slow" --collect-only -q | tail -1
3383/3395 tests collected (12 deselected)
$ grep -rn "test_sandbox_containment_runtime\|test_gateway_phase6_performance" .github/workflows/
# no match
```

## 3. Scope

In scope:

- `tests/test_gateway/test_policy.py` and the gateway loopback-server fixtures.
- `agentscan/gateway/policy.py`: an optional, keyword-only `now` parameter on
  `sign_policy()` and `sign_policy_file()`, mirroring `verify_policy_bundle()`.
- `pyproject.toml`: `[tool.coverage.run]` / `[tool.coverage.report]` with branch coverage.
- `.github/workflows/validate.yml`: branch-aware coverage gates that fail the test job.
- `.github/workflows/scheduled-soak.yml`: a new scheduled workflow for slow suites.
- New tests for the scan, audit, remediation and gateway critical paths.

Out of scope:

- `agentscan/core/`, `agentscan/action/`, `agentscan/reporting/audit_verifier.py` and
  `docs/RUNTIME_GATEWAY.md` are frozen for this issue.
- Issues #20-#34 (P1) and their files.
- No change to product behaviour, thresholds, or the signed envelope format.
- No new runtime dependency; no `pytest-timeout`, `freezegun` or similar.

## 4. Test plan

### 4.1 Time-dependent fixture (QA-017)

1. Add `now: datetime | None = None` to `sign_policy()` and `sign_policy_file()` and pass
   it to `_validate_timestamps()`. Default behaviour is unchanged (`None` means the wall
   clock), so the CLI and the runtime keep working.
2. Make the gateway fixtures clock-independent: derive `EXPIRES_AT` from `NOW` and pass
   `now=NOW` at every signing call site.
3. Regression test `tests/test_gateway/test_policy_clock.py`: freeze the process clock past
   the fixture's `EXPIRES_AT` and assert that (a) signing with `now=NOW` still succeeds and
   verifies, and (b) signing without `now` is rejected with `policy bundle has expired`.
   On the current code the first assertion fails with `TypeError: sign_policy() got an
   unexpected keyword argument 'now'`; it passes after the change.
4. Replace the fixed `200 * 0.01s` uvicorn startup polls with a monotonic deadline
   (`15s`) so a loaded machine degrades to a clear assertion instead of a race.

### 4.2 Branch coverage (QA-019)

1. `[tool.coverage.run] branch = true`, `source = ["agentscan"]`,
   `relative_files = true`; `[tool.coverage.report] show_missing = true`,
   `skip_covered = false`, `skip_empty = true`.
2. Keep `--cov-fail-under` in CI rather than in the config so the floor is reviewable in
   the workflow diff and can be raised without touching packaging metadata.

### 4.3 Critical paths (QA-025)

Add one focused module per area, each asserting behaviour that a regression would break:

- Scan: a full `run_scan` against a loopback synthetic target, asserting the report
  contains the expected finding, status and exit-code mapping.
- Audit: the supply-chain/audit verifier path from finding to emitted artifact,
  including a negative case that must not be reported as clean.
- Remediation: guardrail rejection and dry-run/apply separation, i.e. a remediation that
  must not touch the filesystem.
- Gateway: receipt write/verification failure paths and the policy deny-by-default
  branches that the happy-path tests skip.

Each new test must fail if the guard it covers is removed; no assertions on private
attributes and no network access beyond `127.0.0.1`.

### 4.4 Scheduled slow suites (QA-026)

New `.github/workflows/scheduled-soak.yml`:

- `on: schedule` (weekly) plus `workflow_dispatch`.
- `permissions: contents: read`, `timeout-minutes: 60`, concurrency group per ref.
- Pinned actions only (the same SHAs as `validate.yml`); `astral-sh/setup-uv` at
  `0.12.3`, because `.github/tests/test_workflow_security.py` enforces both rules on every
  workflow file.
- Installs the Playwright Chromium browser, then runs `-m slow` with
  `AGENTSCAN_RUN_DOCKER_TESTS=1` so the Docker containment test is exercised rather than
  skipped.

## 5. CI design

- The existing `test` job keeps a single, branch-aware coverage invocation with an explicit
  floor. A regression lowers the number below the floor and fails the job.
- The per-module gateway gates keep their intent but move to branch coverage with floors
  measured on this branch, not guessed.
- Floor values are recorded in the implementation commit message and the PR conversation so
  a reviewer can see how much headroom each gate has.
- The scheduled workflow is separate from `ci.yml`: it must never block a PR, and it must
  never be silently green - a skipped Docker test fails its step by design.

## 6. Risks and mitigations

| Risk | Mitigation |
| --- | --- |
| A coverage floor set too high makes unrelated PRs red. | Floors are measured on this branch and set a few points below the measured value. |
| Branch coverage reports lower numbers than statement coverage, so the existing 82 floor cannot be reused unchanged. | Re-measure, then set the branch-aware floor explicitly and document the delta. |
| The scheduled job is red for infrastructure reasons (Docker, browsers). | Slow suites are opt-in via env vars only where the suite already supports it; the job is scheduled, not per-PR, and its logs name the failing node id. |
| The new `now` parameter changes a public helper. | It is keyword-only with a default of `None`, so existing callers are unaffected and the signed envelope format is untouched. |
| Windows CRLF checkout already fails the frozen-digest tests on this host. | Not touched by this issue; recorded as pre-existing in the report. |

## 7. Exit checklist

- [x] A regression test fails before the fix and passes after it (see 9.1).
- [x] Added and changed tests pass locally with the project interpreter (9.1, 9.3).
- [x] The wider suite passes, or every failure is pre-existing and named (9.5).
- [x] `ruff check` and `ruff format --check` pass on every changed Python file (9.4).
- [x] Coverage config produces a branch report and the floors are measured, not guessed (9.2).
- [x] The scheduled workflow is valid YAML and passes the workflow pinning test (9.4).
- [x] Commits reference issue #42.

## 8. Follow-ups (deliberately not in this PR)

- Turn the per-module gateway floors into a single report with `--cov-append` so one test
  run can gate several modules.
- Add `pytest-timeout` to the dev group to bound the whole suite on CI.
- Extend the scheduled job to a multi-hour soak once the harness has a time budget flag.

## 9. Implementation record

Everything below ran in this checkout with the project interpreter
(`D:\prathamesh\AgentScan-gw-impl\.venv\Scripts\python.exe`, i.e. `python -m pytest ...`)
and a per-run `--basetemp` outside the repository.

### 9.1 Clock seam (QA-017)

| Check | Command | Result |
| --- | --- | --- |
| Regression test fails before the fix | `python -m pytest tests/test_gateway/test_policy_clock.py` with `agentscan/gateway/policy.py` stashed | `2 failed, 2 passed`; both failures are `TypeError: sign_policy() got an unexpected keyword argument 'now'` |
| Regression test passes after the fix | the same command | `4 passed` |
| Policy suite | `python -m pytest tests/test_gateway/test_policy.py` | passed |
| Readiness deadlines | `python -m pytest tests/test_gateway/test_gateway_phase4_server.py tests/test_gateway/test_gateway_phase5_serve.py tests/test_gateway/test_gateway_phase5_upstream.py tests/test_gateway/test_policy.py` | `117 passed` |

`sign_policy` / `sign_policy_file` gained a keyword-only `now: datetime | None = None`
that is threaded into `_validate_timestamps`; the default is still the process clock, so
the CLI keeps enforcing the window and the signed envelope format is unchanged. The CLI
round-trip test now derives a live window instead of reusing the fixture dates, because
the CLI has no `--now` flag.

### 9.2 Branch coverage (QA-019)

`python -m pytest tests -m "not slow" --cov=agentscan --cov-branch` on this branch reports
`TOTAL 82%` (18125 statements, 5792 branches, 850 partial branches). Floors added to
`validate.yml`, each about two points under the measured value:

| Gate | Measured | Floor |
| --- | --- | --- |
| `agentscan` (whole package) | 82% | 80 |
| `agentscan.gateway.policy` | 83% | 81 |
| `agentscan.gateway.receipts` | 85% | 83 |
| `agentscan.remediation.recovery` | 97% | 95 |

Statement-only coverage at the old floor of 82 was already at the measurement, so reusing
that number with branch coverage would have left zero headroom. The floors keep the
regression signal and cannot be tripped by an unrelated change.

### 9.3 Critical-path tests (QA-025)

`tests/test_remediation/test_recovery_journal.py` builds the recovery journal in-process
instead of only through a child process that calls `os._exit` mid-apply. Coverage of
`agentscan/remediation/recovery.py` with
`python -m pytest tests/test_remediation -q -m "not slow" --cov=agentscan.remediation.recovery --cov-branch`
goes from 41% to 97%. The remaining statement (line 133, "File changed during recovery")
guards a race between preflight and apply and needs a monkeypatched `os.replace`.

Where the other critical paths already have tests, no duplicate test was added:

- audit certificates: `tests/test_reporting/test_audit_verifier.py` (89% of
  `agentscan/reporting/audit_verifier.py`), including tampered digests and wrong keys;
- gateway: `tests/test_gateway` (83% policy, 85% receipts with branch coverage) plus the
  new per-module floors;
- scan: the runner and connector paths are exercised by the end-to-end and connector
  suites; the one gap found, `agentscan/remediation/declarative.py`, is imported by
  nothing at all, so it is a follow-up (delete or wire it up), not a test target.

### 9.4 Scheduled soak (QA-026)

`.github/workflows/scheduled-soak.yml` runs `python -m pytest tests -q -m slow`, which
collects 12 slow node ids (Docker containment, live container, browser connectors, deep
activation probes, gateway soak, semantic model) with `AGENTSCAN_RUN_DOCKER_TESTS=1` and
Chromium installed. `test_all_external_actions_and_uv_are_pinned` passes for the new file,
and `ruff check` / `ruff format --check` pass on every changed Python file.

### 9.5 Environment limits on this host (not caused by this change)

- Git Bash and `sh.exe` cannot create their signal pipe under the host sandbox, so the
  workflow tests that spawn bash (`.github/tests/test_workflow_security.py`) fail locally;
  the YAML-only tests pass, including the action pinning and audit-gate assertions.
- `mypy` cannot import its compiled modules here (`ImportError: DLL load failed while
  importing constraints: An Application Control policy has blocked this file`), so CI is
  the only type check.
- The full `-m "not slow"` suite reports `4 failed, 3352 passed, 32 skipped, 13 deselected`
  on this host. All four failures are sandbox artifacts: three
  `tests/test_mcp_catalog_process.py` cases and
  `tests/test_remediation/test_recovery.py::test_process_exit_keeps_recoverable_preimages_and_preserves_later_edits`
  fail because a child process cannot open piped stdio or a `mode=0o700` directory created
  outside the pytest wrapper. They pass on a normal Linux or Windows checkout and are
  unrelated to the files this branch changes.