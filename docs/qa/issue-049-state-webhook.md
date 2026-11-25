# Issue #49 — State and webhook edge cases (QA-065, QA-068, QA-069, QA-117, QA-178)

- **Base:** `origin/main` @ `7c17743`
- **Branch:** `fix/qa-049-state-webhook`
- **Issue:** [#49](https://github.com/PrathaMesh3056/AgentScan/issues/49)
- **Priority:** P3

## Context

The QA review at `7c17743` recorded five state/webhook edge cases: no-op guardrail
plans, unvalidated webhook findings, absolute paths in generated PR bodies, a
misleading reconciliation summary for a successful reconcile, and dashboard gateway
copy that still describes the `serve` command as future work. Each item below has a
reproduction, a contained fix, and a regression test that must fail before the change
and pass after it.

Hard constraints carried from the issue and the task brief:

- Only `agentscan/core/`, `agentscan/action/`, `agentscan/reporting/audit_verifier.py`
  and `docs/RUNTIME_GATEWAY.md` are frozen; none of them are touched.
- Do not repeat the scan-state, provenance, or docs work owned by #36, #37, #39 and
  #41. No P1 issues (#20-#34) and no #43/#45/#46/#47/#48 work.
- Synthetic temporary fixtures and loopback targets only; no credentials, customer
  data, or external providers.
- No broad refactor or formatting churn. Each diff is limited to the affected module
  and its tests.

## 1. Skip no-op guardrails (QA-065)

**Where:** `agentscan/remediation/guardrails.py`

**Current behavior:** `plan_guardrails()` appends a `FixAction` for
`guardrails/agent_guardrails.co` and `guardrails/system_prompt_guard.md` for every
`ATK-*` finding, regardless of the current file contents. When the generated text is
already on disk, the plan still contains an action whose `before == after`. Running
`agentscan fix --apply` then rewrites identical bytes and reports an applied
remediation; `agentscan fix` prints `(New file to be created)` for an existing,
unchanged file because the diff is empty.

**Fix:** build each proposed action from the current contents and only append it when
the generated content actually differs. A plan is then empty when every guardrail file
already matches, so the CLI correctly reports `No remediations needed or applicable.`
Generic prompt-injection rules remain intentional defense-in-depth for findings without
an ATK-specific template; they are still skipped when the file already contains them.

**Regression tests** (`tests/test_remediation/test_guardrails.py`):

- A second `plan_guardrails()` run after writing both generated files returns no
  actions.
- When only one file already matches, only the other action is planned.

## 2. Validate webhook findings (QA-068)

**Where:** `agentscan/remediation/webhook_receiver.py`

**Current behavior:** `_parse_findings()` catches every exception from
`Finding.model_validate()` and falls back to a hand-built `Finding`: an unknown
severity silently becomes `HIGH`, a missing attack ID silently becomes `SC-011`, and
an arbitrary `metadata` value is passed into the model. `finding_ids` are turned into
findings without validation, so a malformed ID raises an unhandled validation error
(500) instead of a bounded client error. A remote alert therefore controls finding
identity/severity that later drive remediation planning and generated PR text.

**Fix:** validate alert input at the boundary:

- Keep strict `Finding` validation for full finding objects.
- For alert-shaped dictionaries, require `attack_id` (or `id`) to match the Finding
  pattern (`ATK-`/`SC-`/`ID-`), require a recognized severity when one is supplied
  (case-insensitive), require `owasp_id` to be `LLMnn`/`UNMAPPED`, and require
  `metadata` to be an object.
- Validate every `finding_ids` entry against the same attack-ID pattern.
- Bound the number of findings accepted from one alert.
- Return HTTP 400 with a bounded field-level reason (no echoing of raw metadata) for
  invalid input; keep the existing 400 for an alert with no findings.

**Regression tests** (`tests/test_remediation/test_self_healing.py`):

- Unknown severity is rejected with 400 (and is not silently downgraded to `HIGH`).
- An invalid attack ID in `findings` or `finding_ids` is rejected with 400.
- Non-object `metadata` is rejected with 400.
- A valid alert-shaped item (lowercase severity, `id` alias) is still accepted.

## 3. Use relative PR paths (QA-069)

**Where:** `agentscan/remediation/git_pr.py`

**Current behavior:** `GitPRAutomator.generate_pr_body()` renders
`- **File Path**: <absolute filesystem path>` and `_generate_unified_diff()` uses only
the basename in `a/`/`b/` headers. A generated PR body exposes the operator's host
layout, and nested or same-named files cannot be distinguished.

**Fix:** resolve each action path relative to `self.repo_path` as a POSIX path and use
it for both the body field and the diff headers. Paths already relative are preserved;
absolute paths outside the repository fall back to the file name so the body still
never leaks a host path. This is deliberately limited to `git_pr.py`; #37's shared
`patch_text` helper (LF normalization + repo-relative artifact paths) is not on `main`,
so this branch does not duplicate it.

**Regression test** (`tests/test_remediation/test_git_pr.py`):

- A plan with an absolute nested path renders `src/agent.py` (and `a/src/agent.py` /
  `b/src/agent.py`) in the body and does not contain the temporary root.

## 4. Relabel the reconcile warning on success (QA-117)

**Where:** `agentscan/gateway/recovery.py`

**Current behavior:** when a pending decision is reconciled with an upstream
`applied` confirmation, the durable outcome summary is
`reconciled: upstream effect status is not confirmed absent`. The result status is the
successful `APPLIED`, but the recorded summary reads as a warning and hides the
confirmation that was actually received.

**Fix:** select the summary from the confirmation status for pending decisions:

- `applied` -> `reconciled: upstream confirmed the effect was applied`
- `unknown` -> `reconciled: upstream could not confirm the effect status` (explicit
  uncertainty is retained here only)

The outcome remains `unknown` (no response hash exists), the reconciliation note is
unchanged, and `no_effect` handling is unchanged.

**Regression test** (`tests/test_gateway/test_gateway_recovery.py`):

- The `applied` reconcile appends the positive summary and never the old negative
  warning; the `unknown` reconcile keeps the explicit uncertainty summary.

## 5. Align gateway copy with the shipped commands (QA-178)

**Where:** `agentscan/ui/static/dashboard-app-core.js`

**Current behavior:** the Runtime Gateway panel says `/readyz` "fails closed until
Phase 5 wires the runtime" and "The gateway serve command arrives in Phase 5." The
`agentscan-gateway serve --config ...` command has shipped, so the copy is stale.

**Fix:** describe the shipped command and current behavior: `/readyz` fails closed
when the runtime is not ready; start the gateway with
`agentscan-gateway serve --config gateway.toml` (or
`python -m agentscan.gateway serve --config gateway.toml`) and point
`AGENTSCAN_GATEWAY_URL` at the loopback base URL. The stale "Phase 5" wording is
removed. The panel remains read-only and makes no new gateway calls.

**Regression test** (`tests/test_ui_gateway_status.py`):

- The dashboard source contains the shipped `agentscan-gateway serve` command and no
  stale `Phase 5` gateway copy.

## Files to change

| File | Change |
| --- | --- |
| `agentscan/remediation/guardrails.py` | Skip actions whose content is unchanged |
| `agentscan/remediation/webhook_receiver.py` | Validate findings/finding_ids and return 400 |
| `agentscan/remediation/git_pr.py` | Repo-relative PR body and diff paths |
| `agentscan/gateway/recovery.py` | Correct reconciliation summaries |
| `agentscan/ui/static/dashboard-app-core.js` | Current shipped-command copy |
| `tests/test_remediation/test_guardrails.py` | No-op guardrail regressions |
| `tests/test_remediation/test_self_healing.py` | Webhook validation regressions |
| `tests/test_remediation/test_git_pr.py` | Relative PR path regression |
| `tests/test_gateway/test_gateway_recovery.py` | Reconcile summary regression |
| `tests/test_ui_gateway_status.py` | Gateway copy regression |
| `docs/qa/issue-049-state-webhook.md` | This plan |

## Verification plan

All Python commands use the shared virtualenv:

```text
D:\prathamesh\AgentScan-gw-impl\.venv\Scripts\python.exe
```

Targeted:

```text
tests/test_remediation/test_guardrails.py
tests/test_remediation/test_self_healing.py
tests/test_remediation/test_git_pr.py
tests/test_gateway/test_gateway_recovery.py
tests/test_ui_gateway_status.py
```

Then the related existing remediation/UI/gateway suites (`tests/test_remediation`,
`tests/test_gateway`, `tests/test_ui_gateway_status.py`), followed by Ruff check/format
on the changed Python and mypy on the changed Python. Report any environment-only
failure with the exact command and error.

## Risks and rollback

- **Webhook compatibility:** external SIEMs that previously sent invalid severities or
  IDs now receive 400. That is the intended hardening; valid full findings and the
  documented alert-shaped payload still work.
- **Guardrail plan size:** re-running `fix` against an already-patched repository now
  reports no actions instead of rewriting identical files. Roll back by reverting the
  module; no migration is involved.
- **Reconcile summaries:** only human-readable summaries change; receipt states,
  hashes, and reconciliation notes are untouched.
- **Overlap with #37:** `git_pr.py` is also touched by #37. This branch keeps the
  change local to display paths and does not add `patch_text.py`; rebase/resolve on
  whichever PR lands first.

## Out of scope

#36 scan state, #37 remediation provenance/LF patches, #39 dashboard workflow, #41 docs
claims, #43 error handling, #45 security headers, #46 CLI/UI polish, #47 docs
consistency, #48 CI hygiene, and all P1 issues #20-#34.
