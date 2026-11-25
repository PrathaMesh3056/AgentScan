# Issue #37 - Remediation and data handling (QA-057..QA-064, QA-103, QA-180)

Status: in progress. Branch `fix/qa-037-remediation-data`, base `origin/main` @ `7c17743`.
Owner: subagent for issue #37. Scope is deliberately bounded; this file is the written plan,
not a security approval.

## Problem

The remediation and data-handling paths are lossy or leaky in four independent ways.
Each item below is reproduced by a regression test that fails on `7c17743` and passes with
the fix.

| ID (theme) | Defect at `7c17743` | Operator impact |
|---|---|---|
| provenance map | `FixPlan` only stores a bare `finding_id` per action; neither the `--output` artifact nor the generated PR body shows which finding produced which change | Reviewer cannot audit an automated PR back to its source finding |
| operator-preserving bumps | `pin_bump` rewrites every matched specifier to `>=<fix>`, discarding `==`/`~=`/`<=` and inline environment markers' intent | Reviewers lose reproducibility (`==`) or receive a broken bound (`<=` promoted to a lower bound silently) |
| LF patches / relative paths | `git_pr._generate_unified_diff` and the `fix` CLI diff emit `a/<basename>` and pass CRLF bytes straight into the diff; `generate_pr_body`/`generate_github_pr_payload` print absolute host paths and basenames | Patches fail to apply for nested or same-named files, contain `\r`, and leak operator filesystem layout into PR bodies/artifacts |
| secret DOM/artifact retention | the certificate signing-key and canary-token inputs keep their values in the DOM after submission; `/api/sentinel/status` and the `sentinel:start` SSE artifact retain the raw synthetic canary token | A shoulder-surf, screenshot, extension, or log capture recovers a live signing key/canary reference from the dashboard or its status artifact |

## Reproduction

All fixtures are synthetic and loopback-only; no real credentials or external providers.

1. Provenance: run `agentscan fix <report.json> --output plan.json` on a report with one
   `SC-001` finding; `plan.json` has no key that maps the finding to its action, and
   `GitPRAutomator.generate_pr_body(plan)` has no provenance table.
2. Operators: `requirements.txt` containing `pkg~=1.2.0` plus an `SC-001` finding with
   `fix_version` `1.2.9` becomes `pkg>=1.2.9`; `pkg==1.2.0` becomes `pkg>=1.2.9`.
3. Patch text: a `FixAction` for `src/agent.py` with CRLF `before`/`after` yields a diff with
   `--- a/agent.py` and embedded `\r`; `generate_pr_body` prints the absolute
   `C:\\...\\src\\agent.py` path.
4. Secrets: load the dashboard and run certificate verification / start a scan with a
   synthetic canary: after `verifyCertAction()` the `#cert-secret-key` value is unchanged;
   `GET /api/sentinel/status` returns the raw `canary_token` string.

## Scope (implemented in this PR)

1. `agentscan/remediation/models.py`: `FixPlan.provenance_map()` returns one entry per
   finding - action positions, kinds, and repo-relative POSIX paths (derived from the bound
   root, so it never emits host paths).
2. `agentscan/remediation/git_pr.py`, `agentscan/remediation/patch_generator.py`,
   `agentscan/_cli/commands/misc.py`: a shared `patch_text` helper LF-normalizes diff input
   and resolves `a/`/`b/` paths relative to the repository root; the PR body, GitHub payload,
   `--output` artifact, and CLI diff all use those relative paths. `--output` embeds the
   provenance map.
3. `agentscan/remediation/pin_bump.py`: bumps the version while preserving the original
   operator (`==`, `~=`, `>=`) and any spacing/marker suffix. Upper bounds (`<`, `<=`) and
   `!=` are converted to `>=<fix>` because an upper bound cannot express the fix; that
   conversion is explicit and covered by a test.
4. `agentscan/ui/static/form-validation.js` + flows: `clearSecretFields()` clears the
   authored secret inputs (`signingKey`, `canary`) after their values are captured; the
   certificate flow no longer sends a duplicate `secret` alias; the canary input is cleared
   after scan launch. `agentscan/ui/routers/sentinel.py` stores only a `configured` marker in
   the status artifact, so `/api/sentinel/status` and the `sentinel:start` SSE payload no
   longer carry the raw token. The direct `/api/sentinel/start` and `/api/sentinel/probe`
   responses keep returning the generated token once, because the operator must plant it on
   the target; that response is not an artifact.

## Not in scope

- QA-107 (`RequestTemplateConnector` ignores `auth_header`): blocked - it requires
  `agentscan/core/connectors/http.py`, which is frozen pending explicit approval.
- `agentscan/core/`, `agentscan/action/`, `agentscan/reporting/audit_verifier.py`, and
  `docs/RUNTIME_GATEWAY.md` are not edited.
- QA-192/QA-193 (browser storage, CSP) and QA-069 (other PR paths) overlap #45/#49; this
  PR only takes the remediation/data-handling slice and leaves those issue scopes intact.
- Raw secret scanning of report artifacts (QA-055, P1 #24) is untouched.

## Test plan

Targeted suites (new and existing) with `-p no:cacheprovider` and an explicit basetemp:

- `tests/test_remediation/test_provenance_map.py` (new): map completeness, repo-relative
  paths, `--output` artifact contains `provenance`, PR body renders the table.
- `tests/test_remediation/test_pin_bump_operators.py` (new): `==`, `~=`, `>=`, spacing,
  marker retention, upper-bound conversion, pyproject variant.
- `tests/test_remediation/test_patch_paths.py` (new): CRLF diff normalization, nested and
  duplicate-basename paths, PR body/payload relative paths, CLI diff headers.
- `tests/test_remediation/test_secret_retention.py` (new): sentinel status/SSE never return
  the token; the DOM helper clears only secret fields (Node, as in the existing dashboard
  contract tests).
- Updated expectations: `tests/test_remediation/test_pin_bump.py`,
  `tests/test_remediation/test_cli_fix.py` (operator now preserved).
- Related existing suites: `tests/test_remediation/`, `tests/test_ui_form_validation.py`,
  `tests/test_ui.py`, `tests/test_ui_target_selection.py`.

Every new test was run against the pre-fix tree first and observed failing for the stated
reason, then against the fix.

## Risks

- Operator preservation changes committed pin output from `>=` to `==`/`~=`; a reviewer who
  expects `>=` must read the diff. Bumps only happen for findings that already carry a
  `fix_version`, and `agentscan fix` remains dry-run unless `--apply` is passed.
- Relative paths rely on the bound plan root; actions whose path is outside the root keep
  their original path and are still rejected by `contained_path` during apply.
- Clearing DOM fields removes operator convenience (re-typing the key for a second verify);
  this is the intended trade-off for a secret field.
- Sentinel status now exposes `canary_token: "configured"` instead of the raw reference.
  Anything that depended on the raw value from status must use the start/probe response.
- Merge order with #35/#45/#49: #35 also edits `agentscan/ui/routers/sentinel.py` around
  `/api/sentinel/status`; this PR does not touch that function's return line, so the hunks
  are adjacent but independent.

## Acceptance

- [x] Pickup comment posted on #37.
- [x] Written plan committed before implementation.
- [ ] Regression tests fail before / pass after for items 1-4.
- [ ] Targeted + related suites pass; Ruff check and format check clean.
- [ ] Implementation commit pushed; draft PR marked ready for review. No merge.
