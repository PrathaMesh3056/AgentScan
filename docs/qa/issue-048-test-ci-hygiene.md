# Issue #48 — Test and CI hygiene plan

- **Issue:** [#48](https://github.com/PrathaMesh3056/AgentScan/issues/48) (P3)
- **QA IDs:** QA-018, QA-022, QA-023, QA-027, QA-034, QA-035, QA-036
- **Branch:** `fix/qa-048-test-ci-hygiene`
- **Base:** `origin/main` at `7c17743`
- **Status:** implementation in progress; draft PR before code changes

## 1. Scope and constraints

This change is limited to test and CI hygiene. It does not change runtime behaviour, dependency pins, security gates, or the issues assigned to other agents.

In scope:

1. Remove the stale optional-provider skip.
2. Simplify the hashed dependency-audit command.
3. Replace broad gitleaks directory allowlists with exact, reviewable entries.
4. Modernise the pre-commit stage contract.
5. Enable additional mypy checks that pass on the current tree.
6. Add a focused set of high-signal Ruff security rules.
7. Include tests, documentation, and the lockfile in the source distribution.

Out of scope:

- P1 issues #20–#34 and their files.
- The `wcmatch` advisory itself; this issue records hygiene and does not change dependency pins.
- Error handling (#43), security headers (#45), CLI/UI polish (#46), documentation consistency (#47), or state/webhook work (#49).
- Any production provider call, real credential, or external target.
- Merge or force-push. The PR remains unmerged.

Protected paths not edited by this work:

- `agentscan/core/`
- `agentscan/action/`
- `agentscan/reporting/audit_verifier.py`
- `docs/RUNTIME_GATEWAY.md`

## 2. Baseline evidence

### QA-018 — vestigial `litellm` skip

`tests/test_ui.py::test_ui_calibration_and_benchmarking` starts with:

```python
pytest.importorskip("litellm")
```

Nothing in the test or the UI calibration path imports `litellm`; the dependency was removed when the optional `llm` extra became an intentional empty compatibility alias. Baseline result on this branch:

```text
$ python -m pytest tests/test_ui.py::test_ui_calibration_and_benchmarking -q -rs
s                                                                        [100%]
SKIPPED [1] tests\test_ui.py:248: could not import 'litellm': No module named 'litellm'
1 skipped in 0.21s
```

### QA-022 — audit command

The current gate exports a fully hashed, frozen requirements file and then passes redundant flags:

```text
--require-hashes --disable-pip --no-deps --desc on
```

`--require-hashes` already prevents resolution; `--disable-pip` and `--no-deps` restate that choice, while `--desc on` duplicates the default description behaviour for text output. The security-relevant contract is `--strict --require-hashes` plus the frozen export.

### QA-023 — gitleaks allowlists

Baseline with the repository config:

- Working tree (`gitleaks dir .`): 12 findings, all synthetic.
- Full history (`gitleaks git .`): 13 findings, all synthetic.

With only the default rules (`useDefault = true`):

- Working tree: 40 findings.
- Full history: 41 findings.

The gap is caused by whole-directory allowlists:

```toml
paths = [
  '''(^|/)tests/fixtures/''',
  '''(^|/)tests/test_attacks/''',
  '''(^|/)tests/test_e2e\.py$''',
]
```

These suppress every future credential-shaped value in those directories, not only the intentional fixtures. The replacement uses exact synthetic values, a line-scoped rule for blank `.env.example` placeholders, and the existing `gw-canary-signature` marker. CI keeps `fetch-depth: 0` and therefore scans full history.

### QA-027 — pre-commit stages

`.pre-commit-config.yaml` has no `minimum_pre_commit_version`, no explicit default stage, and pins `pre-commit-hooks` v4.6.0. That release still declares legacy stage names (`commit`, `push`, `manual`). The current major release uses `pre-commit`/`pre-push` and declares `minimum_pre_commit_version: 3.2.0`.

### QA-034 — typing

`[tool.mypy]` currently sets only `python_version`, `strict = false`, and `ignore_missing_imports = true`. The following additional checks pass on the current tree:

```text
--check-untyped-defs
--no-implicit-optional
--strict-equality
--warn-redundant-casts
```

They are enabled without turning on full `strict` mode or removing the third-party import escape hatch, so this remains a focused widening rather than a refactor.

### QA-035 — security linting

Ruff currently selects `E`, `F`, `I`, `UP`, `B`, and `SIM`. The full `S` set reports 65 findings on `agentscan`, mostly intentional `subprocess`, `assert`, and hardcoded-password patterns. A focused subset is selected instead:

```text
S113 (request without timeout), S301 (pickle), S307 (eval), S324 (insecure hash),
S501 (TLS verification disabled), S602 (shell=True), S608 (SQL construction),
S701 (Jinja autoescape), S704 (unsafe markup)
```

This subset currently has no runtime violations. The only hits are intentional insecure samples under `tests/fixtures/` and a synthetic SQL target under `benchmarks/`, which receive narrow per-file ignores.

### QA-036 — sdist sources

The current sdist includes only `agentscan/`, `rules/ai_rules.yaml`, `pyproject.toml`, `README.md`, `LICENSE`, and `CHANGELOG.md`. It omits the test suite, documentation, and `uv.lock`, so a source consumer cannot reproduce the validated environment or run the tests from the archive. The change adds those inputs while preserving the artifact checker's private-file exclusions.

## 3. Implementation detail

### 3.1 Optional provider (QA-018)

- Remove `pytest.importorskip("litellm")` from `tests/test_ui.py`.
- Add a comment stating that calibration uses the deterministic local judge and does not require a provider SDK.
- Leave `[project.optional-dependencies].llm = []` as the declared compatibility stub; no provider package is introduced.

### 3.2 Dependency audit (QA-022)

Replace the audit line with:

```bash
uvx --from pip-audit==2.10.1 pip-audit --strict --require-hashes --requirement "$RUNNER_TEMP/agentscan-audit-requirements.txt"
```

Keep the frozen export, `set -euo pipefail`, the pinned tool version, and the absence of `||`/`continue-on-error`.

### 3.3 Gitleaks (QA-023)

- Convert the legacy `[allowlist]` table to modern `[[allowlists]]`.
- Remove all broad test-directory and whole-file path allowlists.
- Allow only exact synthetic values already present in fixtures, plus the canary JWT suffix.
- Add a separate line-scoped allowlist for blank `OPENAI_API_KEY=`, `ANTHROPIC_API_KEY=`, and `GEMINI_API_KEY=` placeholders in `.env.example`.
- Add a config regression test that rejects broad test-directory allowlists and checks the full-history checkout.

The acceptance check is a clean scan of both the tracked working tree and the complete commit history, not merely a clean PR diff.

### 3.4 Pre-commit (QA-027)

- Set `minimum_pre_commit_version: "4.0.0"` (the lockfile installs 4.5.1).
- Set `default_stages: [pre-commit, manual]` so local `pre-commit run` and explicit manual runs behave the same.
- Update `pre-commit-hooks` from v4.6.0 to v6.0.0.
- Extend `.github/tests/test_commit_hooks.py` to assert the stage contract and hook-stage names.

### 3.5 Typing and security lint (QA-034, QA-035)

Add to `[tool.mypy]`:

```toml
check_untyped_defs = true
no_implicit_optional = true
strict_equality = true
warn_redundant_casts = true
```

Extend `[tool.ruff.lint].select` with the focused `S` subset and add only these per-file ignores:

- `tests/fixtures/**` for intentional vulnerable samples.
- `tests/api/test_idempotency.py` for its synthetic SQL identifier test.
- `benchmarks/evaluation/atk005_retrieval_target.py` for its synthetic SQL target.

### 3.6 Sdist (QA-036)

Add to `[tool.hatch.build.targets.sdist].include`:

```toml
"/tests/**",
"/docs/**",
"/uv.lock",
```

Update `.github/scripts/check_artifact_contents.py` so these are valid source-distribution inputs while `.env`, private keys, internal docs, and operational repair files remain rejected. Extend `.github/tests/test_artifact_contents.py` with positive and negative cases.

## 4. Verification plan

```powershell
# 1. Focused regressions
python -m pytest tests/test_ui.py::test_ui_calibration_and_benchmarking -q
python -m pytest .github/tests -q

# 2. Lint and types
python -m ruff check .
python -m ruff format --check .
python -m mypy agentscan

# 3. Secret scanning
gitleaks dir . --config .gitleaks.toml --redact --exit-code 1
gitleaks git . --config .gitleaks.toml --redact --exit-code 1

# 4. Packaging
uv build --no-sources
python .github/scripts/check_artifact_contents.py dist/*.whl dist/*.tar.gz
python -c "import tarfile; ..."  # assert tests/, docs/, uv.lock in sdist
```

Also run the broader non-slow suite where the environment allows it. Report any Windows Application Control or sandbox limitation separately from a repository failure.

## 5. Risks and rollback

- **Sdist growth and fixture exposure:** tests contain only synthetic credential-shaped values. The artifact checker continues to reject real private/operational filenames and suffixes. If size becomes a concern, the tests/docs lines can be reverted independently.
- **Gitleaks false negatives:** exact values could hide a future real secret that happens to equal a fixture. The values are distinctive and limited to known test canaries; broad paths are deliberately not restored.
- **Security-lint noise:** the chosen `S` subset has no runtime findings today. New findings should be fixed or narrowly suppressed with a justification, not by switching back to the full `S` set.
- **PR #53 conflict:** both branches touch `.github/workflows/validate.yml`. This branch changes one audit command line; resolve by taking the cleaned line and PR #53's coverage changes.

## 6. Completion criteria

- All seven QA items have code/config changes and focused tests.
- Gitleaks passes on working tree and full history with no broad directory allowlists.
- Ruff, formatting, and mypy pass on the changed tree.
- Wheel and sdist build, artifact checks pass, and the sdist contains tests, docs, and `uv.lock`.
- The plan is committed before implementation, the PR is opened as a draft, and it is marked ready only after checks pass.
- The PR is left unmerged.

## 7. Verification evidence

Recorded on `fix/qa-048-test-ci-hygiene` after the implementation commit:

```text
pytest tests/test_ui.py -q
10 passed

pytest tests/test_ui.py::test_ui_calibration_and_benchmarking \
  .github/tests/test_lint_config.py .github/tests/test_commit_hooks.py \
  .github/tests/test_artifact_contents.py -q
57 passed

pytest \
  .github/tests/test_workflow_security.py::test_audit_is_a_required_lock_export_gate \
  .github/tests/test_workflow_security.py::test_gitleaks_scans_full_history_without_broad_allowlists \
  .github/tests/test_workflow_security.py::test_all_external_actions_and_uv_are_pinned \
  .github/tests/test_workflow_security.py::test_release_uses_validation_artifact_without_rebuilding \
  .github/tests/test_workflow_security.py::test_github_expressions_are_not_embedded_in_shell_source \
  -q
5 passed

ruff check .
All checks passed!

ruff format --check .
456 files already formatted

mypy agentscan
Success: no issues found in 212 source files

gitleaks dir . --config .gitleaks.toml --redact --exit-code 1
gitleaks git . --config .gitleaks.toml --redact --exit-code 1
no leaks found (both scans)

pre-commit validate-config .pre-commit-config.yaml
exit 0

uv build --no-sources
built wheel and sdist

check_artifact_contents.py
wheel: 268 files, 13 required assets
sdist: 536 files, 16 required assets
top-level sdist entries include tests, docs, and uv.lock
```

The full `.github/tests` run on this Windows host also exercises Bash wrapper tests. Those fail here with `couldn't create signal pipe, Win32 error 5` from Git Bash, the same host-level Application Control limitation seen during cloning; the five non-Bash workflow assertions pass. CI remains authoritative for the Bash wrapper tests.

## 8. Local clone note

The requested clone command was attempted twice against the local source path and failed with the same host-level `couldn't create signal pipe, Win32 error 5` while Git started `git-upload-pack` through `sh.exe`. After that single retry, the equivalent repository was cloned directly from GitHub, the origin was set to `https://github.com/PrathaMesh3056/AgentScan.git`, and the branch was checked out from `origin/main` at `7c17743`. No other agent's clone was used or modified.
