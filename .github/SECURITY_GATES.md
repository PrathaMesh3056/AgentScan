# Action and release validation

The composite action passes inputs through environment variables to a quoted Bash argument array. It accepts only `audit` or `scan`, rejects empty positional inputs and unsupported severity values, and places paths/URLs after `--`. Spaces, dollar signs, quotes, newlines and option-looking paths remain literal arguments. Scanner failure exits the action with the same failure status. SARIF output has precedence when both output inputs are supplied; clear `sarif-output` when requesting only JSON.

CI and tag-triggered releases call the same local reusable validation workflow at the triggering revision. Python 3.12 and 3.13 both run pre-commit hooks, locked dependency installation, lint/format/type checks, the nonslow test suite with an 82% total coverage floor, action boundary regressions, a strict audit of hashed lock exports, a wheel/sdist build and clean artifact installation smoke checks. A Windows job verifies the frozen benchmark input digests, and a gitleaks scan blocks committed credentials on pull requests and main pushes. Any vulnerability, dependency collection error, audit tool failure, detected secret or coverage regression blocks that validation job. There is no unconditional fallback to success.

Release publishing requires the entire validation workflow to succeed. It downloads the Python 3.12 distribution artifact from its own workflow run and publishes those tested bytes, without a second build. Validation jobs have read-only repository access; publishing alone receives content-write and OIDC permissions and targets the `pypi` environment. External Actions are pinned to resolved upstream commit IDs; uv and pip-audit use explicit versions.

The artifact smoke script installs the core wheel, core sdist, and wheel with UI/API extras in separate environments outside the checkout. It verifies CLI startup, SARIF conversion and optional service imports. GPU, browser, commercial provider and production deployment profiles are not validated by this workflow. Dependency auditing covers the selected lock export, including validation dependencies; it does not certify every optional profile or exclude future vulnerabilities.

Repository administrators still need to configure protected tags, reviewers for the `pypi` environment, and the PyPI trusted-publisher identity. Source changes cannot configure those account settings. The active `main` ruleset requires pull requests, strict success of the four validation checks above, review-thread resolution, and squash-only merges, and it blocks deletion and non-fast-forward pushes. That ruleset is a repository setting, not a versioned file. Required human approval and CODEOWNERS remain open until a second collaborator exists. OIDC publishing and remote Actions runs have not been executed locally. The artifact pipeline does not yet generate independent SLSA provenance.

Local action checks:

```powershell
.\.venv\Scripts\python.exe -m pytest .github\tests -q
```

Bash is required; Windows checks use Git for Windows Bash when installed. The tests execute the action's actual Bash script with a harmless scanner stub, verify exact argument boundaries and failure statuses, and check required workflow gates. They make no provider or publishing calls.

Upstream references: [GitHub's secure-use guidance](https://docs.github.com/en/actions/reference/security/secure-use), [reusable workflow semantics](https://docs.github.com/en/actions/how-tos/reuse-automations/reuse-workflows), and [pip-audit options and exit policy](https://github.com/pypa/pip-audit#usage).
