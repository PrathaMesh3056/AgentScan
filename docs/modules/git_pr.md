# Remediation and GitHub pull requests

AgentScan can propose fixes for supported findings and optionally apply them
through a Git branch and GitHub pull request. Generated changes require review
and project-specific tests; publication does not establish that a fix is correct.

## Preview first

```powershell
agentscan fix ./owned-project --output fix-plan.json
```

Review the plan and diffs. Dynamic or ambiguous changes may need manual edits.
See the [starting guide](../START_HERE.md) for fix kinds and recovery behavior.

## Apply or publish

```powershell
agentscan fix ./owned-project --apply
agentscan fix ./owned-project --apply --pr
```

`--apply` writes proposed file changes. `--pr` additionally requests branch,
commit, push and pull-request work; use an authorized clean repository and
review the plan first. Git needs configured author identity. GitHub publication
requires the `gh` CLI and authentication for the intended repository.

When `gh` is unavailable, PR publication cannot complete; review the local
branch/commit and reported outcome. Automated GitLab and Bitbucket publication
are not supported. Interrupted application can leave private recovery receipts;
inspect those before retrying, and preserve subsequent editor changes.

This is an optional workflow. Ordinary scans and opening the dashboard do not
publish remediation changes.
