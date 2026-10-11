# Swarm execution budget

Swarm runs limit rounds and estimated prompt/response tokens. They can stop early
when execution evidence or an independently provisioned protected-canary
disclosure confirms the declared outcome. Ordinary candidate findings alone do
not establish a confirmed exploit.

## Start a bounded run

```powershell
agentscan swarm http://127.0.0.1:8000/chat --offline --rounds 2 --output swarm-report.json
```

Use an authorized target. `--offline` disables model generation, **not target
network requests**. See the [starting guide](../START_HERE.md) for local-model
selection and external-provider privacy requirements.

## Interpret the budget

The report's `budget_summary` records rounds used, estimated tokens consumed and
the stopping reason. Possible reasons include reaching the round limit, reaching
the token ceiling or observing a confirmed outcome. Protected canaries must be
provisioned independently and excluded from attack prompts.

Token accounting estimates usage from text; it is not a provider billing ledger
or a strict model-token quota. Active turns are not preemptively interrupted when
the ceiling is crossed. Additional rounds or turns are stopped when the budget
is checked. A stopped run may have incomplete assessment coverage.
