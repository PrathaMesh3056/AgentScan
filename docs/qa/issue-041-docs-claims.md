# Issue #41 — Documentation and claims (QA-086, QA-108, QA-120/121/122, QA-175)

Status: draft plan, committed before the documentation changes it describes.

## Problem

The documentation set makes claims and gives copy-paste instructions that do not
match the shipped code at `7c17743`:

- **QA-086 (API quickstart).** `docs/AgentScan_Manual.md` §3.13 shows
  `agentscan api serve --host 0.0.0.0 --port 8080` followed by a `/token` call
  authenticated with `dev-psk`, and documents `/token` as using
  `AGENTSCAN_TOKEN_PSK`. The shipped service accepts neither: `agentscan/api/auth.py`
  requires exactly one of `AGENTSCAN_JWT_PRIVATE_KEY_FILE` or
  `AGENTSCAN_JWT_PRIVATE_KEY`, and enrollment comes from
  `AGENTSCAN_TENANT_CREDENTIALS_JSON` with secrets of at least 32 characters.
  Startup also requires `AGENTSCAN_DATA_KEY_FILE`, `AGENTSCAN_ALLOWED_TARGET_HOSTS`
  and `AGENTSCAN_TENANT_POLICIES_JSON`. Copying the example therefore fails at the
  first request, and there is no end-to-end quickstart anywhere in the docs.
- **QA-108 (heal runbook).** The self-healing section of the manual starts
  `agentscan heal-server` without documenting `AGENTSCAN_HEAL_TOKEN` or
  `AGENTSCAN_HEAL_ROOT`. `agentscan/remediation/webhook_receiver.py` returns 503
  when either is missing, so the documented command cannot heal anything. The
  opt-in `AGENTSCAN_HEAL_ALLOW_APPLY=1` gate is also undocumented.
- **QA-120/121/122 (stale gateway copy).** The dashboard still says the gateway
  starts "in Phase 5" and that `/readyz` fails closed "until Phase 5 wires the
  runtime"; `docs/dashboard_feature_matrix.md` repeats "wired as of Phase 5".
  The gateway ships today as the `agentscan-gateway` console script
  (`serve`/`reconcile`/`policy`), with `python -m agentscan.gateway` as the
  documented fallback. The runbook also says the unimplemented `verify`
  subcommand "exits with a usage error"; it actually exits 1 with
  `error: verify is not available yet`.
- **QA-175 (claims beyond evidence).** The manual calls an HMAC-signed report a
  "certified audit report" and calls the optional API "production-grade ... capable
  of managing thousands of concurrent scans". Nothing in the repository verifies a
  certification or a production deployment; `docs/RELEASE_READINESS.md` explicitly
  limits the API evidence to host-Python tests.

## Reproduction (before the fix)

1. `agentscan api serve --host 0.0.0.0 --port 8080` in a clean shell: the process
   starts but `/token` and `/scans` reject every request because no signing key,
   data key, tenant credentials or tenant policy are configured. The documented
   `dev-psk` request fails: the secret is shorter than 32 characters and
   `AGENTSCAN_TOKEN_PSK` is intentionally unsupported.
2. `agentscan heal-server --host 127.0.0.1 --port 8766`, then
   `POST /webhook/alert` without a bearer token and root: 503
   `Webhook token and project root are not configured`.
3. Open the dashboard Runtime Gateway tab with no `AGENTSCAN_GATEWAY_URL`: the
   helper text says the `serve` command arrives in Phase 5, although
   `agentscan-gateway serve --help` is available in the same build.
4. `Select-String -Path docs/AgentScan_Manual.md -Pattern 'certified audit report'`
   matches the §3.12 verify instructions.

## Scope

In scope (documentation, copy and tests only):

1. `docs/api.md`: add a copy-paste local quickstart — dependency startup, key and
   credential files, the exact environment exports, a synthetic loopback fixture
   target, `agentscan api serve`/`worker`, token issuance, scan submission and
   status retrieval. Fix the broken `../internal_docs/...` links that do not exist
   in the repository.
2. `docs/AgentScan_Manual.md` §3.11: document every heal-server variable
   (`AGENTSCAN_HEAL_TOKEN`, `AGENTSCAN_HEAL_ROOT`, `AGENTSCAN_HEAL_ALLOW_APPLY`)
   and the fail-closed behavior.
3. `docs/AgentScan_Manual.md` §3.12/§3.13: replace the unrunnable API example and
   the `AGENTSCAN_TOKEN_PSK` reference with the configured flow; qualify the
   certification and production/scale claims to what the repository verifies.
4. `agentscan/ui/static/dashboard-app-core.js` and
   `docs/dashboard_feature_matrix.md`: state the shipped `agentscan-gateway serve`
   command and the real `/readyz` behavior instead of the Phase 5 placeholder.
5. `docs/RUNTIME_GATEWAY_RUNBOOK.md`: correct the `verify` subcommand wording.
6. `tests/test_docs_qa041.py`: copy-paste documentation tests (below).

Out of scope:

- `docs/RUNTIME_GATEWAY.md` is **frozen** by the issue constraints and is not
  edited. It still says `Status: Approved for v1 implementation — not implemented`,
  which is stale. This is recorded as a blocked item below and must be corrected
  by the owner of the frozen spec.
- No changes to `agentscan/core/`, `agentscan/action/` or
  `agentscan/reporting/audit_verifier.py`; no dashboard status/label logic beyond
  the two stale user-facing strings; no P1 issue work.
- No new support claims, no new API features, no formatting churn.

## Implementation plan

| Item | Change | Regression test |
| --- | --- | --- |
| QA-086 | Quickstart section in `docs/api.md`; manual §3.13 points at it and uses the configured flow | Fenced-block extraction: every documented `agentscan api` command/flag exists in the shipped CLI; every exported variable is read by `agentscan/api/*.py`; every relative link resolves; the documented fixture snippet is executed and probed |
| QA-108 | Required-variable table plus failure behavior in the heal section | The documented heal variables equal the set the webhook receiver reads, and the table marks all three as required/opt-in |
| QA-120/121/122 | Dashboard/feature-matrix copy uses `agentscan-gateway serve --config gateway.toml`; runbook `verify` wording | No "Phase 5" gateway placeholder remains in the dashboard copy or feature matrix; the referenced console script exists in `pyproject.toml` |
| QA-175 | Qualified certification/compliance and scale wording | Forbidden unqualified phrases are absent; the required qualification text is present |

## Test plan

`tests/test_docs_qa041.py` runs offline with synthetic fixtures and loopback only:

- extract fenced `bash`/`python` blocks by marker and assert the documented
  commands, flags, endpoints, environment variables and relative links exist in
  the shipped code;
- run the documented fixture-target snippet on an ephemeral loopback port and
  assert it answers a synthetic JSON request;
- assert heal documentation and code agree on the required variable set;
- assert stale Phase 5 copy and unqualified claims are gone.

Commands used for verification:

```powershell
$env:PYTHONDONTWRITEBYTECODE='1'
& 'D:\prathamesh\AgentScan-gw-impl\.venv\Scripts\python.exe' -m pytest tests/test_docs_qa041.py -q -p no:cacheprovider
& 'D:\prathamesh\AgentScan-gw-impl\.venv\Scripts\python.exe' -m ruff check docs tests/test_docs_qa041.py
& 'D:\prathamesh\AgentScan-gw-impl\.venv\Scripts\python.exe' -m ruff format --check tests/test_docs_qa041.py
```

Evidence discipline: the tests prove document/code agreement. They do not prove
that a deployment is certified, compliant or production-ready, and the docs must
not imply otherwise.

## Risks and mitigations

- **Frozen spec drift.** The stale status line in `docs/RUNTIME_GATEWAY.md`
  remains. Mitigation: record it here and in the PR body as blocked; do not
  silently diverge from the spec and do not edit the frozen file.
- **Environment-dependent quickstart.** The quickstart needs PostgreSQL and Redis.
  Mitigation: keep the Compose file as the dependency source, state prerequisites
  explicitly, and keep tests static/loopback so CI does not require services.
- **Over-qualifying claims.** Removing "certified" could under-sell the shipped
  HMAC tamper-evidence. Mitigation: state exactly what is verified (signing and
  verification of the report bytes) and qualify what is not (certification,
  external attestation, production readiness).
- **Copy churn in shared files.** The dashboard copy is a single JS string; the
  change avoids the status/label logic owned by QA-035/QA-036.

## Blocked / follow-up

1. `docs/RUNTIME_GATEWAY.md:3` still reads `— not implemented`; the gateway ships.
   The file is frozen, so this needs the spec owner to update the status line
   (and §19 implementation-decision wording if it still says otherwise).
2. The frozen spec's `verify` subcommand description must be reconciled with the
   shipped CLI once the spec owner unfreezes it.
