# Runtime Gateway Operations Runbook

**Applies to:** `agentscan-gateway` v1 (Phase 6 implementation)
**Companion spec:** [RUNTIME_GATEWAY.md](RUNTIME_GATEWAY.md). The spec is the
approved design; if this runbook and the spec disagree, the spec wins and the
gateway must be treated as misconfigured until the difference is resolved.

This runbook covers one tenant, one receipt chain, one active writer, and one
upstream MCP server over streamable HTTP. It does not cover the CI scanner or
the dashboard.

---

## 1. Prerequisites

### Host

- Python 3.12 (the project requires `>=3.12`).
- The gateway extra: `uv sync --locked --extra gateway` (or
  `pip install 'agentscan[gateway]'`).
- A local filesystem receipt directory with working `fsync` and no network
  share. The gateway fsyncs the WAL and JSONL before returning from a durable
  append; a filesystem that lies about durability weakens the audit claim.
- A secret store or OS-protected environment for the upstream credential and
  the policy signing key. Never put either in the TOML file or the repository.
- TLS certificate and key files when `listen_host` is not loopback. The config
  validator refuses a non-loopback listener without both files.

The console script is `agentscan-gateway`. If a host blocks the generated
launcher, use `python -m agentscan.gateway` with the same arguments.

### Operator-supplied artifacts

| Artifact | Purpose |
| --- | --- |
| Gateway TOML | Validated `GatewaySettings` (section 2). |
| Signed policy bundle (YAML) | Locally loaded, Ed25519-signed allow/deny rules. |
| Active policy public key (PEM) | Verifies the bundle at startup. |
| Historical policy public keys | Retained to re-verify old bundles and attribute old receipts. |
| Identity trust keys (JSON) | Key IDs (`kid`) to Ed25519 public PEMs for caller JWTs. |
| Upstream credential | Held by the gateway, read from the named environment variable. |
| TLS certificate/key | Required for non-loopback listeners. |

Local development may use loopback HTTP and fake data. Production traffic must
use TLS; the gateway does not terminate or verify mTLS in v1 (`mtls_ca_file`
is accepted by config but unused).

---

## 2. Configuration reference

All fields live under `[gateway]`. Unknown fields are rejected. Path fields
(`receipt_dir`, `policy_bundle`, `policy_public_key`, `trust_keys`) must not
contain a `..` segment.

```toml
[gateway]
tenant = "tenant-demo"
gateway_id = "gw-1"
chain_id = "tenant-demo/gw-1"
writer_id = "gw-1-writer"
audience = "agentscan-gateway"
trusted_issuer = "https://issuer.internal.example"
listen_host = "0.0.0.0"
listen_port = 8443
upstream_url = "https://crm-mcp.internal.example/mcp"
upstream_server_id = "crm-mcp"
upstream_credential_env = "AGENTSCAN_GATEWAY_UPSTREAM_TOKEN"
policy_bundle = "/etc/agentscan/policy-bundle.yaml"
policy_public_key = "/etc/agentscan/policy-public.pem"
trust_keys = "/etc/agentscan/identity-trust-keys.json"
receipt_dir = "/var/lib/agentscan/receipts"
mode = "enforce"
tls_certfile = "/etc/agentscan/tls/server.crt"
tls_keyfile = "/etc/agentscan/tls/server.key"
allowed_hosts = ["gateway.internal.example:8443"]
allowed_origins = ["https://console.internal.example"]
```

### Required fields

| Field | Meaning | Constraints |
| --- | --- | --- |
| `tenant` | Tenant bound into sessions, policy, receipts, and upstream calls. | Non-empty, no `/`, `\`, or `..`. |
| `gateway_id` | Gateway identity in every receipt. | Non-empty. |
| `chain_id` | Receipt chain identifier. | Non-empty, `[A-Za-z0-9._/-]+`, no `..`. |
| `writer_id` | Single-writer identity recorded in every receipt. | Non-empty; must match the last writer on an existing chain. |
| `audience` | Required JWT audience. | Non-empty. |
| `trusted_issuer` | Required JWT issuer. | Non-empty. |
| `listen_host` | uvicorn bind address. | Non-loopback requires TLS cert and key. |
| `listen_port` | uvicorn port. | 1-65535. |
| `upstream_url` | Upstream MCP Streamable HTTP endpoint. | HTTP(S), no credentials, query, or fragment; plain HTTP only for loopback. |
| `upstream_server_id` | Server ID used in tool identity hashes and the catalog. | Non-empty. |
| `upstream_credential_env` | Environment variable holding the upstream bearer credential. | Non-empty; the value is read at startup, never logged. |
| `policy_bundle` | Signed bundle path. | No `..`. |
| `policy_public_key` | Active Ed25519 public PEM path. | No `..`. |
| `trust_keys` | JSON mapping of JWT key IDs to public PEMs. | No `..`. |
| `receipt_dir` | Receipt chain root. | No `..`. |

### Optional fields

| Field | Default | Meaning and constraints |
| --- | --- | --- |
| `retention_days` | `30` | Receipt retention and idempotency window. Positive integer; the dedupe window always equals it. |
| `session_idle_timeout_seconds` | `900` | Session idle expiry. Positive. |
| `session_max_lifetime_seconds` | `3600` | Session maximum lifetime. Must exceed the idle timeout. |
| `max_request_bytes` | `65536` | JSON-RPC request body cap. |
| `max_argument_bytes` | `8192` | Per-argument canonical byte cap. |
| `max_total_argument_bytes` | `32768` | Total canonical argument cap. Must satisfy argument <= total <= request. |
| `max_idempotency_key_bytes` | `256` | Raw idempotency key length, 1-1024. |
| `upstream_timeout_seconds` | `5.0` | Per-call upstream deadline. Positive float. |
| `clock_skew_seconds` | `30` | JWT leeway, 0-300. |
| `deny_spike_threshold` | `10` | Alert threshold carried in config for external monitoring; the gateway does not evaluate it. |
| `deny_spike_window_seconds` | `60` | Window for the above; not evaluated by the gateway. |
| `pending_alert_seconds` | `60` | Pending-decision alert age; not evaluated by the gateway. |
| `mode` | `"enforce"` | `enforce` or `shadow`. Shadow forwards would-denies and records them. |
| `allowed_hosts` | `["127.0.0.1:8765", "localhost:8765"]` | Concrete `host:port` entries for MCP DNS-rebinding protection. Every entry must use `listen_port`; wildcards, schemes, and paths are rejected. |
| `allowed_origins` | `["http://127.0.0.1:8765"]` | Concrete HTTP(S) origins for MCP Origin checks. Non-empty, no wildcards. |
| `tls_certfile` | `""` | uvicorn TLS certificate. |
| `tls_keyfile` | `""` | uvicorn TLS private key. |
| `mtls_ca_file` | `""` | Accepted for forward compatibility; v1 does not implement mTLS. |

`enforcement` and `risk` are policy-bundle fields, not gateway settings. A
high-risk tool must use `enforcement: inline` and
`resource_tenant_enforced: upstream`; any other combination rejects the bundle.

### Receipt layout

For `receipt_dir=/var/lib/agentscan/receipts`, `tenant=tenant-demo`, and
`chain_id=tenant-demo/gw-1`, the writer creates:

```
/var/lib/agentscan/receipts/tenant-demo/
  tenant-demo__gw-1.jsonl    authoritative append-only chain
  tenant-demo__gw-1.wal      fsynced write-ahead log for crash replay
  tenant-demo__gw-1.epoch    monotonic writer epoch
  .tenant-demo__gw-1.lock    single-writer file lock
```

`/` in `chain_id` is replaced by `__` in the file name. Protect this directory:
it is the audit record, and manual edits break the hash chain.

---

## 3. Upstream credential environment variable

The gateway holds the real upstream credential. The agent never receives it,
and the gateway never forwards the agent's token upstream.

1. Choose a variable name, for example `AGENTSCAN_GATEWAY_UPSTREAM_TOKEN`, and
   set `upstream_credential_env` to exactly that name.
2. Inject the value from the secret store at process start (systemd
   `EnvironmentFile`, container secret, or the platform's secret manager). Do
   not write it in the TOML file.
3. `serve` and `reconcile` read it before loading the bundle. If it is unset or
   empty, startup fails with:

   ```text
   error: missing upstream credential environment variable: AGENTSCAN_GATEWAY_UPSTREAM_TOKEN
   ```

4. The gateway sends it as `Authorization: Bearer <value>` plus
   `X-AgentScan-Tenant: <tenant>`. The upstream must bind the credential to the
   tenant and must not accept agent tokens.
5. Rotate the upstream credential by updating the secret, restarting the
   gateway, and revoking the old value only after `/readyz` is 200 again.

Example local development only:

```bash
export AGENTSCAN_GATEWAY_UPSTREAM_TOKEN='fake-development-token'
python -m agentscan.gateway serve --config gateway.toml
```

---

## 4. Policy signing and verification

### Generate a key pair

```bash
openssl genpkey -algorithm ed25519 -out policy-private.pem
openssl pkey -in policy-private.pem -pubout -out policy-public.pem
```

Keep `policy-private.pem` offline or in the security owner's secret store. Only
the public key is deployed with the gateway.

### Minimal policy document (unsigned)

```yaml
version: 1
policy_id: prod-crm-2026-11-13
tenant: tenant-demo
default: deny
tools:
  delete_customer_record:
    server: crm-mcp
    risk: high
    enforcement: inline
    resource_tenant_enforced: upstream
    schema_hash: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
    status_operation: check_effect
    rules:
      - id: allow-support-delete-own-tenant
        principal_role: support_operator
        tenant_match: true
        arguments:
          customer_id:
            pattern: "^cust-[0-9]{4}$"
        decision: allow
      - id: deny-intern
        principal_role: intern
        decision: deny
      - id: require-approval-for-bulk
        arguments:
          customer_id:
            pattern: "^bulk-"
        decision: require_approval
```

Allowed tool fields are `server`, `risk`, `enforcement`,
`resource_tenant_enforced`, `schema_hash`, `status_operation`, and `rules`.
Allowed rule fields are `id`, `principal_role`, `tenant_match`, `arguments`,
and `decision`. Unknown fields, duplicate YAML keys, anchors/aliases, invalid
regexes, and duplicate rule IDs reject the bundle. `default` must be `deny`.

`schema_hash` must equal the discovered tool's canonical `inputSchema` hash. To
compute it from a saved schema JSON:

```bash
python -c "import json; from agentscan.gateway.catalog import tool_schema_hash; \
print(tool_schema_hash(json.load(open('delete_customer_record.inputSchema.json'))))"
```

`status_operation` is required for reconciliation; without it the `reconcile`
command refuses to run.

### Sign and verify

```bash
agentscan-gateway policy sign \
  --policy policy.yaml \
  --private-key policy-private.pem \
  --bundle-id prod-crm-2026-11-13 \
  --tenant tenant-demo \
  --issued-at 2026-11-13T00:00:00Z \
  --expires-at 2027-11-13T00:00:00Z \
  --out policy-bundle.yaml

agentscan-gateway policy verify \
  --bundle policy-bundle.yaml \
  --public-key policy-public.pem
```

Successful sign output: `signed bundle: policy-bundle.yaml`. Successful verify
prints two lines:

```text
policy_hash=sha256:<64 lowercase hex>
key_id=ed25519:<64 lowercase hex>
```

Record both values in the change record. The envelope format is
`agentscan-policy-bundle/v1`; timestamps are UTC ISO-8601, `expires_at` must be
later than `issued_at`, and an expired bundle is rejected. Signature
verification happens before any policy structure or regex is compiled.

**Do not hand-edit a signed bundle.** Any change invalidates the signature.
Sign a new bundle instead.

---

## 5. Startup, shutdown, and serve behavior

### Start

```bash
python -m agentscan.gateway serve --config /etc/agentscan/gateway.toml
```

`serve` performs, in order:

1. Load and validate the TOML (`GatewaySettings`, unknown fields rejected).
2. Read the upstream credential from `upstream_credential_env`.
3. Verify the signed bundle with the active public key. Failure exits 1.
4. Open the receipt store and acquire the single-writer lease. Failure exits 1.
5. Run startup recovery: verify the chain, pair decisions and outcomes, and
   close every pending decision as `unknown` with a
   `startup_recovery`/`outcome_not_recorded` note. Failure exits 1.
6. Connect to the upstream MCP server, initialize the pinned protocol session,
   and load the tool catalog. Failure exits 1.
7. Start the session pruner and uvicorn on `listen_host:listen_port`.

The process serves only after every step succeeds; readiness is fail-closed.
Typical bounded startup errors (stderr, exit 1):

| Cause | Message |
| --- | --- |
| Missing credential | `error: missing upstream credential environment variable: <NAME>` |
| Expired bundle | `error: policy bundle has expired` |
| Wrong key or signature | `error: policy key ID does not match the active public key` or `error: policy bundle signature verification failed` |
| Another writer | `error: another writer holds this receipt chain` |
| Different writer on an existing chain | `error: writer handoff requires an authenticated handoff record` |
| Upstream unreachable | `error: upstream unavailable` |
| Upstream initialized too slowly | `error: upstream request timed out` |

### Shutdown

Send `SIGINT` (Ctrl+C) or `SIGTERM` and let uvicorn drain in-flight requests.
The lifecycle then cancels the session pruner, closes the upstream session, and
releases the writer lease. Do not `SIGKILL` a gateway that is processing
high-risk calls: a kill between the effect and the outcome append is recovered
as `unknown` on the next start, never as success.

After a hard kill, the next start replays the WAL, completes any partial JSONL
line from its durable WAL record, and verifies the chain before serving.

### Concurrency and scale

v1 is one process and one writer per `(tenant, chain_id)`. uvicorn concurrency
serves multiple MCP requests, but there is no active-active writer and no
horizontal scale-out for the same chain. Scale by adding chains/tenants, not by
starting a second writer on the same chain.

---

## 6. Health, readiness, metrics, and alerts

All three endpoints are unauthenticated and must be restricted by network
policy. They are not a substitute for MCP identity checks.

| Endpoint | Success | Failure |
| --- | --- | --- |
| `GET /healthz` | `200 {"status":"ok"}` | No response means the process is down. |
| `GET /readyz` | `200 {"status":"ready"}` | `503 {"status":"not_ready","agentscan_code":"GATEWAY_UNAVAILABLE","reason":"<code>"}` |
| `GET /metrics` | Prometheus text, `text/plain; version=0.0.4` | Same. |

`/healthz` is liveness only. A process can be alive and not ready.

### Readiness reason codes

`/readyz` returns the first failing check, in this order:

1. `policy_missing` - loaded policy tenant does not match `tenant`.
2. `policy_expired` - the bundle's `expires_at` has passed. Replace the bundle
   and restart; v1 does not hot-reload and continues serving until you do.
3. `chain_invalid` - the on-disk chain no longer matches the in-memory head or
   fails verification.
4. `writer_lease_missing` - the process does not hold the chain lease.
5. `receipt_sink_unhealthy` - a durable append failed or the sink was marked
   failed; calls return `GATEWAY_UNAVAILABLE` until restart.
6. `catalog_unavailable` - no upstream tool catalog has been loaded.

`/readyz` re-reads and verifies the JSONL chain on every probe. Probe at a
sensible interval (for example 10-30 s), not in a tight loop.

### Metrics

Counters (`agentscan_gateway_<name>_total`, labels `tool`, `decision`, `reason`):

`decisions`, `chain_verification_failures`, `pending_decisions`,
`unknown_outcomes`, `identity_mismatches`, `writer_conflicts`,
`upstream_errors`, `upstream_timeouts`, `auth_failures`, `approval_required`,
`protocol_failures`.

Summaries with `quantile="0.5"`, `quantile="0.99"`, `_count`, and `_sum`:
`agentscan_gateway_policy_latency_seconds` and
`agentscan_gateway_receipt_append_latency_seconds`. Samples are bounded to the
most recent 2048 observations and reset on restart.

v1 increments `decisions`, `unknown_outcomes`, `identity_mismatches`,
`upstream_errors`, `upstream_timeouts`, `auth_failures`, `approval_required`,
and `protocol_failures`. `chain_verification_failures`, `pending_decisions`,
and `writer_conflicts` are declared but not incremented; use `/readyz` and
receipt inspection for those conditions.

### Alert conditions

| Condition | Signal | Operator action |
| --- | --- | --- |
| Deny spike | `rate(agentscan_gateway_decisions_total{decision="deny"}[5m])` above `deny_spike_threshold` per `deny_spike_window_seconds` | Section 13.1. |
| Chain break | `/readyz` reason `chain_invalid`; startup recovery failure | Section 13.2. |
| Pending decision too old | Decision receipts without a paired outcome older than `pending_alert_seconds` | Section 13.3. |
| Unknown outcome | `increase(agentscan_gateway_unknown_outcomes_total[15m]) > 0` | Section 13.3. |
| Schema drift | Deny receipts with `reason="schema_drift"`; `decisions_total{decision="deny"}` rise after an upstream deploy | Section 9. |
| Policy expired | `/readyz` reason `policy_expired` | Rotate the bundle and restart. |
| Writer conflict | Startup error `another writer holds this receipt chain`; multi-instance deploy | Section 7. |
| Gateway unhealthy | `/healthz` fails or `/readyz` 503 | Section 13.4/13.5. |
| Direct upstream connection attempt | Egress/network telemetry, not the gateway | Block and investigate; v1 does not observe bypass attempts. |

The threshold fields in config are carried for the monitoring system; the
gateway itself raises no alerts.

---

## 7. Writer lease, standby, failover, and chain ownership

- The lease is the `.<chain>.lock` file in the tenant receipt directory. It is
  held for the life of the serving process and released on clean shutdown.
- A second process configured for the same `(tenant, chain_id)` exits at
  startup with `another writer holds this receipt chain`. It does not queue and
  it does not become an active standby.
- v1 standby is **cold**: run the standby with the same config, but start it
  only after the primary has stopped and released the lease.
- Each acquisition increments `writer_epoch` and writes it to `.epoch`. Every
  receipt records `writer_epoch` and `writer_id`.
- Continuing an existing chain requires the same `writer_id` as the last
  receipt. A different `writer_id` is rejected with
  `writer handoff requires an authenticated handoff record`. v1 has no CLI to
  create that handoff receipt. To change writer identity, start a new
  `chain_id` and record the cutover in the change log; do not edit the chain.
- Two writers must never be started against one chain. The file lock is the
  enforcement; do not delete or unlock the file while a gateway is running.
- Backups, restores, and reconciliation all require the lease, so stop the
  gateway before running them.

---

## 8. Startup recovery and the reconcile command

### What startup recovery does

On every start, after acquiring the lease, the gateway:

1. Verifies the JSONL chain from genesis against the in-memory cache.
2. Pairs every decision with its outcome; an unpaired decision is `pending`.
3. Appends one `unknown` outcome for each pending decision, with the note
   `{"source":"startup_recovery","reason":"outcome_not_recorded",...}`.
4. Rebuilds the idempotency index from the durable receipts.
5. Aborts startup if pairing, appending, or re-verification fails.

Recovery never queries the upstream and never retries a destructive call.

### Inspect pending or unknown decisions

With the gateway stopped:

```bash
python -c "from agentscan.gateway.receipts import verify_jsonl_file; \
from agentscan.gateway.idempotency import pair_receipts; \
v = verify_jsonl_file(r'/var/lib/agentscan/receipts/tenant-demo/tenant-demo__gw-1.jsonl'); \
print('chain', v.head_hash, len(v.receipts)); \
[print(p.decision.idempotency_key, p.state, p.decision.trace_id) \
 for p in pair_receipts(v.receipts) if p.state in ('pending', 'unknown')]"
```

### Reconcile one decision

Only when the upstream exposes an authenticated `status_operation` (configured
in the policy) and only after the gateway has stopped:

```bash
agentscan-gateway reconcile \
  --config /etc/agentscan/gateway.toml \
  --idempotency-key '<the raw key the client used>'
```

Add `--request-hash sha256:<64 hex>` when the same key could match more than
one stored decision. The CLI hashes the raw key, loads the bundle, acquires the
lease, queries the upstream status operation with the gateway credential, and
applies one explicit confirmation.

| Output status | Meaning | Retry behavior |
| --- | --- | --- |
| `NO_EFFECT_RECORDED` | Upstream confirmed no effect; `no_effect` appended. | Terminal for the key; a new key may be used. |
| `ALREADY_NO_EFFECT` | The key was already reconciled. | No new receipt; same key returns `no_effect`. |
| `APPLIED` | Upstream reports the effect applied; pending decisions get an `unknown` outcome because no response hash exists. | Same key returns `OUTCOME_UNKNOWN`; do not retry with a new key. |
| `UNKNOWN` | Upstream cannot confirm either way; state stays `unknown`. | Same key returns `OUTCOME_UNKNOWN`; same-content/new-key calls are denied. |

`reconcile` prints `reconciliation=<STATUS> receipt=<hash|none>` and exits 1 on
error. Common bounded errors:

- `tool has no authenticated status operation`
- `idempotency key does not identify exactly one stored decision`
- `confirmation key hash does not match the supplied key`
- `another writer holds this receipt chain` (gateway still running)

Never retry a destructive call with the same key unless its recorded outcome is
`no_effect`. A new key is not proof of new intent while a decision is pending or
unknown.

---

## 9. Schema-drift response

The catalog is loaded at startup and refreshed on every `tools/list`. A
`tools/call` uses the latest successfully loaded snapshot.

1. If a tool's `inputSchema` no longer matches the policy's `schema_hash`, the
   call is denied with `SCHEMA_DRIFT`, a denied decision receipt with
   `reason="schema_drift"` is appended, and the tool is removed from
   `tools/list`. A policy rule naming an argument absent from the schema is
   also denied as schema drift (`rule_argument_missing`).
2. Readiness is not changed by drift; the gateway stays ready while denying the
   changed tool.
3. Treat an unexpected drift as a possible upstream compromise: compare the
   upstream schema with the reviewed snapshot, identify the change owner, and
   check for shadow-server or tool-poisoning activity.
4. To approve a change, compute the new `schema_hash`, update the policy, sign a
   new bundle, deploy the bundle and public key together, then restart the
   gateway. v1 has no hot reload and no dynamic approval path.
5. Do not silence drift by deleting rules, lowering `risk`, or switching the
   tool to `observe`.

If the upstream catalog is unreachable at startup, the process exits rather
than serving without a catalog.

---

## 10. Manual key rotation

### Policy signing key

v1 trusts one active policy public key. Historical public keys are retained for
audit verification, not for live trust.

1. Generate a new Ed25519 key pair (section 4) in the security owner's store.
2. Sign the current policy with the new key and a new `bundle_id`.
3. Verify the new bundle with the new public key; record `policy_hash` and
   `key_id`.
4. Stop the gateway. Replace `policy_bundle` and `policy_public_key` together;
   a mismatched pair fails startup.
5. Retain the old bundle and old public key in the audit archive. Receipts
   record `policy_hash` and `policy_key_id`, so they can be attributed to the
   bundle that was active.
6. Start the gateway and require `/readyz` 200.
7. Re-verify an archived bundle with its retained public key when auditing:

   ```bash
   agentscan-gateway policy verify --bundle archive/old-bundle.yaml \
     --public-key archive/old-public.pem
   ```

Emergency rotation after key compromise: stop the gateway, rotate the upstream
credential, sign with a new policy key, replace both policy files, restart,
verify, and preserve the old key material and receipts for investigation.

### Identity trust keys

`trust_keys` is JSON: `{"keys": {"<kid>": "<public PEM>"}}`. Multiple keys are
allowed, which is how identity keys rotate without dropping valid tokens.

1. Add the new public key under a new `kid` in the trust JSON.
2. Deploy the file and restart the gateway (trust keys are loaded at startup).
3. Issue caller tokens with the new `kid`; old tokens continue to verify.
4. Remove the old key after the maximum token lifetime plus
   `clock_skew_seconds` has passed, then restart and verify.

Trust files must not contain private keys; the loader rejects them.

---

## 11. Receipt retention, backup, and restore

### Retention

- `retention_days` (default 30) is the logical retention and idempotency
  window. The dedupe window always equals it.
- The retention index excludes expired entries from idempotency lookups, but
  v1 does **not** delete or compact JSONL/WAL files. Disk usage grows with every
  decision. Monitor disk and archive/rotate files only under the procedure
  below; deleting receipts weakens audit and idempotency.
- Receipts are redacted arguments plus canonical hashes; they do not contain
  credentials or full PII.

### Backup

1. Stop the gateway cleanly and confirm the lease is released.
2. Copy the entire tenant chain directory (`*.jsonl`, `*.wal`, `*.epoch`, and
   the lock file) plus the policy bundle, active and historical public keys,
   trust keys, and gateway TOML.
3. Verify the copied chain with the offline command below before storing it.
4. Store backups with the same confidentiality as audit logs.

A live copy can capture a partial trailing line. If you must copy without
stopping, take a filesystem snapshot rather than a file-by-file copy, and
verify the copy before relying on it.

### Offline verification

```bash
python -c "from agentscan.gateway.receipts import verify_jsonl_file; \
v = verify_jsonl_file(r'/backup/tenant-demo/tenant-demo__gw-1.jsonl'); \
print(len(v.receipts), v.head_hash)"
```

A `ReceiptChainError` means the file is corrupt, truncated, reordered, or
edited. Preserve it and investigate; do not serve from it.

### Restore

1. Stop the gateway.
2. Restore the chain directory into `receipt_dir`, preserving file names.
3. Keep the configured `writer_id` equal to the last receipt's `writer_id`.
4. Keep the matching policy bundle and public key available.
5. Start the gateway. Startup recovery replays the WAL, completes a partial
   final line from the durable WAL record, verifies from genesis, and closes
   pending decisions as `unknown`.
6. Require `/readyz` 200 before sending traffic.

Restoring an older chain discards receipts written after that backup. Export
the newer receipts first and record the gap as an audit exception.

Never hand-edit `.jsonl`, `.wal`, or `.epoch`; a rewrite breaks the chain and
the writer epoch.

---

## 12. Upgrade and rollback

### Upgrade

1. Read the release notes and confirm the receipt format and config schema are
   unchanged or have a documented migration.
2. Stop the gateway and back up the chain (section 11).
3. Install the new locked dependencies: `uv sync --locked --extra gateway`.
4. Run `agentscan-gateway policy verify` with the deployed bundle and key.
5. Start the gateway, require `/readyz` 200, and send a canary call with a new
   idempotency key.
6. Watch deny/error counters and `/metrics` latency for one window before
   restoring full traffic.

### Rollback

1. Stop the gateway.
2. Reinstall the previous code and the matching policy bundle/public key pair.
3. Start and require `/readyz` 200.
4. Do not restore an old receipt chain over receipts written by the newer
   version. Receipts are append-only; the previous version must verify the
   existing `agentscan-receipt/v1` chain.
5. If the previous version cannot verify the current chain, keep the newer
   gateway serving and escalate; do not start a second writer.

v1 has no database or on-disk schema migrations.

---

## 13. Incident playbooks

### 13.1 Deny spike

**Symptoms:** `decisions_total{decision="deny"}` rises; callers report policy
or identity errors.

**Confirm:**

```bash
curl -s http://127.0.0.1:8765/metrics | grep agentscan_gateway_decisions_total
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8765/readyz
```

Group denials by receipt `authorization.reason`: `explicit_deny`,
`default_deny`, `approval_required`, `resource_tenant_unverified`,
`idempotency_required`, `schema_drift`, `token_scope`.

**Act:**

- `explicit_deny`/`default_deny`: confirm the caller role, tenant, and arguments
  against the signed bundle. If the policy is wrong, sign and deploy a new
  bundle; do not disable enforcement.
- `idempotency_required`: the client must send
  `params._meta["agentscan.idempotency_key"]` for high-risk tools.
- `resource_tenant_unverified`: the policy is missing
  `resource_tenant_enforced: upstream`; fix the bundle, not the gateway.
- Identity reasons (`identity_mismatch`, `auth_failures`,
  `unsupported_protocol_version`): check token issuer, audience, tenant, expiry,
  and the pinned `MCP-Protocol-Version: 2025-11-25` header.

**Do not:** switch `mode = "shadow"`, delete deny rules, or restart with an
unsigned bundle to stop the noise.

### 13.2 Chain break

**Symptoms:** `/readyz` 503 `chain_invalid`; startup recovery exits 1; offline
verification raises `ReceiptChainError`.

**Act:**

1. Stop the gateway. Preserve the chain directory and take a copy before any
   repair attempt.
2. Check disk health, free space, and whether another process wrote the chain.
3. Restore from the last verified backup if the loss is acceptable; otherwise
   start a new `chain_id` and record the cutover as an audit exception.
4. Never delete the chain to "fix" readiness. Never start a second writer.
5. Escalate a suspected compromise; v1 has no external anchor and cannot prove
   the absence of a full local rewrite.

### 13.3 Pending or unknown outcome

**Symptoms:** a decision receipt has no outcome, or `result.status="unknown"`;
retries return `OUTCOME_UNKNOWN` (409).

**Act:**

1. Stop the gateway if it is running; this is required for reconciliation.
2. Find the key with the inspection one-liner in section 8.
3. Run `reconcile` with the raw key. Record the printed status and receipt hash.
4. If the result is `NO_EFFECT_RECORDED`, the client may retry with a **new**
   key. If it is `APPLIED` or `UNKNOWN`, do not retry; escalate to the tool
   owner and reconcile manually against the upstream system of record.
5. Never manufacture a `no_effect` confirmation. The CLI only records what the
   authenticated upstream reports.

### 13.4 Receipt sink failure

**Symptoms:** calls return 503 `GATEWAY_UNAVAILABLE`; `/readyz`
`receipt_sink_unhealthy`; logs show a bounded durable-append error.

**Act:**

1. Stop sending high-risk traffic; the gateway already fails closed.
2. Check disk space, directory permissions, file locks, and filesystem
   durability. Do not delete WAL or JSONL files.
3. Restart after fixing the cause. Startup recovery verifies the chain and
   closes pending decisions as `unknown`.
4. Reconcile any pending decisions that matter (section 8).
5. If the outcome append failed after an upstream success, the recorded state is
   `unknown`; do not assume the effect failed.

### 13.5 Upstream outage

**Symptoms:** calls return `UPSTREAM_ERROR`, `TIMEOUT`, or `OUTCOME_UNKNOWN`;
startup fails with `upstream unavailable`; schema drift may appear after
recovery.

**Act:**

1. Confirm the upstream health and credential independently of the gateway.
2. The gateway fails closed for high-risk tools; do not switch to shadow mode
   or bypass it.
3. Calls that timed out are recorded `timeout`; calls whose effect cannot be
   confirmed are `unknown`. Reconcile before retrying.
4. When the upstream returns, restart the gateway if startup had failed, then
   require `/readyz` 200 and verify the catalog has no unexpected drift.
5. v1 has no upstream circuit breaker; each call is bounded only by
   `upstream_timeout_seconds`.

---

## 14. v1 limitations

State these limits in any security or audit claim:

- **One writer.** One writer per `(tenant, chain_id)`; no active-active
  multi-writer chain. Standby is cold, and changing `writer_id` requires a new
  chain because there is no handoff CLI.
- **No external anchor.** The hash chain detects accidental corruption and
  partial local tampering. It does not prove integrity against a compromised
  gateway host. Do not claim "tamper-proof".
- **No approval workflow.** `require_approval` fails closed with
  `APPROVAL_REQUIRED`; no pause, approval UI, or timeout-to-deny exists.
- **TLS required in production.** Non-loopback listeners require certificate
  and key files. Loopback HTTP is for local development only. mTLS is not
  implemented.
- **No hot reload.** Policy bundles and trust keys load at startup; replacing
  them requires a restart.
- **One policy signing key.** Historical public keys are retained for audit,
  not live multi-key trust. Automated rotation is v1.1.
- **No upstream circuit breaker.** Failures are per call and bounded by the
  upstream timeout.
- **No physical receipt deletion.** Retention is a logical lookup window; JSONL
  files grow until an operator archives them under the backup procedure.
- **No built-in alerting or verifier worker.** Metrics and readiness are
  exposed; alerting, pending-decision aging, and async verification are
  external responsibilities. Several declared counters are not incremented.
- **No gateway-side resource-tenant lookup.** The upstream must enforce
  resource-to-tenant binding; high-risk tools without that declaration are
  denied.
- **No stdio, HTTP proxy, SDK wrapper, or `2026-07-28` stateless MCP mode.**
- **Detection, not prevention, for unrouted tools.** Tools that bypass the
  gateway are outside the enforcement claim, and v1 does not observe bypass
  attempts itself.

---

## 15. Command reference

Verified against `--help` for the Phase 6 build:

```text
agentscan-gateway [-h] [{serve,verify,policy,reconcile}]

agentscan-gateway serve --config CONFIG

agentscan-gateway reconcile --config CONFIG --idempotency-key IDEMPOTENCY_KEY
                            [--request-hash REQUEST_HASH]

agentscan-gateway policy sign --policy POLICY --private-key PRIVATE_KEY
                              --bundle-id BUNDLE_ID --tenant TENANT
                              --issued-at ISSUED_AT --expires-at EXPIRES_AT
                              --out OUT

agentscan-gateway policy verify --bundle BUNDLE --public-key PUBLIC_KEY
```

`verify` remains listed for forward compatibility but is not implemented; it
exits with a usage error. Use `policy verify` for bundles.
