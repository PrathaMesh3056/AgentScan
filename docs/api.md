# REST API and distributed scans

The optional service uses FastAPI for authentication and scan submission, Redis Streams for delivery, and PostgreSQL for durable scan state and report JSON. Install the `ui` and `api` extras for the service; a DEEP worker also needs the `deep` extras and a suitable model cache.

## Local quickstart (copy-paste)

This walkthrough runs the API on loopback against a synthetic fixture target. Every
key, password and credential below is disposable and local; never reuse them for a
deployed service. PostgreSQL 16 and Redis 6.2+ must be reachable before the API
starts.

### 1. Start PostgreSQL and Redis

```bash
export AGENTSCAN_POSTGRES_PASSWORD='local-fixture-password'
docker compose -f docker-compose.api.yml up -d redis postgres
```

The Compose file maps PostgreSQL to `127.0.0.1:5432` and Redis to
`127.0.0.1:6379`.

### 2. Create local keys, credentials and tenant policy

```bash
mkdir -p .agentscan-local
openssl genpkey -algorithm ED25519 -out .agentscan-local/agentscan-jwt.pem
python -c "from pathlib import Path; from cryptography.fernet import Fernet; Path('.agentscan-local/agentscan-data.key').write_bytes(Fernet.generate_key())"
```

```bash
cat > .agentscan-local/tenant-credentials.json <<'JSON'
{"tenant-a": "local-tenant-a-secret-0123456789abcdef"}
JSON
cat > .agentscan-local/tenant-policies.json <<'JSON'
{"tenant-a": {"origins": ["http://127.0.0.1:8010"], "networks": ["127.0.0.1/32"], "max_active_scans": 2, "submissions_per_hour": 10, "max_scan_seconds": 120, "max_target_requests": 50, "allow_local_model_analysis": false, "allow_external_model_analysis": false}}
JSON
```

The tenant secret must be at least 32 characters. The policy enrolls the
fixture origin and its loopback network; every target must also appear in
`AGENTSCAN_ALLOWED_TARGET_HOSTS`.

### 3. Export the configuration

```bash
export AGENTSCAN_DATABASE_URL='postgresql://agentscan:local-fixture-password@127.0.0.1:5432/agentscan'
export AGENTSCAN_REDIS_URL='redis://127.0.0.1:6379/0'
export AGENTSCAN_JWT_PRIVATE_KEY_FILE="$PWD/.agentscan-local/agentscan-jwt.pem"
export AGENTSCAN_DATA_KEY_FILE="$PWD/.agentscan-local/agentscan-data.key"
export AGENTSCAN_TENANT_CREDENTIALS_JSON="$(cat .agentscan-local/tenant-credentials.json)"
export AGENTSCAN_ALLOWED_TARGET_HOSTS='127.0.0.1'
export AGENTSCAN_TENANT_POLICIES_JSON="$(cat .agentscan-local/tenant-policies.json)"
```

Run these exports in every terminal that starts an API or worker process.

### 4. Start the synthetic fixture target

Save this file as `.agentscan-local/fixture_target.py`. It is a JSON echo
fixture, not an agent; scans against it verify transport and persistence only.

```python
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import sys


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        _ = self.rfile.read(length)
        body = json.dumps({"reply": "synthetic fixture acknowledgement"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


port = int(sys.argv[1]) if len(sys.argv) > 1 else 8010
ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
```

```bash
python .agentscan-local/fixture_target.py 8010
```

### 5. Start the API and one worker

In the first terminal:

```bash
agentscan api serve --host 127.0.0.1 --port 8081
```

In a second terminal, with the same exports:

```bash
agentscan api worker
```

`DEEP` scans additionally need `agentscan api worker --deep` and a configured
offline model; this walkthrough uses deterministic `SCAN` only.

### 6. Enroll, submit and inspect a scan

```bash
curl -s http://127.0.0.1:8081/health/ready
```

```bash
export TOKEN="$(curl -s -X POST http://127.0.0.1:8081/token \
  -H 'content-type: application/json' \
  -d '{"tenant_id": "tenant-a", "secret": "local-tenant-a-secret-0123456789abcdef"}' \
  | python -c 'import json, sys; print(json.load(sys.stdin)["access_token"])')"
```

```bash
export SCAN_ID="$(curl -s -X POST http://127.0.0.1:8081/scans \
  -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -H 'idempotency-key: quickstart-001' \
  -d '{"target_url": "http://127.0.0.1:8010/chat", "scan_mode": "SCAN", "analysis_mode": "deterministic", "data_classification": "sensitive", "timeout": 30, "concurrency": 5}' \
  | python -c 'import json, sys; print(json.load(sys.stdin)["scan_id"])')"
```

```bash
curl -s "http://127.0.0.1:8081/scans/$SCAN_ID" -H "authorization: Bearer $TOKEN"
curl -N "http://127.0.0.1:8081/scans/$SCAN_ID/stream" -H "authorization: Bearer $TOKEN"
```

The fixture answers every probe with a synthetic JSON body, so the result is
`inconclusive` rather than a security assessment. The walkthrough verifies
authentication, admission, queue delivery, persistence and streaming. Stop the
API and worker with `Ctrl+C` when finished.

## Service boundaries

See [ARCHITECTURE.md](ARCHITECTURE.md) for component structure and [SECURITY.md](SECURITY.md) for deployment trust boundaries. The original diagram sources are not shipped in this repository.

Enrollment is an operator action. The same credential cannot request another tenant's token. The service-wide host list is an outer admission boundary. Each tenant also needs exact permitted origins (scheme, hostname and port), private-network CIDRs and scan quotas. HTTP initial URLs and every redirect are checked. Service connections resolve once per connection and connect to an approved literal IP while retaining the original TLS/Host identity. Mixed public/private DNS answers are rejected unless every address is permitted. Link-local metadata destinations, multicast and reserved destinations remain blocked. Infrastructure egress enforcement and identity-provider federation remain deployment responsibilities.

Remote API jobs support `http://` and `https://` targets only. WebSocket, `mcp://stdio`, filesystem, browser and other connector schemes are rejected both when accepting a request and when executing a queued job. Trusted local CLI connector capabilities remain available independently. Remote WebSocket support requires redirect and network policy enforcement before it can be enabled.

## Configuration

There is no default signing key or default enrollment secret. API startup requires one configured Ed25519 PKCS8 PEM private key. All replicas and replacement processes must load the same key. Never commit a real key or enrollment credential.

| Variable | Purpose | Default |
|---|---|---|
| `AGENTSCAN_DATABASE_URL` | PostgreSQL connection URI | `postgresql://agentscan:agentscan@localhost:5432/agentscan` (local fixture convenience) |
| `AGENTSCAN_REDIS_URL` | Redis 6.2+ connection URI | `redis://localhost:6379/0` |
| `AGENTSCAN_JWT_PRIVATE_KEY_FILE` | Path to shared Ed25519 PEM key | Required unless inline key is used |
| `AGENTSCAN_JWT_PRIVATE_KEY` | Inline Ed25519 PEM key supplied by a secret manager | Required unless key file is used |
| `AGENTSCAN_TENANT_CREDENTIALS_JSON` | Object mapping enrolled tenant IDs to unique secrets of at least 32 characters | `{}` disables `/token` |
| `AGENTSCAN_ALLOWED_TARGET_HOSTS` | Comma-separated exact hostnames; enroll private/localhost targets explicitly | Required, no wildcard |
| `AGENTSCAN_TENANT_POLICIES_JSON` | Object mapping tenants to exact origins, private CIDRs and quotas | Required, no implicit tenant scope |
| `AGENTSCAN_DATA_KEY_FILE` | Shared persistent Fernet key file for queued requests | Required on API and workers |
| `AGENTSCAN_RETENTION_DAYS` | Terminal report/event retention | `7`, allowed 1–365 |
| `AGENTSCAN_LOCAL_MODEL` | Installed offline analysis model for permitted tenants | `ollama/llama3.2` |
| `AGENTSCAN_EXTERNAL_MODEL` | Explicit `openai/model`, `anthropic/model` or `gemini/model` for external-enabled tenants | Empty; required when external mode is selected |
| `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` / `GEMINI_API_KEY` | Selected provider credential, supplied through deployment environment/secret manager | No default; no service `.env` fallback |
| `AGENTSCAN_CORS_ORIGINS` | Explicit browser origin allowlist | Empty; cross-origin browser access disabled |
| `WORKER_ID` | Redis consumer identity | Hostname |
| `AGENTSCAN_DEEP_WORKER` | Consume only the DEEP stream | `false` |
| `AGENTSCAN_WORKER_LEASE_SECONDS` | Database execution lease and Redis idle-reclaim threshold | `60`, allowed 3–600 |
| `AGENTSCAN_WORKER_MAX_ATTEMPTS` | Maximum execution claims before a durable failed outcome | `3`, allowed 1–10 |

The former `AGENTSCAN_JWT_SECRET` and `AGENTSCAN_TOKEN_PSK` variables are intentionally unsupported. Existing tokens must be reissued because the configured key, audience and signing-key ID are required. JWTs require issuer, audience, subject, tenant, issue time, not-before and expiry; the algorithm is pinned to EdDSA. Current key rotation invalidates existing tokens; overlapping key rotation/JWKS is not implemented.

An operator can generate a local development signing key with:

```bash
openssl genpkey -algorithm ED25519 -out agentscan-jwt.pem
```

Store it outside version control. For the Compose stack, follow the required environment and key mounting configuration in `docker-compose.api.yml`. The API is available on its configured mapped port (the supplied local stack uses `http://localhost:8081`). PostgreSQL and Redis must be ready before API startup; dependency initialization failures prevent the API from serving.

## Token enrollment and HTTP endpoints

`POST /token` accepts `{"tenant_id":"tenant-a","secret":"<tenant-a enrollment credential>"}` and returns `access_token`, `token_type: "bearer"`, and `tenant_id`. It returns 404 when enrollment is disabled and 403 for an unknown tenant or mismatched credential. Use HTTPS for deployed enrollment. The service does not yet implement enrollment rate limiting or user roles.

All scan routes require `Authorization: Bearer <token>`.

| Endpoint | Behavior |
|---|---|
| `POST /scans` | Validate enrolled target, atomically persist encrypted request, queued metadata, delivery intent and initial event; optional tenant-scoped `Idempotency-Key`; return 202 with `scan_id`, current accepted `status`, and `stream_url` |
| `GET /scans?limit=20&offset=0` | List the authenticated tenant's scans; limit 1–100 and nonnegative offset |
| `GET /scans/{scan_id}` | Return metadata, UTC timestamps, nullable score, and redacted service report under `report` |
| `GET /scans/{scan_id}/stream` | Replay tenant-scoped PostgreSQL events using `Last-Event-ID`, then follow durable state |
| `POST /scans/{scan_id}/cancel` | Cancel active work, clear queued credentials and fence running attempts; 409 for terminal state |
| `DELETE /scans/{scan_id}` | Delete a terminal record; return 409 for queued/running scans, 404 for missing/other-tenant records |
| `GET /health/live` | Process liveness; does not require DB/Redis |
| `GET /health/ready` | Bounded DB and Redis checks; return 503 during a required dependency outage |

Example scan request:

```json
{
  "target_url": "https://agent.example.com/chat",
  "scan_mode": "SCAN",
  "analysis_mode": "deterministic",
  "data_classification": "sensitive",
  "timeout": 30,
  "concurrency": 10
}
```

Modes are `SCAN`, `EXPLOIT` and `DEEP`. DEEP requires a separately configured consumer: ordinary workers read only the high and normal streams. The supplied CPU Kubernetes deployment does not provision a GPU/DEEP worker automatically.

Optional `indirect_adapter: "document_v1"` enables ATK-005 only when the enrolled
HTTP target implements the [document ingestion/receipt contract](modules/indirect_injection.md).
Supply an operator-known synthetic `canary_token` already provisioned privately
on that target. Neither setting installs an adapter or a reference remotely.
The worker preserves this selection and the existing target/tenant egress policy.
Missing capability is unavailable; missing disclosure criteria or consumption
receipts are inconclusive. This module uses deterministic evidence without a judge.
Omitting the adapter, or sending `null`, preserves the previous canonical admission
request shape; opting in changes its identity for `Idempotency-Key` retries.

Optional `factuality_baseline` selects only ATK-009's [approved-answer policy
checks](modules/overreliance.md#approved-baseline). Use the same baseline JSON
object shown in that guide, with `target_url` exactly matching the enrolled scan
target, `scan_mode: "SCAN"`, deterministic analysis and no document adapter.
Expected answers are processed by AgentScan and omitted from target probe prompts;
questions and supplied wrong answers are sent to the target. The persisted job
configuration is encrypted. Reported policy deviations remain separate from
security findings and scores. An absent or null baseline preserves the previous
admission shape; a changed baseline changes the idempotency request identity.
Duplicate JSON keys and invalid fields are rejected without reflecting submitted
facts in validation responses.

### Retrying a submission

Clients that may retry `POST /scans` should generate a unique key for each intended scan and send it in the `Idempotency-Key` header. For example, `Idempotency-Key: scan-request-20261007-001`. Keep that key and the same request when retrying after a lost response or connection failure.

The header is optional. It must occur exactly once and contain 1–128 ASCII letters, digits, periods, underscores, tildes or hyphens. Empty, duplicate, whitespace-containing and oversized keys return **400** without persisting a submission. A reused key with a changed request returns **409**. The key is scoped to the authenticated tenant; another tenant's use of the same string is independent.

The canonical request includes every validated scan option, target headers and system prompt. JSON object order and omitted default values do not change its identity; URL spelling and actual option values do. A matching retry returns **202**, the original `scan_id`, its current persisted `status` (including terminal states) and the original stream URL. It does not create another job, progress event or outbox record, and does not consume another active/hourly quota slot. Replays still pass current authentication and tenant authorization checks; provider key availability is required only for a new external submission. A completed external scan remains inspectable through a matching retry when its provider key is unavailable.

Deduplication is stored in PostgreSQL in the same transaction as acceptance, under the tenant transaction lock used for quotas. Concurrent retries across API replicas therefore share one accepted scan. Upgrade every API replica before enabling keyed client retries; older replicas do not implement this header. The database retains domain-separated HMAC-SHA256 digests of the tenant/key and canonical request, rather than the raw key or an unkeyed hash of potentially low-entropy credentials. The HMAC secret derives from the required shared `AGENTSCAN_DATA_KEY_FILE`; all API replicas must use that same persistent file content. Keep this key stable while queued encrypted requests or idempotency bindings remain. Data-key rotation requires a coordinated retention/drain plan; replacing it independently also changes retry identity.

The binding lasts as long as its scan record. Completing, failing or cancelling a scan clears queued credentials while preserving its binding. Explicit deletion of a terminal scan, or terminal expiry under `AGENTSCAN_RETENTION_DAYS`, removes the binding with the scan. The key can then create a new scan, and normal quota checks apply. Active scans retain their bindings. This is a retention-bounded submission guarantee; clients should use fresh keys for new scans and should not deliberately recycle deleted keys.

Without the header, each accepted `POST /scans` remains a new submission. Submission deduplication does not make target interactions exactly once: worker recovery can repeat target requests after an execution crash.

Completed responses contain `report` as a JSON object and timestamps as ISO UTC strings. `score: null` and `status: "inconclusive"` indicate that sufficient evaluation evidence is unavailable; operational errors are not interpreted as a clean scan. Report statuses `COMPLETE`, `INCONCLUSIVE` and `ERROR` map to persisted states `completed`, `inconclusive` and `failed`.

SSE data frames contain JSON, for example `data: {"status":"completed","progress":100,"score":81}`, with a durable PostgreSQL event sequence in the `id` field. Keepalives are comment frames. Reconnect with `Last-Event-ID` to replay missed transitions; `GET /scans/{id}` also returns authoritative state. Optional Redis PubSub notification is independent of the durable event log.

## Delivery and failure behavior

See [ARCHITECTURE.md](ARCHITECTURE.md) for the submission and worker flow; the persisted states are the `ScanState` values in `agentscan/api/contracts.py`.

The worker leaves an entry pending when it cannot persist a terminal result, loses its lease or shuts down. A replacement consumer uses `XAUTOCLAIM` after the idle threshold. A database lease token fences stale owners from committing results. A terminal redelivery is acknowledged without rerunning the scan. Retry counters live in PostgreSQL; exhausted expired attempts become a durable failed result before ACK. Malformed deliveries without a valid persisted scan identity are quarantined with a bounded Redis receipt.

Delivery is **at least once**. A crash after target interaction but before result persistence can repeat target actions. Leases and result fencing do not provide exactly-once external effects. EXPLOIT operations therefore still need target-side idempotency or operator controls.

Submission commits the scan, its encrypted request, initial progress event, transactional outbox record and optional idempotency binding together. Redis relay failure still returns **202** after durable acceptance. API/worker reconciliation retries undelivered records and periodically redelivers stranded queued/expired work, including after Redis data loss. A crash after Redis acceptance may create duplicate deliveries; fenced leases and terminal-state checks prevent simultaneous ownership and terminal reruns. Client retries with a matching `Idempotency-Key` reuse the accepted scan within its retention window; use the returned scan ID to inspect acceptance.

Progress comes from a tenant-scoped PostgreSQL event log. `Last-Event-ID` must be a nonnegative signed-64-bit decimal sequence. Running and terminal transitions append an event in the same transaction as the state update. Stream reconnects replay events after the cursor and terminate after the authoritative terminal outcome. Redis PubSub remains an optional best-effort signal, independent of durable replay.

`XACK` and `XDEL` run together after durable terminal state. This service assumes one consumer group; do not add independent consumer groups and expect historical replay after entry deletion. Uncompleted/pending entries are retained. Dead-letter receipts are bounded at approximately 1000; archival, queue quotas and overload policy remain deployment work.

API schema setup includes additive lease columns and is not a versioned migration framework. Plan rolling deployment compatibility and migration ownership separately. SIGTERM/SIGINT cancels the current asynchronous job and closes the DB pool; the unacknowledged lease expires for recovery. It does not roll back effects already observed by the target.

## Regression verification

Run API unit and failure-state tests:

```bash
python -m pytest tests/api -q
```

Live integration tests require disposable, dedicated PostgreSQL and Redis services configured through `AGENTSCAN_TEST_DATABASE_URL` and `AGENTSCAN_TEST_REDIS_URL`. They reset scanner tables in the test database and scanner queue streams in the test Redis instance. Do not point them at production or shared queues.

The live suite verifies UTC/JSONB round trips, tenant isolation, stale-owner rejection, all three stream deliveries, pending reclamation, persistence-failure recovery, bounded retries, terminal redelivery, outbox repair, durable replay, cancellation, quotas and an actual SCAN run against a refusal-only localhost fixture. `tests/api/test_idempotency.py` additionally checks concurrent matching/conflicting submissions, tenant-key isolation, canonical defaults, encrypted requests, quota accounting, persistence across pool recreation, and deletion/retention of bindings against PostgreSQL. The dedicated database URL alone enables these idempotency cases; they do not require Redis because submission delivery is tested separately. The tests do not load `.env` or call commercial providers. Provider adapter tests use synthetic responses through mocked transports; they do not validate a real model/account.

To include real dependency stop/start checks, set `AGENTSCAN_TEST_POSTGRES_CONTAINER` and `AGENTSCAN_TEST_REDIS_CONTAINER` to the dedicated test containers. Their names must start with `agentscan-hardening-`. Bind explicit localhost ports when creating them: automatic Docker host-port allocation may change when a container restarts, invalidating the test connection URLs. The outage check verifies readiness becomes 503 while either dependency is down, liveness remains 200, and readiness returns to 200 after recovery.

## Tenant policy and sensitive data

Example administrator policy (the outer host list must include `agent.example.com`):

```json
{
  "tenant-a": {
    "origins": ["https://agent.example.com"],
    "networks": [],
    "max_active_scans": 5,
    "submissions_per_hour": 60,
    "max_scan_seconds": 600,
    "max_target_requests": 500,
    "allow_local_model_analysis": false,
    "allow_external_model_analysis": false
  }
}
```

Private targets require an explicit narrow CIDR as well as their origin. Quotas use per-tenant database transaction locks and durable hourly counters; deleting reports does not replenish the hourly allowance. Exceeding submission/active quotas returns 429. Execution has a total deadline and a request budget covering every HTTP hop. POST interactions are not automatically retried unless a trusted local operator explicitly opts into state-changing retries. Service response bodies are capped and compressed responses are rejected. HTTP request bodies are limited to 256 KiB and a 15-second receive deadline.

Analysis defaults to `analysis_mode: "deterministic"` and `data_classification: "sensitive"`. `"local"` requires tenant permission and an administrator-operated offline loopback model. `"external"` requires explicit client designation `data_classification: "non_sensitive"`, tenant permission and the administrator's provider/model/key configuration. Both submission and worker execution reject sensitive external analysis. Neither a configured key nor a permitted tenant changes these defaults, and availability failures never trigger an external fallback.

External analysis can send relevant objectives and target responses to the selected provider; classification is the client's decision. Keys and arbitrary provider URLs are never accepted in scan requests. Service keys are administrator-configured rather than per-tenant BYOK; a client can use its own key through a locally owned CLI/dashboard process. See [data policy](DATA_POLICY.md) for external setup, offline setup, encryption, redaction, retention and the three analysis paths.

Database encryption key and tenant policy settings are required in the Compose and Kubernetes templates. Existing rolling deployments need a coordinated schema/config rollout; these local checks do not establish deployed cluster isolation.
