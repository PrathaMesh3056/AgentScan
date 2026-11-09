# Runtime Gateway and MCP Integration

**Status:** Approved for v1 implementation — not implemented
**Date:** 2026-11-09  
**Related:** spike PR #12, `internal_docs/spike-action-verification/SPIKE_RESULT.md`, methodology §14  
**Scope:** production runtime enforcement, not the CI scanner

---

## 1. Summary

AgentScan's scanner answers a pre-deployment question: *can this agent be
tricked into an unauthorized call?* It does not answer the runtime question:
*is this call, in this chat, right now, authorized?*

The runtime gateway is an inline policy enforcement point (PEP) between the
agent and its tools. It makes a deterministic allow/deny decision **before** the
tool executes, emits a hash-chained `ActionReceipt` for every decision, and
forwards allowed calls to the real tool. A separate asynchronous verifier
consumes receipts for audit and alerting; it cannot undo an effect.

The spike (PR #12) demonstrated the reference behavior with a fake CRM tool:

- an authorized fake delete was allowed and changed fake customer state;
- an unauthorized delete was denied; fake customer-record state was unchanged,
  and the denial appended an audit event;
- ACT-001 produced a finding carrying that run's denial receipt hash;
- a direct call to the mock tool without the gateway's in-process capability
  raised `PermissionError`; this is not a network or credential-isolation test;
- the in-memory receipt chain verified per run. Receipt hashes include
  `trace_id` and `timestamp`, so they differ between runs; state hashes are
  reproducible.

These are spike results for a scripted, single-process fake tool. They are not
evidence of production MCP enforcement, durable audit, network bypass
prevention, or multi-tenant isolation.

This document turns that reference behavior into a production design for MCP
tools. It is deliberately narrow: one high-risk tool, one MCP server, one
tenant, then expand.

---

## 2. Goals

- Enforce per-call authorization before side effects for high-risk tools.
- Fail closed when identity, policy, or audit is unavailable for high-risk
  tools.
- Keep the hot path deterministic, local, and under 10 ms p99 policy latency,
  with the durable audit append separately budgeted.
- Emit a tamper-evident receipt for every allow, deny, error, and timeout.
- Support MCP first (streamable HTTP/SSE, then stdio), then HTTP proxy and SDK
  wrapper.
- Make bypass detectable and preventable through credential custody.
- Reuse the spike's `ActionReceipt` and hash-chain semantics.

## 3. Non-goals for v1

- No LLM, judge, or scanner in the request path.
- No full policy language, policy UI, or approval UI. The approval workflow is
  deferred to v1.1; v1 fails closed with `APPROVAL_REQUIRED`.
- No multi-region, Kubernetes, SSO, billing, or custom auth.
- No MCP stdio transport in v1. v1 supports streamable HTTP/SSE only.
- No active-active multi-writer receipt chain. One writer per chain; redundant
  gateways are standby.
- No gateway-side resource-to-tenant lookup in v1. The upstream tool must
  enforce resource-tenant binding; otherwise high-risk calls are denied.
- No enforcement for tools that cannot be routed through the gateway; those are
  receipt-only/observe, and the honest claim is detection, not prevention.
- No MCP protocol extensions beyond what is needed to identify the caller and
  tool.
- No claim of tamper-proof audit without an external anchor. See section 10.
- No replacement for the CI scanner.

---

## 4. Definitions

| Term | Meaning |
|---|---|
| **Principal** | The end user or service on whose behalf the agent acts. |
| **Agent** | The workload making the tool call. |
| **Tool identity** | `server_id` + `tool_name` + `schema_hash`, not a display name. |
| **PEP** | Policy enforcement point: the inline gateway that allows or denies. |
| **Receipt** | Immutable record of one decision and its outcome. |
| **Verifier** | Out-of-band consumer that recomputes chains and alerts. |
| **Policy bundle** | Signed, versioned, locally loaded allow/deny rules. |
| **High-risk tool** | Write, delete, send, money movement, privilege change, or data export. |

---

## 5. Architecture

```
User / Agent
    │
    ▼
MCP client ──► AgentScan Gateway (PEP) ──► MCP server ──► Tool
                    │
                    ├── allow / deny (require_approval: v1.1)
                    │   deterministic policy, no LLM, no network
                    │
                    └── ActionReceipt ──► append-only log
                                              │
                                              ▼
                                      async verifier ──► alerts / audit
```

Three components, one policy, one receipt schema:

| Component | When | Job | Latency |
|---|---|---|---|
| Scanner | CI / pre-deploy | Prove exploitability and policy coverage | Minutes |
| Gateway (PEP) | Production, inline | Allow or deny before the tool executes | < 10 ms |
| Verifier | Production, out-of-band | Detect, alert, audit; cannot undo | Seconds |

The gateway is the only component that can prevent damage. It must be small,
deterministic, and fast. The scanner and verifier must never sit in the request
path.

### Control plane and data plane

- **Control plane:** policy bundle authoring, signing, versioning, distribution.
- **Data plane:** receipt parsing, identity resolution, tool lookup, schema
  check, policy evaluation, upstream call, receipt append.

The gateway loads a signed policy bundle locally. It does not fetch policy over
the network on the hot path. If no valid bundle is loaded, high-risk tools are
denied.

---

## 6. Trust boundaries and threat model

| Threat | Mitigation |
|---|---|
| Prompt injection causes a destructive call | Policy checks principal, tool identity, and arguments, not the model's text. |
| Confused deputy | Bind principal + agent + delegation chain; no ambient authority. |
| Token passthrough | Gateway holds the real tool credential; the agent holds only a scoped gateway token. |
| Direct bypass to the upstream tool | Remove the direct network route; egress policy; credential custody; alert on direct connections. |
| Replay | Request ID/nonce, short expiry, idempotency key, duplicate rejection. |
| TOCTOU | Decision and execution in the same process; no re-resolution of the tool after the decision. |
| Tool or schema drift | Hash the MCP `inputSchema` at discovery; deny on drift until approved. |
| Tool poisoning / shadow server | Server allowlist; signed catalog; no dynamic tool registration without approval. |
| Log tampering | Hash chain, single-writer ownership, append-only storage, and separate writer credentials. v1 does not claim detection of a full local rewrite; v1.1 adds an off-host signed anchor. |
| Crash after effect, before outcome receipt | Persisted idempotency key, pending-decision reconciliation, no automatic retry of destructive calls. |
| Session identity change or reconnect | Session is bound at `initialize` to principal, agent, tenant, and delegation; every call is revalidated; mismatch denies and requires a new session. |
| Cross-tenant resource ID | Tool catalog must declare upstream resource-tenant enforcement; high-risk calls without that declaration are denied. |
| Gateway compromise | Least privilege per tool credential, rotation, process isolation, no shell. |
| Identity spoofing | Signed tokens, mTLS, audience and expiry checks, per-call session revalidation. |

The gateway must never trust the agent's self-report, its text response, or a
tool description supplied at call time.

---

## 7. Identity and credential model

### Identities

- **Principal:** end user or service. Carried in a signed token with `sub`,
  `aud`, `scope`, `exp`, and an actor/delegation claim.
- **Agent:** workload identity via mTLS certificate or signed workload JWT.
- **Gateway:** its own identity to the upstream MCP server.

### Delegation validation

- A delegated token must carry a signed chain from the principal to the acting
  agent. Each hop must be signed, audience-bound, and unexpired.
- The final subject must match the session principal; the delegation chain must
  match the tuple bound at `initialize`.
- Maximum chain depth is 3 in v1. A missing, broken, expired, or over-depth
  chain denies high-risk.
- The gateway never derives a role from an unsigned claim. `principal_role`
  must come from the signed token or the policy's principal mapping.

### Credential custody

- The gateway holds the real upstream credential (API key, OAuth token, mTLS
  cert, database credential).
- The agent holds a short-lived gateway token scoped to the gateway audience and
  the tools it may request. The gateway checks the tool scope on every
  `tools/call`; a token that does not name the requested tool is denied.
- The agent must not possess the upstream credential. If it does, the gateway is
  advisory, not enforcing.

### MCP HTTP / streamable HTTP

- v1 pins MCP `2025-11-25` in handshake mode. `initialize` may propose another
  version, but the gateway counter-offers `2025-11-25` and never negotiates a
  different version.
- Every request after `initialize` must carry the matching
  `MCP-Protocol-Version` header. A missing or different header denies
  `UNSUPPORTED_PROTOCOL_VERSION`.
- The 2026-07-28 stateless mode (`server/discover`, per-request `_meta`) is
  deferred to v1.1. v1 rejects a `server/discover` request with
  `UNSUPPORTED_PROTOCOL_VERSION`; it does not silently accept it.
- Every request carries a signed bearer token. Claims include principal, agent,
  tenant, scopes, and delegation chain.
- The gateway validates signature, audience, expiry, and tenant binding before
  policy evaluation.
- Missing or invalid identity: deny high-risk; `UNVERIFIED` in observe mode.

### Session binding and reconnect

- `initialize` requires a valid signed token. The gateway binds the session to
  the tuple `(principal, agent, tenant, delegation_chain)` and records the
  token expiry.
- Every later `tools/call` revalidates the presented token against the bound
  tuple. The token must be unexpired and addressed to the gateway audience.
- If the token changes principal, agent, tenant, or delegation, the gateway
  denies `IDENTITY_MISMATCH` and requires a new session. It must not silently
  rebind an existing session.
- Reconnect or SSE resumption creates a new session and re-authenticates.
  Session IDs are routing state, not bearer credentials.
- A session expires at the earliest of token expiry, idle timeout, or the
  configured maximum lifetime.

### MCP stdio

v1 does not support stdio. The following is deferred to v1.1:

- The gateway launches the upstream server and holds its environment secrets.
- The agent never receives the upstream environment.
- If one stdio session can serve multiple principals, require a session per
  principal or deny. A shared stdio session without per-request identity is
  `UNVERIFIED` at best.

---

## 8. MCP integration

The gateway is an MCP proxy: it speaks MCP to the agent and to the upstream
server. v1 supports streamable HTTP/SSE only. stdio is deferred to v1.1.

### Intercepted methods

| MCP method | Gateway behavior |
|---|---|
| `initialize` | Require a signed token; negotiate protocol; bind the session to `(principal, agent, tenant, delegation)`; record client info and token expiry; reject missing or invalid identity. |
| `tools/list` | Fetch upstream list; canonicalize; hash each `inputSchema`; apply visibility policy; return filtered list. |
| `tools/call` | Revalidate session identity, resolve tool identity, validate arguments, evaluate policy, allow or deny, forward if allowed, emit decision and outcome receipts. |
| `notifications/*` | Pass through; no policy decision. |
| `resources/*`, `prompts/*` | v1: pass through with audit; policy enforcement is tool-focused. |

### Tool identity

```
tool_identity = sha256(canonical_json({
  "server_id": "<configured server id>",
  "name": "<tool name>",
  "schema": <inputSchema>
}))
```

The display name and description are not identity. A schema change produces a
new identity and triggers drift handling.

### `tools/call` flow

1. Parse the JSON-RPC request; reject malformed or oversized payloads.
2. Resolve the session and revalidate the presented token against the bound
   `(principal, agent, tenant, delegation)` tuple. Deny `IDENTITY_MISMATCH` if
   it changed; reject missing or invalid identity for high-risk tools.
3. Look up the tool by name; verify the schema hash against the approved
   snapshot.
4. Canonicalize arguments: reject duplicate keys, NaN/Infinity, non-string keys,
   and oversize values; validate required fields and types.
5. Evaluate policy. Record `policy_id`, `rule_id`, `resource_tenant_enforced`,
   and the reason.
6. On deny: append a `decision` receipt with status `denied`, return a stable
   MCP error, and do not call upstream.
7. On allow: require a caller-supplied `idempotency_key` for high-risk calls.
   Do not derive it from `trace_id` or the JSON-RPC ID. Scope it to
   `(tenant, principal, tool_identity, idempotency_key)` and store the canonical
   `request_hash` with it to detect key reuse with different arguments. Append
   and fsync a `decision` receipt with status `pending` and the idempotency key.
   If the key is missing or the durable append fails, deny.
8. Call upstream with the gateway-held credential. Never forward the agent's
   token upstream.
9. Append an `outcome` receipt for success, error, timeout, or unknown; return
   the upstream result or `OUTCOME_UNKNOWN`. Reconciliation may append
   `no_effect` per section 10. Decision and outcome receipts share `trace_id`,
   `request_hash`, and `idempotency_key`.
10. On crash or restart with a `pending` decision and no outcome, follow the
    recovery rules in section 10. Do not auto-retry a destructive call.
11. On approval-required: v1 denies with `APPROVAL_REQUIRED`. The v1.1
    approval workflow pauses, creates an approval record, and times out to
    deny.

### Idempotency key

- For MCP, the key is `params._meta["agentscan.idempotency_key"]`. For the HTTP
  proxy, it is the `Idempotency-Key` header.
- The caller must reuse the key across retries, reconnects, JSON-RPC ID changes,
  and trace-ID changes.
- The gateway must not generate a fresh key from `trace_id`, the JSON-RPC ID, or
  wall-clock time.
- A missing key on a high-risk call returns `IDEMPOTENCY_REQUIRED` and the call
  does not execute.
- The key is scoped to `(tenant, principal, tool_identity, idempotency_key)`.
  The canonical `request_hash` is stored with it; reuse with a different hash
  returns `IDEMPOTENCY_CONFLICT`.

### Argument canonicalization

- JSON canonical form (sorted keys, no insignificant whitespace).
- Reject duplicate keys before parsing.
- Reject non-finite numbers.
- Enforce size limits per argument and total request.
- Hash canonical arguments for the receipt; store redacted values only.

### Error codes

| Code | Meaning |
|---|---|
| `POLICY_DENIED` | Policy returned deny. |
| `IDENTITY_MISSING` | No valid principal or agent identity. |
| `IDENTITY_MISMATCH` | The session's principal, agent, tenant, or delegation changed. |
| `UNSUPPORTED_PROTOCOL_VERSION` | The client requested or sent a protocol version other than the pinned v1 revision. |
| `SCHEMA_DRIFT` | Tool schema does not match the approved snapshot. |
| `RESOURCE_TENANT_UNVERIFIED` | The upstream did not declare resource-tenant enforcement. |
| `APPROVAL_REQUIRED` | Approval is required; v1 does not execute the call. |
| `IDEMPOTENCY_REQUIRED` | A high-risk call omitted the required idempotency key. |
| `IDEMPOTENCY_CONFLICT` | The idempotency key was reused with a different request. |
| `OUTCOME_UNKNOWN` | A prior effect could not be confirmed after a crash. |
| `UPSTREAM_ERROR` | Upstream MCP server returned an error. |
| `TIMEOUT` | Upstream call exceeded the deadline. |
| `GATEWAY_UNAVAILABLE` | Fail-closed path; no decision possible. |

Errors returned to the agent must not leak upstream credentials, internal
hostnames, or policy internals.

---

## 9. Policy model

### v1 bundle

YAML, signed, versioned, and loaded locally:

```yaml
version: 1
policy_id: prod-crm-2026-11-09
tenant: tenant-demo
default: deny

tools:
  delete_customer_record:
    server: crm-mcp
    risk: high
    enforcement: inline
    resource_tenant_enforced: upstream
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

`resource_tenant_enforced: upstream` is mandatory for every high-risk tool.
`require_approval` is parsed in v1 but fails closed with `APPROVAL_REQUIRED`;
the approval workflow is v1.1.

### Evaluation

Evaluation is ordered and fail-closed:

1. Explicit deny rules.
2. `require_approval` rules. v1 denies with `APPROVAL_REQUIRED`; v1.1 pauses
   for approval.
3. Allow rules.
4. Default deny.

Deny always overrides allow. If an allow rule and an approval rule both match,
approval wins. If a deny rule and an approval rule both match, deny wins. Within
one class, the first matching rule wins. A rule with an unknown field, an
invalid pattern, or an unparseable value is a configuration error and causes the
bundle to be rejected.

Every decision includes `policy_id`, `rule_id`, `resource_tenant_enforced`, and
a machine-readable reason.

### Resource-tenant authorization

`tenant_match: true` proves only that the principal belongs to the policy's
tenant. It does not prove that `customer_id` belongs to that tenant.

Every high-risk tool must declare exactly one of:

| Declaration | Meaning | v1 behavior |
|---|---|---|
| `resource_tenant_enforced: upstream` | The upstream MCP server verifies that the target resource belongs to the authenticated tenant. | Allowed only with a cross-tenant test. |
| `resource_tenant_enforced: gateway` | The gateway performs a declared resource lookup before allow. | Deferred to v1.1. |
| `resource_tenant_enforced: none` | No resource-tenant check exists. | High-risk calls are denied. |

A missing or `none` declaration for a high-risk tool is a deny. The gateway
records the declaration in the receipt. The upstream declaration is a trust
assumption: it must be covered by the server allowlist and a cross-tenant test.

### Policy lifecycle

- Bundles are signed (Ed25519) and hash-pinned.
- v1 verifies the signature against one active public key. A manual rotation
  runbook publishes the new key, switches signing, and retains historical public
  keys for audit verification. Automated rotation and live multi-key trust sets
  are v1.1.
- The gateway refuses unsigned, invalidly signed, expired, or tenant-mismatched
  bundles.
- Unknown fields, invalid patterns, and rule-precedence errors reject the
  bundle.
- Tool schema snapshots are part of the signed catalog or policy bundle. A
  schema change requires a new signed bundle; v1 has no dynamic approval UI.
  Until the new bundle is loaded, calls to the changed tool return
  `SCHEMA_DRIFT`.
- Hot reload is atomic. If a reload fails, keep the last known good bundle. If
  none is valid, deny high-risk tools.
- Policy changes are tested with table-driven unit tests and, later, the scanner.

### What policy is not

- It is not an LLM judge.
- It is not a free-form expression language in v1.
- It is not fetched from a remote service on the hot path.

---

## 10. Receipts and audit

### Schema

Reuse the spike's `ActionReceipt` and extend it for production:

```json
{
  "trace_id": "…",
  "phase": "outcome",
  "tenant_id": "tenant-demo",
  "gateway_id": "gw-1",
  "chain_id": "tenant-demo/gw-1",
  "writer_epoch": 7,
  "idempotency_key": "sha256:…",
  "principal": "user:123",
  "agent": "agent:support",
  "tool": {
    "name": "delete_customer_record",
    "server": "crm-mcp",
    "schema_hash": "sha256:…"
  },
  "arguments": {"customer_id": "cust-1001"},
  "authorization": {
    "decision": "allow",
    "policy_id": "prod-crm-2026-11-09",
    "rule_id": "allow-support-delete-own-tenant"
  },
  "result": {"status": "success", "summary": "deleted"},
  "evidence": {"hash": "sha256:…", "prev_hash": "sha256:…"},
  "timestamp": "2026-11-09T14:00:00Z",
  "request_hash": "sha256:…",
  "response_hash": "sha256:…",
  "decision_latency_ms": 1.8,
  "transport": "mcp-http",
  "mcp_request_id": "…",
  "approval_id": null
}
```

### Receipt states

- A `decision` receipt records `pending` for an allowed call or `denied` for a
  deny. A deny is terminal and has no outcome receipt.
- An `outcome` receipt records `success`, `error`, `timeout`, `unknown`, or
  `no_effect`.
- `unknown` means the effect could not be confirmed after a crash. It is not
  success, and it is not safe to retry automatically.
- `no_effect` means the upstream definitively confirmed that the original call
  did not take effect. It is terminal for that idempotency key and clears the
  pending/unknown guard for a new key.
- Production extends the spike's `ActionResult.status` literal with `pending`,
  `unknown`, and `no_effect`; the spike's literal remains unchanged.

### Chain and storage

- One chain per `(tenant, chain_id)`; fixed genesis.
- Canonical JSON + SHA-256; each receipt binds the previous hash.
- Append-only JSONL for v1; object storage for cold retention.
- Two-phase audit for high-risk tools: append and fsync a `decision` receipt
  before the tool effect, then append an `outcome` receipt after. A single
  receipt cannot both precede the effect and contain its result.
- If the decision receipt cannot be made durable, deny. If the outcome receipt
  cannot be written after an allowed call, append `unknown` if possible, alert,
  and fail closed for that tool until the sink recovers.
- Use a local write-ahead log with group commit to amortize fsync; the durable
  append budget is separate from policy-decision latency.

### Crash recovery and pending decisions

- Every high-risk call persists the caller-supplied idempotency key and the
  canonical `request_hash` in the `decision` receipt before dispatch. The key is
  never derived from `trace_id`, the JSON-RPC ID, or wall-clock time.
- On restart, a `decision` receipt with no matching `outcome` is `PENDING`.
- The gateway must not auto-retry a destructive call. It may query the upstream
  only if the tool declares an idempotent status operation; otherwise it appends
  an `outcome` receipt with status `unknown` and alerts for manual
  reconciliation.
- A retry with the same key and the same `request_hash` returns the recorded
  outcome, or the pending status, and does not dispatch again. A retry with the
  same key but a different `request_hash` returns `IDEMPOTENCY_CONFLICT`.
- If a different key arrives with the same `request_hash` while a prior decision
  for that `(tenant, principal, tool_identity)` is `pending` or `unknown`, deny
  `OUTCOME_UNKNOWN` and do not dispatch. A new key is not proof of a new intent.
- Reconciliation may append an `outcome` receipt with status `no_effect` only
  when the upstream definitively confirms that the original call had no effect.
  This is the only transition that clears the pending/unknown guard:
  - `no_effect` is terminal for that key. A retry with the same key returns
    `no_effect` and does not dispatch.
  - A new request with a new idempotency key is allowed only after `no_effect`
    is recorded.
  - If the upstream cannot confirm no effect, the state remains `unknown`.
- The gateway never auto-retries a destructive call. Retrying is a new client
  decision, and the client must use a new idempotency key after `no_effect`.
  For an explicitly idempotent tool, the upstream may dedupe retries, but the
  gateway still does not redispatch a recorded decision.
- The idempotency window defaults to the configured receipt retention period
  and must never be shorter than it. Dedupe state is durable across restarts; an
  expired key is treated as a new request.
- Crash-injection test points: before dispatch, during the call, after the
  effect but before the outcome append, and during the outcome append.

### Chain ownership and concurrency

- One writer per `(tenant, chain_id)`. The writer holds a lease with a monotonic
  `writer_epoch`; a new writer may append only after the lease expires and it
  has fenced the old writer.
- Active-active writers for one chain are not supported in v1. Redundant
  gateways operate as standby for a chain.
- A failover continues the same chain only with a signed handoff receipt.
  Otherwise it starts a new chain segment with an explicit handoff record.
- If two writers attempt to extend the same chain, one wins and the other fails
  closed.

### Tamper evidence and anchor

- A hash chain detects accidental modification and local reordering, but a
  compromised host can rewrite and rehash the entire local chain.
- v1 does not configure an external anchor. The claim is limited to integrity
  evidence against accidental corruption and partial tampering. It is not proof
  against a compromised gateway host.
- v1.1 adds an off-host anchor, a Merkle root, and automated anchor
  verification. When configured, the gateway publishes a signed chain head
  (daily or every N receipts) to an append-only store outside the gateway host;
  the claim is then tamper-evident against local rewrite.
- Do not claim "tamper-proof."

### Redaction

- Never store raw credentials, bearer tokens, cookies, or full PII.
- Store canonical argument hashes plus redacted values for audit.
- Redaction rules are part of the policy bundle and are tested.

### Async verifier

- Separate worker; reads receipts, recomputes the chain, checks policy version
  and rule identity, and detects missing or out-of-order receipts.
- Alerts on chain break, deny spikes, schema drift, missing receipts, and policy
  expiry.
- Cannot block; cannot undo. It is detection and audit, not prevention.

---

## 11. Enforcement modes

| Tool class | Mode | Failure behavior |
|---|---|---|
| Read-only, low impact | Observe + alert | Fail open, alert |
| Write / delete / send / money | Inline enforce | Fail closed |
| Highest impact | Inline enforce; human approval is v1.1 | v1 denies with `APPROVAL_REQUIRED`; v1.1 pauses and times out to deny |

The tool's risk classification lives in the policy bundle. Do not apply one mode
to every tool. v1 implements observe and enforce; the approval workflow is
v1.1.

---

## 12. Failure handling

- **Gateway unavailable:** high-risk tools deny; observe tools queue or drop with
  an alert.
- **Policy unavailable or invalid:** deny high-risk; use the last known good
  signed bundle only if it is unexpired.
- **Upstream timeout:** receipt `error`; return `TIMEOUT`; do not retry
  non-idempotent calls automatically.
- **Crash after effect, before outcome:** pending decision; do not auto-retry a
  destructive call; reconcile if the upstream supports it, otherwise mark
  `unknown` and alert.
- **Identity change mid-session:** deny `IDENTITY_MISMATCH`; require a new
  session.
- **Resource tenant unverified:** deny high-risk with
  `RESOURCE_TENANT_UNVERIFIED`.
- **Concurrent chain writer:** one writer wins; the other fails closed.
- **Outcome append failure:** mark `unknown` if possible; alert; fail closed for
  the tool until the sink recovers.
- **Idempotency:** accept an idempotency key; dedupe within a window; include it
  in the receipt. Reuse with a different request hash returns
  `IDEMPOTENCY_CONFLICT`.
- **Circuit breaker:** per upstream; open circuit denies high-risk.
- **Clock skew:** reject tokens outside a small window; use monotonic time for
  latency.
- **Backpressure:** bounded queues; never drop an enforcement receipt without
  denying the call.

---

## 13. Deployment modes

| Mode | Customer change | Enforces? | Bypass risk | Use when |
|---|---|---|---|---|
| MCP gateway | Change one MCP server URL | Yes | Low if gateway holds the credential | Agent uses MCP |
| HTTP tool proxy | Change tool base URL | Yes | Low if gateway holds the credential | Tools are REST |
| SDK wrapper | Small code change around dispatch | Yes, in-process | Medium if another path exists | Local functions |
| Sidecar / mesh | Infrastructure change | Yes | Low | Enterprise, many services |
| Receipt-only | Add emitter | No, observe only | N/A | Cannot route through gateway |
| Human approval | Orchestration pause | Yes | Low | Highest impact |

### Recommended order

1. MCP gateway — config-only, explicit tool calls, best first integration.
2. HTTP proxy — config-only for REST tools.
3. SDK wrapper — for in-process tools.
4. Receipt-only — audit-only, no prevention claim.
5. Sidecar — enterprise only.

### Latency budget

- Policy decision p50 < 2 ms, p99 < 10 ms, excluding the durable audit append.
- Durable `decision` receipt append p99 < 20 ms using a local WAL with group
  commit. High-risk tools wait for this append before execution.
- Gateway overhead p99 < 40 ms excluding the upstream tool, including the
  durable decision append.
- No network calls and no LLM on the decision path. Policy and tool metadata
  are loaded from memory; the only disk write on the hot path is the WAL.

### Availability

- Redundant gateways are standby per `(tenant, chain_id)`; active-active
  multi-writer is not supported in v1.
- Health checks, lease-based failover, and graceful drain.
- The gateway is on the critical path for inline tools; capacity planning is
  part of the rollout.

---

## 14. Observability

- Receipts are the source of truth.
- Metrics: decisions by tool/decision/reason, p50/p99 latency, policy age,
  chain verification failures, pending decisions, unknown outcomes, identity
  mismatches, chain writer conflicts, upstream errors, bypass attempts,
  approval waits. v1.1 adds anchor age and anchor verification metrics.
- Logs: structured, request IDs, no secrets.
- Traces: OpenTelemetry optional; export must not block the hot path.
- Alerts: deny spike, missing receipts, chain break, pending decision older
  than the reconciliation threshold, unknown outcome, schema drift, expired
  policy, chain writer conflict, gateway unhealthy, direct upstream connection
  attempt. v1.1 adds stale or missing anchor alerts when an anchor is
  configured.

---

## 15. Security requirements

- TLS everywhere; mTLS for service-to-service.
- Tokens: signature, audience, expiry, tenant binding, least-privilege scopes.
- Session binding: revalidate token subject, tenant, agent, and delegation on
  every call; no silent rebinding.
- Resource-tenant binding: require an explicit tool-catalog declaration; deny
  high-risk when absent.
- Secrets in a secret manager or OS-protected store; never in the repo, a
  plaintext environment variable, logs, or receipts.
- Policy signing key: owned by the security owner; one active key; historical
  public keys retained for audit verification; manual rotation runbook.
- Per-tool credentials; rotation; no shared super-key.
- Signed policy bundles; immutable images; SBOM; dependency audit.
- Audit anchor: v1 does not configure an external anchor; the limited claim
  from section 10 applies. When an anchor is added, publish a signed chain head
  to an off-host store.
- Gateway process: separate user, no shell, read-only filesystem except the
  receipt spool.
- Default-deny upstream server allowlist; egress control blocks direct
  agent-to-upstream connections.
- Bypass detection: log and alert if the agent attempts a direct connection to
  an upstream tool.
- Red-team tests: prompt injection, confused deputy, token theft, replay, schema
  poisoning, log tampering.

---

## 16. Testing and acceptance

### Unit

- Canonical JSON, receipt hash, idempotency-key validation and scoping.
- Policy precedence: deny > approval > allow > default deny; overlapping rules;
  unknown fields; invalid patterns.
- Tenant mismatch, missing identity, and resource-tenant declaration.
- Schema hash and drift detection.
- Protocol version: `initialize` with `2025-11-25` succeeds; a different proposed
  version is countered with `2025-11-25`; a later request with a mismatched
  `MCP-Protocol-Version` header denies `UNSUPPORTED_PROTOCOL_VERSION`.
- Policy key rotation: the active key verifies new bundles; a retired key cannot
  sign new bundles; historical receipts verify with the retained public key.
- Redaction.
- Session binding: same principal/tenant succeeds; changed principal, agent,
  tenant, or delegation denies.
- Delegation validation: broken, expired, over-depth, or unsigned hops deny.
- Gateway-token scope: a token without the requested tool scope denies.
- Receipt state machine: `pending` -> `success` / `error` / `timeout` /
  `unknown` / `no_effect`; `denied` is terminal; `no_effect` is terminal for
  the key.
- Chain ownership and `writer_epoch` fencing.

### Integration (v1)

- MCP HTTP/SSE: allowed call, denied call, missing identity, identity mismatch,
  protocol version mismatch, `server/discover` rejection, schema drift,
  upstream error, timeout, downstream disconnect.
- Schema drift: a changed schema returns `SCHEMA_DRIFT` until a new signed
  bundle is loaded; v1 has no dynamic approval path.
- Receipts: reload JSONL from disk, verify from genesis, tamper with a record and
  assert verification fails.
- Decision durability: decision receipt is fsynced before the upstream effect;
  sink failure denies.
- Bypass: direct upstream call without the gateway credential fails; the agent
  token cannot be used upstream; a direct agent-to-upstream connection attempt
  is blocked by egress policy and alerted.
- Replay and idempotency: a duplicate request does not repeat the effect;
  conflicting reuse returns `IDEMPOTENCY_CONFLICT`; a missing key on a high-risk
  call returns `IDEMPOTENCY_REQUIRED` and does not execute.
- Retry after unknown outcome: retry the same destructive call with a new
  JSON-RPC ID and a new `trace_id` but the same idempotency key; assert the
  effect is not repeated and the recorded outcome or `OUTCOME_UNKNOWN` is
  returned. A different key with the same content while the prior decision is
  pending or unknown must deny `OUTCOME_UNKNOWN` and must not dispatch.
- Shadow vs enforce: shadow forwards and records the would-deny result; enforce
  records denial and does not forward.
- Crash injection: before dispatch, during the call, after the effect but before
  the outcome append, and during the outcome append. No automatic retry of a
  destructive call.
- Reconciliation: when the upstream confirms no effect, append `no_effect`; a
  new request with a new key is then allowed. A retry with the old key returns
  `no_effect` without dispatch. When the upstream cannot confirm, the state
  remains `unknown` and the same-content/new-key guard still denies.
- Session reconnect: a new session re-authenticates; an existing session cannot
  be resumed with a different principal or tenant.
- Resource tenant: cross-tenant ID is denied; a missing upstream declaration
  denies high-risk.
- Chain: restart verifies; two concurrent writers cannot both extend the chain.
  v1 does not test full local-chain rewrite detection because no anchor is
  configured; v1.1 adds that test with an off-host anchor.
- No secrets: seed canaries in credentials and arguments; inspect receipts and
  logs for leaks.

### Performance

- p99 policy latency < 10 ms at a declared target request rate and host profile.
- Durable decision-receipt append p99 < 20 ms under the same conditions.
- One-hour soak in v1 with stable memory and chain verification. The 24-hour
  soak is v1.1.

### Acceptance criteria for v1

1. One MCP server and one high-risk tool are proxied over streamable HTTP/SSE,
   pinned to MCP `2025-11-25` handshake mode.
2. Authorized calls succeed; unauthorized calls do not reach the mutation
   handler. Customer-record state is unchanged for denials and a denial audit
   event is recorded.
3. Every decision emits a receipt; JSONL reloads and verifies from genesis;
   tampering fails verification.
4. Direct upstream access without the gateway credential fails; the agent token
   cannot be used upstream.
5. Missing identity, identity mismatch, protocol version mismatch, invalid
   policy or signature, schema drift, or receipt-write failure denies the
   high-risk tool.
6. Policy decision p99 < 10 ms and durable decision-receipt append p99 < 20 ms
   in the benchmark.
7. Shadow mode forwards and records the would-deny result; enforce mode denies
   and does not forward.
8. No secrets in receipts or logs.
9. Session binding and reconnect tests pass.
10. Resource-tenant test passes with an upstream declaration; otherwise
    high-risk is denied.
11. Crash recovery leaves pending decisions reconcilable to `no_effect` or
    `unknown` and never auto-retries a destructive call.
12. Chain restart verifies under one writer; the limited tamper-evidence claim
    is documented because v1 has no external anchor.

Deferred to v1.1 and not part of v1 acceptance: stdio, human approval workflow,
gateway-side resource lookup, active-active multi-writer chains, external
anchor, automated Merkle anchoring, full-chain rewrite detection, 24-hour soak,
key rotation, OpenTelemetry export, dashboard, multi-region.

---

## 17. Rollout plan

### Phase 0 — Observe

Deploy the gateway in shadow mode for one MCP server. Do not block. Compare
receipts to the scanner's expected policy. Fix identity, schema, and receipt
gaps.

### Phase 1 — Enforce one high-risk tool

Enforce `delete_customer_record` in staging, then a small production canary.
Fail closed. Roll back on a deny/error spike. This is the spike's production
counterpart.

### Phase 2 — Expand

Enforce all write/delete/send tools. Default deny for unclassified tools. Add
human approval for the highest-impact actions.

### Phase 3 — Operate

SLOs, audit export, retention, key rotation, policy change management, and
quarterly bypass tests.

### Gates for each phase

- Policy tests pass.
- Bypass tests pass.
- p99 latency within budget.
- Chain verification 100%.
- No unresolved security review findings.
- Rollback rehearsed.

---

## 18. Minimum v1 slice

To avoid overbuilding, v1 is deliberately small:

- One MCP server over streamable HTTP/SSE, pinned to MCP `2025-11-25` handshake
  mode.
- One high-risk tool: `delete_customer_record` with fake data.
- One tenant, one `chain_id`, one active writer.
- YAML policy bundle, signed with Ed25519, verified against one active public
  key, loaded locally. A manual rotation runbook retains historical public keys
  for audit verification.
- Policy actions allow/deny. `require_approval` fails closed as
  `APPROVAL_REQUIRED`.
- JSONL receipts with hash chain, two-phase decision/outcome, local WAL, and a
  30-day retention default.
- Session identity fixed at `initialize` and revalidated per call.
- Resource-tenant enforcement declared by the upstream; a missing declaration
  denies high-risk.
- Crash recovery for pending decisions; no automatic retry of destructive
  calls.
- No external anchor in v1; the limited claim is documented and the anchor
  interface is defined for v1.1.
- Separate `agentscan-gateway` console script/process with a minimal dependency
  set; no scanner or LLM imports in the request path; no UI.
- Shadow mode and enforce mode.

Deferred to v1.1: stdio, MCP `2026-07-28` stateless mode, HTTP proxy, SDK
wrapper, human approval workflow/UI, gateway-side resource lookup, active-active
multi-writer chains, external anchor, automated Merkle anchor verification,
full-chain rewrite detection, 24-hour soak, automated key rotation, async
verifier beyond receipt-chain checks.

---

## 19. Decisions

### Resolved for v1

| Question | v1 decision |
|---|---|
| Principal token | Signed JWT bearer with `sub`, `aud`, `tenant`, `exp`, and delegation. OIDC discovery and token exchange are deferred. |
| Policy language | YAML only. CEL/Rego is deferred. |
| MCP protocol version | `2025-11-25` handshake mode; streamable HTTP/SSE only; no stdio. `2026-07-28` stateless mode is v1.1. |
| Packaging | Separate `agentscan-gateway` console script/process in the same repo; minimal dependency set; no scanner or LLM imports in the request path. |
| Receipt storage | JSONL with a 30-day retention default. No external anchor in v1; the limited claim is documented and the anchor interface is defined for v1.1. Postgres is deferred. |
| Retention | 30 days for redacted receipts and dedupe state in the fake-data v1; configurable; production retention is set by data classification and policy; the dedupe window equals retention. |
| MCP stdio | Not in v1. Deferred to v1.1. |
| Approval | Not in v1. `require_approval` fails closed. |
| Multi-tenant keys | One active signing key per deployment. Per-tenant keys are v1.1. |
| Key and anchor ownership | Security owner; signing key in a secret manager or OS-protected store; manual rotation runbook retains historical public keys for audit verification; automated rotation is v1.1. |
| Raw arguments | Store canonical hashes and redacted values. No raw secrets or full PII. |
| Chain concurrency | One writer per `(tenant, chain_id)`; standby failover only. |
| Upstream tenant enforcement | Only the mock `delete_customer_record` in v1, backed by an automated cross-tenant negative test, a named upstream owner, and a recorded declaration version/hash. Real tools require owner sign-off and test evidence. |

### Still open (non-blocking)

No decision above blocks v1 implementation. Deferred details: the specific KMS
or secret-manager product, the specific off-host anchor product, the production
retention value, the per-tenant key model (v1.1), and the MCP `2026-07-28`
migration plan (v1.1).

---

## 20. Out of scope

- Full dashboard, billing, SSO, multi-region, Kubernetes operator.
- Policy authoring UI.
- LLM judge or scanner in the request path.
- Automatic remediation.
- MCP stdio, human approval workflow, active-active multi-writer chains,
  gateway-side resource lookup, Merkle proofs, and the 24-hour soak.
- Claims of tamper-proof audit without an external anchor.
- Enforcing tools that cannot be routed through the gateway; those are
  receipt-only with an explicit detection-only claim.

---

## 21. References

- `internal_docs/review-2026-11-09/AGENTSCAN_METHODOLOGY_UPDATE.md` §14
- Spike PR #12: `spike: action verification catches a denied tool call`
- `internal_docs/spike-action-verification/SPIKE_RESULT.md`
- MCP specification: tools, transports, and JSON-RPC lifecycle
- OWASP LLM Top 10 and Agentic Security Initiative guidance

---

## 22. Review disposition (2026-11-09)

**Final status: APPROVE for v1 implementation.** This is a design approval, not
evidence that the gateway is implemented or that the acceptance tests pass. The
review verified that the requirements are specified and testable; it did not
execute them.

### Initial review

Codex initial review: **REJECT for v1 implementation as written.** Revisions
addressed F1–F6:

| Finding | Change |
|---|---|
| F1 — session identity ambiguous | §7 adds fixed session binding and reconnect rules; §8 revalidates identity per call; §16 adds reconnect and identity-change tests. |
| F2 — crash after effect | §10 adds `pending`/`unknown` states, idempotency-key persistence, and no-auto-retry recovery; §16 adds crash-injection tests. |
| F3 — resource tenant | §9 adds mandatory `resource_tenant_enforced` declarations and explicit rule precedence; §16 adds cross-tenant tests. |
| F4 — chain anchor and multi-writer | §10 adds single-writer leases, `writer_epoch`, and an explicit anchor-or-narrowed-claim rule; §16 adds restart and concurrent-writer tests; full-chain rewrite detection is v1.1. |
| F5 — scope mismatch | §16 aligns acceptance with v1; §18 states the v1/v1.1 boundary; stdio, approval, 24-hour soak, and multi-writer are deferred. |
| F6 — evidence wording | §1 narrows the spike claims to customer-record state, the in-process capability guard, and per-run chain verification. |

### Re-review and remaining fixes

Codex re-review of `a3f9446` returned **APPROVE WITH CHANGES**: F1 and F3–F6
`CLOSED`, F7 `PARTIAL`, F8 `OPEN`. Later revisions closed the remainder:

| Finding | Change |
|---|---|
| F7 — delegation, scope, drift, idempotency, egress | §7 adds delegation-chain validation and per-call gateway-token scope; §9 requires a new signed bundle for schema drift; §10 defines the dedupe window; §15 and §16 add egress and bypass tests. |
| F8 — retry-stable idempotency | §8 and §9 require a caller-supplied key that cannot be derived from `trace_id` or the JSON-RPC ID, scoped to `(tenant, principal, tool_identity, idempotency_key)`; §10 adds the content-hash guard for pending/unknown decisions; §16 adds a retry with a new JSON-RPC ID and trace ID. |
| P2 — retry-state contradiction | §10 adds the terminal `no_effect` reconciliation state: it is recorded only when the upstream confirms no effect, a same-key retry returns `no_effect` without dispatch, and a new key is allowed only after it. §16 adds reconciliation tests. |
| P2 — anchor scope contradiction | §14 makes anchor metrics and alerts v1.1; §16 defers full-chain rewrite detection; acceptance criterion 12 requires the documented limited claim because v1 has no external anchor. |
| §19 — implementation decisions | §19 records MCP `2025-11-25` handshake mode, a separate `agentscan-gateway` process, no anchor in v1, 30-day retention, key ownership and rotation runbook, and mock-only upstream tenant enforcement. |

### Final verification

| Check | Result |
|---|---|
| P2 retry-state | `CLOSED` — `no_effect` is terminal and recorded only after upstream confirmation; same-key retries return it without dispatch; a new key is allowed only after it. |
| Anchor scope | `CLOSED` — v1 has no external anchor; anchor metrics, alerts, and full-chain rewrite detection are v1.1; criterion 12 requires the documented limited claim. |
| §19 decisions | Recorded; no open decision blocks v1 implementation. |
| Overall | **APPROVE for v1 implementation.** |

The §16 requirements remain acceptance criteria to execute during
implementation. Phase 2 rollout expansion remains **NO-GO** until v1 is
implemented and passes the §17 rollout gates. Implementation is a separate step
and remains gated on the spike PR and explicit authorization.
