# Runtime Gateway and MCP Integration

**Status:** Draft for review — not implemented  
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

The spike (PR #12) proved the reference behavior with a fake CRM tool:

- an authorized delete was allowed and changed fake state;
- an unauthorized delete was denied before mutation;
- ACT-001 produced a finding carrying the denial receipt hash;
- a direct call outside the gateway failed;
- the receipt chain verified independently.

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
- No full policy language, policy UI, or approval UI.
- No multi-region, Kubernetes, SSO, billing, or custom auth.
- No enforcement for tools that cannot be routed through the gateway; those are
  receipt-only/observe, and the honest claim is detection, not prevention.
- No MCP protocol extensions beyond what is needed to identify the caller and
  tool.
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
                    ├── allow / deny / require_approval
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
| Log tampering | Hash chain, append-only storage, separate writer credentials, periodic anchor. |
| Gateway compromise | Least privilege per tool credential, rotation, process isolation, no shell. |
| Identity spoofing | Signed tokens, mTLS, audience and expiry checks. |

The gateway must never trust the agent's self-report, its text response, or a
tool description supplied at call time.

---

## 7. Identity and credential model

### Identities

- **Principal:** end user or service. Carried in a signed token with `sub`,
  `aud`, `scope`, `exp`, and an actor/delegation claim.
- **Agent:** workload identity via mTLS certificate or signed workload JWT.
- **Gateway:** its own identity to the upstream MCP server.

### Credential custody

- The gateway holds the real upstream credential (API key, OAuth token, mTLS
  cert, database credential).
- The agent holds a short-lived gateway token scoped to the gateway audience and
  the tools it may request.
- The agent must not possess the upstream credential. If it does, the gateway is
  advisory, not enforcing.

### MCP HTTP / streamable HTTP

- One signed bearer token per request or session.
- Claims include principal, agent, tenant, scopes, and delegation chain.
- The gateway validates signature, audience, expiry, and tenant binding before
  policy evaluation.
- Missing or invalid identity: deny high-risk; `UNVERIFIED` in observe mode.

### MCP stdio

- The gateway launches the upstream server and holds its environment secrets.
- The agent never receives the upstream environment.
- If one stdio session can serve multiple principals, require a session per
  principal or deny. A shared stdio session without per-request identity is
  `UNVERIFIED` at best.

---

## 8. MCP integration

The gateway is an MCP proxy: it speaks MCP to the agent and to the upstream
server. The first transport is streamable HTTP/SSE; stdio follows.

### Intercepted methods

| MCP method | Gateway behavior |
|---|---|
| `initialize` | Negotiate protocol; bind session to agent identity; record client info. |
| `tools/list` | Fetch upstream list; canonicalize; hash each `inputSchema`; apply visibility policy; return filtered list. |
| `tools/call` | Resolve tool identity, validate arguments, evaluate policy, allow or deny, forward if allowed, emit receipt. |
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

1. Parse JSON-RPC request; reject malformed or oversized payloads.
2. Resolve session → agent → principal; reject missing/invalid identity for
   high-risk tools.
3. Look up the tool by name; verify the schema hash against the approved
   snapshot.
4. Canonicalize arguments: reject duplicate keys, NaN/Infinity, non-string keys,
   and oversize values; validate required fields and types.
5. Evaluate policy. Record `policy_id`, `rule_id`, and reason.
6. On deny: append receipt, return a stable MCP error, do not call upstream.
7. On allow: append and fsync a `decision` receipt, then call upstream with the
   gateway-held credential. Never forward the agent's token upstream.
8. Append an `outcome` receipt for success, error, or timeout; return the
   upstream result. Decision and outcome receipts share `trace_id` and
   `request_hash`.
9. On approval-required: pause, create an approval record, return a stable
   pending response; timeout denies.

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
| `SCHEMA_DRIFT` | Tool schema does not match the approved snapshot. |
| `APPROVAL_REQUIRED` | Human approval required; call not executed. |
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

### Evaluation

- Deny overrides allow; default is deny.
- Explicit deny rules are evaluated before allow rules.
- First matching allow wins; no implicit allow.
- Every decision includes `policy_id`, `rule_id`, and a machine-readable reason.

### Policy lifecycle

- Bundles are signed (Ed25519) and hash-pinned.
- The gateway refuses unsigned, expired, or tenant-mismatched bundles.
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

A `decision` receipt uses `"phase": "decision"`, `"result": {"status":
"pending"}`, and no `response_hash`. Production extends the spike's
`ActionResult.status` literal with `"pending"`; the spike's literal remains
unchanged.

### Chain and storage

- One chain per tenant and gateway stream; fixed genesis.
- Canonical JSON + SHA-256; each receipt binds the previous hash.
- Append-only JSONL for v1; object storage for cold retention.
- Two-phase audit for high-risk tools: append and fsync a `decision` receipt
  before the tool effect, then append an `outcome` receipt after. A single
  receipt cannot both precede the effect and contain its result.
- If the decision receipt cannot be made durable, deny. If the outcome receipt
  cannot be written after an allowed call, alert and fail closed for that tool
  until the sink recovers.
- Use a local write-ahead log with group commit to amortize fsync; the durable
  append budget is separate from policy-decision latency.
- Daily Merkle root / anchor is optional v1.1.

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
| Highest impact | Inline enforce + human approval | Fail closed, pause, timeout denies |

The tool's risk classification lives in the policy bundle. Do not apply one mode
to every tool.

---

## 12. Failure handling

- **Gateway unavailable:** high-risk tools deny; observe tools queue or drop with
  an alert.
- **Policy unavailable or invalid:** deny high-risk; use the last known good
  signed bundle only if it is unexpired.
- **Upstream timeout:** receipt `error`; return `TIMEOUT`; do not retry
  non-idempotent calls automatically.
- **Idempotency:** accept an idempotency key; dedupe within a window; include it
  in the receipt.
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

- Redundant gateway instances behind a local load balancer or service VIP.
- Health checks and graceful drain.
- The gateway is on the critical path for inline tools; capacity planning is
  part of the rollout.

---

## 14. Observability

- Receipts are the source of truth.
- Metrics: decisions by tool/decision/reason, p50/p99 latency, policy age,
  chain verification failures, upstream errors, bypass attempts, approval waits.
- Logs: structured, request IDs, no secrets.
- Traces: OpenTelemetry optional; export must not block the hot path.
- Alerts: deny spike, missing receipts, chain break, schema drift, expired
  policy, gateway unhealthy, direct upstream connection attempt.

---

## 15. Security requirements

- TLS everywhere; mTLS for service-to-service.
- Tokens: signature, audience, expiry, tenant binding, least-privilege scopes.
- Secrets in a secret manager or environment; never in logs or receipts.
- Per-tool credentials; rotation; no shared super-key.
- Signed policy bundles; immutable images; SBOM; dependency audit.
- Gateway process: separate user, no shell, read-only filesystem except the
  receipt spool.
- Default-deny upstream server allowlist; egress control.
- Bypass detection: alert if the agent connects directly to an upstream tool.
- Red-team tests: prompt injection, confused deputy, token theft, replay, schema
  poisoning, log tampering.

---

## 16. Testing and acceptance

### Unit

- Canonical JSON and hash chain.
- Policy evaluation: allow, deny, deny-overrides, default-deny, missing identity,
  tenant mismatch, argument mismatch, approval path.
- Schema hash and drift detection.
- Redaction.

### Integration

- MCP HTTP/SSE: allowed call, denied call, missing identity, schema drift,
  upstream error, timeout, downstream disconnect.
- MCP stdio: allowed call, denied call, secret isolation.
- Receipt sink failure: high-risk deny; observe alert.
- Replay and idempotency.
- Bypass: direct upstream call fails without the gateway credential; agent token
  cannot be used upstream.

### Performance

- p99 policy latency < 10 ms at the target request rate.
- Soak test for 24 hours with stable memory and receipt chain.

### Acceptance criteria for v1

1. One MCP server and one high-risk tool are proxied.
2. Authorized calls succeed; unauthorized calls are denied before the upstream
   effect.
3. Every decision emits a receipt; the chain verifies independently.
4. Direct upstream access without the gateway credential fails.
5. Missing identity, invalid policy, or audit sink failure denies the high-risk
   tool.
6. Policy decision p99 < 10 ms and durable decision-receipt append p99 < 20 ms
   in the benchmark.
7. Shadow mode works without blocking; enforce mode works for the selected tool.
8. No secrets in receipts or logs.

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

- One MCP server over streamable HTTP/SSE.
- One high-risk tool: `delete_customer_record` with fake data.
- One tenant.
- YAML policy bundle, signed, loaded locally.
- JSONL receipts with hash chain.
- CLI process `agentscan-gateway` (or `agentscan gateway`), no UI.
- Shadow mode and enforce mode.
- No stdio, no approval UI, no multi-region, no policy editor.

Stdio, HTTP proxy, SDK wrapper, human approval, and the async verifier follow
only after v1's acceptance criteria are met.

---

## 19. Open questions

1. Principal token: OIDC/JWT directly, or OAuth token exchange?
2. Policy language: YAML v1, or CEL/Rego from the start?
3. Receipt storage: local JSONL + object storage, or Postgres?
4. MCP stdio identity: one session per principal, or deny shared sessions?
5. Approval transport: CLI, webhook, or chat?
6. Multi-tenant key management and per-tenant chains.
7. Which MCP protocol versions must be supported at launch?
8. Separate service, or `agentscan gateway` subcommand in the existing package?
9. How long to retain raw arguments versus hashes only?
10. Who owns the policy bundle and the approval workflow?

---

## 20. Out of scope

- Full dashboard, billing, SSO, multi-region, Kubernetes operator.
- Policy authoring UI.
- LLM judge or scanner in the request path.
- Automatic remediation.
- Enforcing tools that cannot be routed through the gateway; those are
  receipt-only with an explicit detection-only claim.

---

## 21. References

- `internal_docs/review-2026-11-09/AGENTSCAN_METHODOLOGY_UPDATE.md` §14
- Spike PR #12: `spike: action verification catches a denied tool call`
- `internal_docs/spike-action-verification/SPIKE_RESULT.md`
- MCP specification: tools, transports, and JSON-RPC lifecycle
- OWASP LLM Top 10 and Agentic Security Initiative guidance
