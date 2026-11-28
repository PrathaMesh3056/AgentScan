# AgentScan architecture

AgentScan is a Python assessment application with three entry points: the terminal, a local dashboard and an optional multi-tenant service. They share the scan models, attack registry, connectors and report formats. Feature registration means that code exists; execution still depends on applicability, installed packages, target configuration and evidence.

This document is the public architecture summary. Detailed use-case, component, sequence, state, data-flow, deployment and function inventories are not published because they contain local verification receipts and private working material; they are excluded from distribution packages. Public installation and operation instructions are in [START_HERE.md](START_HERE.md).

## Execution and evidence

| Component | Responsibility and boundary |
|---|---|
| `agentscan.cli`, `agentscan._cli` | Parse commands and profiles, validate options and construct scan, static-audit, monitoring, swarm or remediation inputs. |
| `agentscan.core.models` | Typed target, finding and report contracts, including selected/evaluated coverage, module outcomes and nullable scores. |
| `agentscan.core.runner`, `agentscan.core.outcomes` | Select applicable modules, bound execution and record completed, unavailable and failed work. A target response or an exception is not itself proof of a vulnerability. |
| `agentscan.attacks.registry` | Discover modules and report optional-load failures. SCAN, EXPLOIT and DEEP suites overlap; EXPLOIT requires explicit selection. |
| `agentscan.attacks.scan`, `agentscan.attacks.exploit` | Exercise authorized target behavior and evaluate supported observations. Private-data disclosure needs a known private baseline, provisioned canary or configured analysis criterion. Tool side effects require observable evidence. |
| `agentscan.core.connectors` | Normalize HTTP/request-template, WebSocket, MCP and optional browser traffic. Transport capability differs from the target's effective permissions. See [MCP compatibility](MCP_COMPATIBILITY.md). |
| `agentscan.reporting` | Render JSON, HTML, SARIF and optional PDF, preserving incomplete assessment status and evidence provenance. Compliance mappings associate checks with requirements; they do not establish compliance. |

Sensitive scans use deterministic checks or explicitly selected local analysis. External analysis requires a per-scan non-sensitive designation, a selected provider/model and its configured credential. The service additionally requires tenant permission. No implicit fallback to a remote provider is allowed. Local inference must be provisioned and independently restricted for offline operation. See [DATA_POLICY.md](DATA_POLICY.md).

ATK-005 uses an explicit boundary capability rather than chat-role simulation.
The configured HTTP `document_v1` connector submits a clean task separately from
the untrusted source; the target owns staging, retrieval and model-input
instrumentation. A receipt binds protocol, probe/source identity and the exact
UTF-8 document digest. Missing evidence is inconclusive, and unsupported connectors
remain unavailable. Findings additionally require a complete known private
reference. This is target-reported correlation, without independent causal or
tool-execution proof. See [the adapter contract](modules/indirect_injection.md)
and the adapter contract for the request/response shape and evidence fields.

The [separately authored retrieval validation](modules/atk005_retrieval_validation.md)
uses an owned three-document SQLite FTS5 corpus per probe. Search derives from
the clean task and ranks candidates with BM25; event-chain checks bind actual
stored, selected, callback-visible and rendered model-input content. That
benchmark application is separate from the shipped scanner, which does not own
a client's retrieval engine or install the benchmark's numeric output control.
See [the retrieval validation](modules/atk005_retrieval_validation.md) for the corpus and event-chain checks.

DEEP reference probes load a pinned local model through `agentscan.neural`. Those observations describe that local reference model, not the hidden states of a remote application. Reference observations do not contribute to the remote-target score. CPU execution, GPU execution and a Kubernetes deployment require separate verification.

## Dashboard and service

The dashboard in `agentscan.ui` is a local operator interface with field validation, task state, progress events, exports and feature guidance. It defaults to a loopback address. A dashboard token/session authorizes local operations; it is separate from target authentication and model-provider credentials. The dashboard does not start the target agent. Advanced profiles and browser scanning remain terminal workflows; the [feature matrix](dashboard_feature_matrix.md) shows the actual coverage.

The optional API in `agentscan.api` admits enrolled HTTP(S) targets under current tenant policies, persists encrypted pending requests in PostgreSQL and relays scan identities through Redis Streams. Workers use database leases to fence stale attempts, durable progress events, cancellation and retention. An optional tenant-scoped `Idempotency-Key` deduplicates matching submissions within record retention. It does not promise exactly-once effects on a target after a worker interruption. All replicas require the same persistent signing/data keys. See [API operations](api.md).

Application checks do not replace deployment boundaries. Kubernetes templates require operator-provisioned secrets, verified image digests, model-cache volumes where applicable, a NetworkPolicy-enforcing CNI and explicit target egress enrollment. Templates and a passing local API test are not proof of a running cluster. See [release readiness](RELEASE_READINESS.md).

## Static inspection, enforcement and remediation

`agentscan.supply_chain` audits supported dependency/configuration files, secrets, framework rules and MCP declarations. `agentscan.identity` analyzes declared identities and permissions. Both preserve parsing failures and provenance. A declared scope or an absent authentication field does not prove deployed behavior. Optional OSV queries transmit dependency names/versions; offline mode avoids that lookup.

`agentscan.guard` provides opt-in argument, path, command and capability validation at an integrated tool boundary. `agentscan.sandbox` selects available isolation engines; audit-only subprocess observation is distinct from isolation. Runtime availability and enforcement must be verified on the actual host. See [guard integration](GUARD.md) and [sandbox boundaries](SANDBOX.md).

`agentscan.remediation` creates reviewable plans for supported source, dependency, manifest and guardrail changes, then applies explicitly selected operations with containment and recovery handling. Optional Git/PR automation is an explicit workflow. A generated patch requires review and application-specific validation.

`agentscan.swarm` coordinates bounded specialist runs and records intelligence and budget telemetry. `agentscan.sentinel` watches configured paths/canaries. Optional telemetry requires its own endpoint configuration. Neither a proposed exploit nor a monitor's connectivity check establishes confirmed execution.

## Verification and remaining scope

The labelled local evaluation and its limits are documented in [EVALUATION.md](EVALUATION.md). Synthetic targets, transport mocks, real database/queue tests, a bounded authorized external sample and local model runtime checks establish different facts; they should be reported separately. Production model accuracy, accelerator behavior and infrastructure enforcement need representative independent evidence.
