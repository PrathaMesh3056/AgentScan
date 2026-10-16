# AgentScan Roadmap

Updated 11 October 2026. Package metadata declares **v0.2.0** and a beta development status. This describes the implemented source and verification limits; it does not establish a production deployment or calibrated detection accuracy.

16 October sequencing update: at the owner's request, live-model and combined
module evaluations are deferred while engineering improvements proceed one module
at a time. ATK-005's remaining positive-evidence and defense-improvement gates stay
open. [ATK-012](docs/modules/system_prompt_leak.md) has its scoped engineering
update; [ATK-003](docs/modules/pii_exfiltration.md) has its update, with a
private-value-only criterion, current primary-source review, bounded public-input
provenance and private evidence handling. [ATK-007](docs/modules/output_handling.md)
now inventories 12 output-text indicators without promoting syntax into execution
findings or clean impact scores, and hardens the scanner's live terminal preview.
Its optional trusted in-process consumer profile keeps local browser/SQLite
findings outside customer target scores. All 48 frozen fixed-control consumer
runs passed their declared thresholds. A separate 24-generation offline model
smoke completed only 5/24 consumer assessments per arm and 0/12 benign tasks;
it is INCONCLUSIVE for real-agent efficacy. The model smoke reused 17 preserved
generations with input/response hashes, but lacks their contemporaneous weight
receipt. Published papers/current disclosures inform this work. Other modules'
deferred live gates and historical results remain unchanged.

## Implemented capabilities

| Capability | Implemented behavior | Verification boundary |
|---|---|---|
| Agent assessments | SCAN, EXPLOIT and DEEP orchestration; 27 attack modules mapped to OWASP LLM 2025 scenarios | Module availability depends on the selected profile. Mapping scenarios does not establish complete category coverage or detector accuracy. |
| [ATK-001 scoped update](docs/modules/prompt_injection.md) | Completed 10 October: 24 direct-user seeds, complete known-reference disclosure criterion, input-provenance checks, reference validation and transcript redaction | Single-turn supported text representations only; missing criteria stay inconclusive. Independent real-agent accuracy remains unverified. |
| [ATK-005 document profile](docs/modules/indirect_injection.md) | Seven document patterns, opt-in HTTP adapter, separate source/task delivery and correlated consumption receipts; configured through dashboard, CLI or API | Complete known-reference disclosure only. Receipts are target-reported, tools are unassessed and unsupported connectors stay unavailable. Local model run observed no disclosures and only 1/2 strict benign tasks; independent customer accuracy is unverified. |
| Target connectors | HTTP JSON, captured cURL request profiles, local Playwright browser targets, WebSocket and MCP stdio/Streamable HTTP with bounded GET resumption and legacy HTTP+SSE discovery | Service jobs permit HTTP(S) only. Failed tool calls are not replayed; legacy endpoint announcements must stay on the enrolled origin. |
| Static audit and identity | Python/configuration checks, dependency advisories, AI component declarations, nested MCP server declarations, permission graphs and minimized reports | Unsupported/partial inputs retain inconclusive status; offline advisories and declarations do not prove deployed behavior or effective tool permissions. |
| Analysis policy | Deterministic and sensitive defaults; optional offline local analysis; external analysis only with explicit non-sensitive classification and client/operator configuration | Local model runtime must be provisioned. Real external provider calls are outside this verification batch. |
| Dashboard | Field-specific validation, runtime feature guide, audit category controls, diagnostics, JSON/SARIF/HTML exports, event progress and local coverage/severity/status/duration charts | One active local workspace per process. Missing/error states remain visible; charts do not establish attack-success rates or overall agent security. |
| Guard and sandbox | Tool/path/command boundaries; requested isolation fails closed; disposable non-root Docker execution | Integration at the real tool boundary and host-specific isolation checks remain necessary. Host subprocess observation provides no containment. |
| Repair | Scoped reviewable AST/file changes, journals/preimage checks and guarded Git automation | Multi-file replacement is not globally crash-atomic. Generated guidance requires review. |
| Optional API service | Tenant authentication/policies, encrypted canonical requests, transactional outbox, durable events, fenced worker leases, tenant-scoped idempotent scan admission and retention | Admission replay does not create another scan, but at-least-once worker recovery can repeat target interactions. Production ingress, egress, secret custody and migration operations require deployment validation. |
| Release checks | Shared CI/release validation, pinned Actions, lock audit, lint/types/regressions and clean artifact checks | Remote required checks, protected publishing and trusted-publisher settings have not been read or modified. |

## Current priorities

1. Extend ATK-001 evaluation to independently authored authorized agents and representative model/framework combinations. The 11 October frozen offline CPU-model check found one detected reference disclosure in six attacks; the paired application guard suppressed delivery and preserved three of three benign tasks. Six adapter controls passed separately. This small same-team sample does not calibrate general accuracy; see [evaluation scope](docs/EVALUATION.md). Earlier six-request BitInfusion evidence predates repairs and grants no permission for further probes.
2. Extend ATK-005 beyond its completed document/retrieval step: define an actual tool-call/result boundary with authorization baselines and observable unauthorized effects, then freeze cases before implementation. The [separately authored SQLite retrieval validation](docs/modules/atk005_retrieval_validation.md) selected/evaluated all 12 cases without complete-reference disclosures; benign utility was 4/6 in both arms, with no measured output-control benefit. Improve public-task utility in a distinct predeclared experiment. Preserve the earlier seven-seed 1/2 benign result and completed ATK-001 regressions; neither small sample calibrates general accuracy.
3. Extend the published in-house labelled challenge with independently authored, held-out model evaluations. Preserve initial false-positive/missed-finding results, inconclusive rates and coverage before making accuracy claims.
4. Validate client retry/expiry and target-side replay controls in the intended deployment. Tenant-scoped idempotent admission now handles repeated submissions; preserve the documented at-least-once worker-effects boundary.
5. Validate each selected deployment profile: the final frozen CPU image and all 112 host-Python API tests against disposable PostgreSQL/Redis passed on 9 October; the cached offline CPU reference passed separately on 7 October. Ollama, GPU inference, the DEEP image and actual Kubernetes network policy remain unverified on this host. Unselected optional profiles do not block ordinary deterministic CLI/dashboard usage.
6. Validate remote release protections, Linux/Python matrix runs, versioned database migrations and image provenance. See [release readiness](docs/RELEASE_READINESS.md) for concrete operator steps and current evidence.
7. Preserve reviewed architecture documents in version control without exposing private audits, local target data or verification receipts. The requested `internal_docs/diagrams/` folder remains locally saved and Git-ignored.

## Later work

- Expand MCP interoperability across independently implemented servers while retaining byte/deadline bounds, origin checks, correlation and cancellation cleanup.
- Define a community module format with resource limits, provenance and review boundaries.
- Consider eBPF/gVisor and gateway integrations after the core assessment and deployment evidence is established.

Start with [the startup and attack guide](docs/START_HERE.md), [dashboard feature coverage](docs/dashboard_feature_matrix.md), [data policy](docs/DATA_POLICY.md) and [release gates](.github/SECURITY_GATES.md).
