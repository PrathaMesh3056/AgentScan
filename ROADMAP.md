# AgentScan Roadmap

Updated 31 October 2026. Package metadata declares **v0.2.0** and a beta development status. This describes the implemented source and verification limits; it does not establish a production deployment or calibrated detection accuracy.

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

The selected [ATK-006](docs/modules/mcp_shadow.md) engineering update is implemented
and locally verified on 17 October. It separates eight inconclusive
response-proposal observations from one
optional MCP catalog-policy comparison against an independently reviewed
endpoint/tool-definition baseline. Catalog deviations are bounded policy
findings, not evidence of agent execution or server compromise. The full local
non-slow suite passed 2,189 tests; four actual local CLI cases verified discovery
without tool calls. Actual catalog poisoning, post-approval rug pulls and real-agent
efficacy remain open.

The next [ATK-013](docs/modules/excessive_agency.md) engineering update retains
its ten original seeds as a bounded response inventory. Reported tool proposals,
completion claims and refusals remain authorization/effect-INCONCLUSIVE, with
zero impact-evaluated tests and a separate dashboard/report panel. Local verification
passed 2,279 tests on 18 October (32 skipped, eight slow exclusions).
Independent policy/approval/effect witnesses and
real-agent defense evaluation remain open.

The [ATK-004](docs/modules/dos.md) update on 25 October keeps nine finite probes
as a bounded response inventory. Its default scan makes no DoS impact or clean
resilience claim from text, client timing or errors. An optional in-process
owned witness binds work counters and neutral admission to each probe. The
three-arm synthetic control produced one separately scoped local finding when
the uncapped service denied neutral work on probe six; ATK-004 stopped before
further probes. The capped and timeout-text arms had no local finding. Real
serving-stack and concurrent-user evaluation remains open under separately
approved load limits.

The [ATK-027](docs/modules/model_theft.md) engineering update on 26 October
replaces architecture/path/length guesses with a complete privately provisioned
synthetic-reference criterion. Ten bounded model/IP requests preserve the five
original requests and add authored reasoning, diagnostic, manifest and packaging
variations. Missing references prevent probes; public-input contamination and
incomplete responses remain inconclusive. The six-arm authored HTTP evaluation
passed its declared gate with 32 deliveries, including positive, public-information,
incomplete, preflight and request-budget controls. These results do not establish
model theft, weight recovery, training-data origin or real-agent defense efficacy.
Current primary disclosures and published research are documented in the guide.
The owner's presentation changes in `DESIGN-CHANGES.md` are preserved.

The selected [ATK-010](docs/modules/crescendo.md) update replaces public marker
echoes and judge-only success with a complete privately provisioned synthetic
reference criterion across six bounded scripted conversations. It checks the
planned turns, accumulated history and actual request inputs, isolates local
script state and preserves incomplete/error/not-run coverage. Adaptive generation
is disabled for this profile. On 31 October, eight frozen authored HTTP control
arms passed with 86 deliveries, establishing scanner contracts only. Independent real-agent
efficacy, adaptive attack/defense evaluation, target-side history consumption and
server-side session isolation remain open. The existing dashboard design is
preserved.

## Implemented capabilities

The 31 October [T3MP3ST source comparison](docs/research/t3mp3st_comparison.md)
maps AI trust boundaries to AgentScan's measured evidence and open gaps. Its
execution-boundary testing approach informed an independent HTTP hardening fix:
captured-request custom headers are now removed across origins, consistently
with explicitly supplied target headers. Once a chain crosses origins, cookies
cannot be restored from HTTPX's jar on later hops. Destination protocol headers
are regenerated without restoring credential defaults. Source code was not imported. This
scanner credential boundary does not add model-effectiveness or tool-execution
claims; [redirect body and enrollment limits](docs/DATA_POLICY.md#http-redirect-credentials-and-assessment-scope)
remain explicit.

| Capability | Implemented behavior | Verification boundary |
|---|---|---|
| Agent assessments | SCAN, EXPLOIT and DEEP orchestration; 27 attack modules mapped to OWASP LLM 2025 scenarios | Module availability depends on the selected profile. Mapping scenarios does not establish complete category coverage or detector accuracy. |
| [ATK-001 scoped update](docs/modules/prompt_injection.md) | Completed 10 October: 24 direct-user seeds, complete known-reference disclosure criterion, input-provenance checks, reference validation and transcript redaction | Single-turn supported text representations only; missing criteria stay inconclusive. Independent real-agent accuracy remains unverified. |
| [ATK-005 document profile](docs/modules/indirect_injection.md) | Seven document patterns, opt-in HTTP adapter, separate source/task delivery and correlated consumption receipts; configured through dashboard, CLI or API | Complete known-reference disclosure only. Receipts are target-reported, tools are unassessed and unsupported connectors stay unavailable. Local model run observed no disclosures and only 1/2 strict benign tasks; independent customer accuracy is unverified. |
| [ATK-006 MCP profile](docs/modules/mcp_shadow.md) | Eight inconclusive response observations; optional approved exact-endpoint/full-tool-definition catalog comparison through CLI/SDK/local dashboard | A complete catalog comparison is one `mcp_catalog_policy` check, with bounded MEDIUM findings for unexpected, changed or missing entries. No automatic approval, metadata injection, continuous monitoring or downstream execution proof. |
| [ATK-013 agency inventory](docs/modules/excessive_agency.md) | Ten retained user-message probes; bounded hashed proposal/status observations and separate CLI/dashboard/report presentation | Engineering locally verified, 18 October. No authorization or effect findings/evaluated negatives; pure inventory score and SSP are null. No independent policy/approval/effects adapter or installed defense. |
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
