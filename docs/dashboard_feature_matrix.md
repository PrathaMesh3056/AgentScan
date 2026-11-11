# Dashboard feature coverage

This inventory compares the local dashboard with implemented commands and APIs. It records what is available, what has been surfaced in this repair, and which workflows still require the terminal. It does not claim that package presence proves a working model, browser or deployment.

Start with [START_HERE.md](START_HERE.md) for setup, scan examples, the attack catalogue and error recovery. Start the dashboard with `agentscan ui`, or `python -m agentscan.cli ui` when the console launcher is unavailable.

## Dashboard workflows

The overview now includes **Scan evidence** charts for evaluated coverage,
finding severity, module execution status and whole-scan elapsed time. Severity
buttons filter the findings view; module IDs, scopes and reasons are available
in an equivalent table. Missing/inconsistent counts and timestamps remain
unavailable. Local reference observations are separate from target findings.

| Capability | Dashboard surface | Actual implementation / limit |
| --- | --- | --- |
| HTTP JSON, WebSocket and remote MCP endpoint scans | Launch scan | `/api/scan`; target URL and authentication must match the target. Authentication failures are assessment errors, not clean findings. |
| SCAN, EXPLOIT and DEEP selection | Launch scan and attack catalogue | Modes use registered modules. Neural probes need optional dependencies and configured local model assets. An unavailable module must remain visible as unavailable. |
| Deterministic, local or optional external analysis | Analysis controls and feature guide | Deterministic is the default. Sensitive scans allow deterministic or offline local analysis. External analysis requires explicit non-sensitive designation and a locally configured provider key. |
| Runtime package availability | Feature guide | New `/api/features` checks module presence without importing optional model libraries, probing daemons or reading keys. Package presence does not verify a running model, installed browser binaries or native libraries. |
| Attack catalogue and load failures | Evaluation pipelines | `/api/attacks` returns actual registered modules, supported modes and load errors. The supported mode counts overlap. |
| ATK-005 document ingestion adapter | Launch scan → Indirect document assessment | Select `document_v1` only for an HTTP target implementing the [adapter contract](modules/indirect_injection.md). The masked private reference must already exist on the target. Other connectors stay unavailable; absent/mismatched receipts remain inconclusive. Selecting this does not install an adapter. |
| ATK-006 approved MCP catalog | Launch scan → MCP inventory baseline | Optional JSON specifies `mcp-tool-json-sha256-v1`, the exact selected MCP endpoint and reviewed full-definition hashes by tool name. Malformed values, unsupported modes and endpoint mismatches are field errors. Providing a baseline selects a catalog-only SCAN with only ATK-006 and no `tools/call`. Missing baseline retains the ordinary suite; native MCP targets are unavailable to ATK-006's chat-probe profile. See [setup and limits](modules/mcp_shadow.md). |
| Assessment verdict and every module outcome | Overview assessment panel | The report contains status, tests selected/run, module errors, unavailable checks and module outcomes. Review all outcomes before interpreting a score. |
| JSON, SARIF and standalone HTML reports | Report download actions | New `/api/report/download?format=json`, `sarif` or `html` uses only the current in-memory scan report. Fixed attachment names, no arbitrary file path or archive. No report produces an actionable 404. |
| Findings, HTTP traffic and trajectories | Findings, traffic and trajectory views | Current report/recorder data; evidence can remain sensitive even after credential-pattern redaction. |
| Source and dependency audit | Supply-chain audit | Eight category checkboxes expose dependency, config, secret, typo, MCP, identity, framework and optional Semgrep checks. Offline and transitive controls default on; seven categories default on, with Semgrep opt-in. Unchecking offline can send package names and versions to OSV. Dashboard paths are contained within its configured project root. |
| AI bill of materials and dependency graph | Feature guide actions and audit views | Existing `/api/aibom`, `/api/aibom/download` and `/api/dependencies/graph`. Declared and unresolved inventory must not be shown as observed model/runtime versions. |
| Identity and RBAC | Identity and authorization views | Existing manifest inspection and permission graphs. Manifest declarations alone do not prove actual runtime permission enforcement. |
| Guardrail configuration | Guardrails | Existing LiteLLM, Cloudflare and Bedrock export representations. This generates configuration; it does not deploy or verify a gateway. |
| Runtime gateway health and readiness | Runtime Gateway tab | New read-only `GET /api/gateway/status` added by this work probes the configured loopback gateway `/healthz` and `/readyz` only and reports bounded probe state. The panel does not evaluate policy, receipts or tool decisions, does not expose or call `/metrics`, and the gateway `serve` command is not wired until Phase 5. `/readyz` fails closed until then. |
| Compliance mapping and signed report verification | Compliance and verification controls | Findings-to-framework mappings do not certify compliance. Signing requires a private configured key; integrity verification is separate from assessment completeness. |
| Remediation preview and explicit apply | Healing | Existing local remediation endpoints use the configured project root. Review plans before applying. Unsupported or ambiguous rewrites remain manual. |
| Multi-agent evaluation | Team / swarm controls | Existing `/api/swarms/run`; fresh scan observations and the same analysis classification policy apply. |
| Canary monitoring | Sentinel | Existing start, stop and single-probe endpoints. Target availability and authentication still apply. |
| AgentScan MCP tools | MCP tools | Existing `/api/mcp/invoke`; this is the scanner's tool interface, distinct from configuring every possible remote target transport. |
| Calibration and benchmark smoke checks | Calibration / benchmark actions | Existing endpoints identify synthetic scope. These are not independent accuracy benchmarks or target security certifications. |

## Terminal workflows and deliberate boundaries

The scan form also accepts an optional masked **Private synthetic reference**. Provision
the same synthetic value privately on the target before scanning. It is passed to the
existing target configuration, never seeded into attack messages. Without usable
criteria, ATK-001 remains inconclusive; markers and judge opinions do not replace them.
See [ATK-001 setup and assessment limits](modules/prompt_injection.md).

| Capability | How to access it | Why it is not a generic dashboard action |
| --- | --- | --- |
| Captured HTTP request / custom JSON message and response paths | `agentscan scan --config target.yaml`; `agentscan scan --help` documents `--curl`, `--message-path`, `--response-path` | The simple dashboard URL form does not accept a captured request body/header profile. Profiles may contain credentials. The feature guide shows the terminal handoff rather than implying that any URL is an API-compatible target. |
| Browser widget scans | `agentscan scan --browser-url https://your-agent.example/chat --input-selector '#message' --response-selector '.reply' --completion-selector '.done'` | Selectors must match the application. Browser dependencies/binaries and verified reply completion need setup. No automatic browser/model download occurs. |
| MCP stdio subprocess target | Use a local target profile and `agentscan scan --help` | The local dashboard does not expose arbitrary process commands. Remote MCP URL support does not imply that browser users can spawn local tools. |
| Full transcript and trajectory files | `agentscan scan http://127.0.0.1:8000/chat --transcript transcript.json --trajectory-log trajectory.json` | Output paths and local sensitive evidence retention belong to the terminal operator. |
| Custom Semgrep rule paths | `agentscan audit --help`; select `--rules PATH` with the Semgrep check | Dashboard audit categories, offline mode and transitive chains now have controls. Custom rule file paths remain a terminal option. |
| Git integration for remediation | `agentscan fix --help` | The command previews by default. Apply, commit, push and PR creation require explicit options and a suitable repository. A feature card does not trigger these operations. |
| PDF report generation | `agentscan scan http://127.0.0.1:8000/chat --output report.pdf` | Optional WeasyPrint/native setup. Dashboard downloads expose JSON, SARIF and HTML only. |
| Service deployment, workers, quotas and retention | `agentscan api --help`; [api.md](api.md) | The local dashboard is separate from the tenant service. It must not invent worker readiness, durable history, tenant policy or retention guarantees for its in-memory state. |
| Optional OpenTelemetry / Prometheus deployment | [api.md](api.md), deployment configuration | Configuration and service deployment are operator responsibilities. Local dashboard events do not imply that every optional exporter is running. |
| Independent benchmark receipt verification | `agentscan verify-claims --help` | Separate receipt workflow; the dashboard's synthetic benchmark is not equivalent. |

## New read-only API contracts

`GET /api/features` returns:

- `runtime`: optional feature name, installed flag, missing packages, manual setup command and an explicit `verified: false`.
- `analysis_policy`: sensitive-safe defaults and external-analysis prerequisites. It returns no key, model weights, target data or local environment values.
- `report`: current report availability, supported formats and the download endpoint.
- `workflows`: implemented dashboard actions or honest terminal commands. These describe capabilities; they do not execute commands.

`GET /api/report/download?format=json|sarif|html` downloads the current scan report. Authentication and localhost/origin controls remain in effect. HTML is autoescaped, self-contained and delivered as an attachment with a sandbox content-security policy. The SARIF download includes assessment status, coverage and errors in run properties so a failed scan is not reduced to an empty findings list. No filesystem export, PDF download, ZIP vault, automatic publishing or provider call occurs.

The local report API and these downloads are not a secret vault. Review target evidence before sharing an exported report. Local evidence retention follows the operator's filesystem policy; the tenant service's retention setting does not apply to local dashboard memory or files.

## Runtime gateway status API

`GET /api/gateway/status` is a read-only status surface for the local runtime gateway. It reads the `AGENTSCAN_GATEWAY_URL` environment variable and makes no network call when the variable is unset or blank.

- Unset or blank: HTTP 200 with `configured: false`, `status: "not_configured"`, `reason: "gateway_url_unset"`, null probes, and no network activity.
- Configured but invalid: HTTP 200 with `status: "misconfigured"` and the bounded reason `gateway_url_invalid`, with null probes. Only loopback HTTP(S) base URLs are accepted (`127.0.0.1`, `localhost` or `::1`); credentials, query, fragment or path components are rejected. The raw URL is not echoed in the response.
- Configured and valid: the endpoint probes `{base}/healthz` then `{base}/readyz` with a 1.5 second timeout, no redirects and no environment credential forwarding. It never calls `/metrics`.

The response reports `status` of `ready`, `not_ready`, `unreachable`, `unhealthy`, `misconfigured` or `not_configured`, the bounded `reason` (for readiness failures the gateway-supplied reason is validated against a lowercase identifier pattern and falls back to `unknown_reason`), per-probe HTTP status and latency, and a UTC ISO `checked_at`. Failures use bounded reason codes such as `health_unreachable`, `health_timeout`, `health_status_<code>`, `health_invalid` and readiness codes; exception text, paths, tokens or response bodies are never included.

The response uses `Cache-Control: no-store`.

The dashboard Runtime Gateway tab renders this probe state only. It does not evaluate policy, receipts or tool decisions, does not use `/metrics`, and the gateway `serve` command is not wired until Phase 5. `/readyz` fails closed until Phase 5 wires the runtime.

## Failure interpretation

For the reported failure, `Target returned HTTP 401` is the immediate cause: the selected target rejected the request's authentication. Missing optional `torch` affects DEEP probes and does not explain HTTP 401 in SCAN. A model-analysis provider key does not authenticate a separately selected target API unless that target explicitly uses the same authentication scheme. Target URL, header, request body and response path must match its API contract.

The dashboard should distinguish field validation, target authentication, unavailable optional modules, partial assessments and unexpected internal failures. Empty fields and malformed values belong next to their controls; assessment/runtime errors belong in the result panel with recovery guidance and full module coverage.

## Verification

`tests/test_ui_features.py` exercises sensitive-analysis policy metadata, unavailable optional packages, absence of returned provider secrets, fixed attachment filenames, strict export formats, missing-report guidance, JSON failure status preservation, SARIF structure, HTML escaping and dashboard authentication. These use synthetic in-memory reports; they do not contact a target or model provider.
