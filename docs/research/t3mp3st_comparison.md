# Lessons from T3MP3ST for AgentScan

Reviewed 31 October 2026. The comparison uses T3MP3ST revision
[`29824d5625ede419ac8cdae418c8f4c72c6270f7`](https://github.com/elder-plinius/T3MP3ST/commit/29824d5625ede419ac8cdae418c8f4c72c6270f7),
reported by GitHub as the `main` head when inspected. Its commit timestamp is
8 September 2026. Mutable README pages and search caches may describe different
snapshots; the source links below use the pinned revision.

The useful lesson is to enforce authority where an action actually happens,
then require evidence appropriate to the claim. T3MP3ST primarily orchestrates
offensive tools. AgentScan assesses authorized AI agents and applications.
Tool capability, a model's willingness to answer and a verified AI security
boundary failure are different measurements.

## What the source establishes

| Inspected mechanism | Useful idea | Limit that AgentScan must retain |
|---|---|---|
| [Scope gate before tool handlers](https://github.com/elder-plinius/T3MP3ST/blob/29824d5625ede419ac8cdae418c8f4c72c6270f7/src/arsenal/index.ts), with [scope regression tests](https://github.com/elder-plinius/T3MP3ST/blob/29824d5625ede419ac8cdae418c8f4c72c6270f7/src/__tests__/arsenal-scope-gate.test.ts) | Reject an unauthorized destination before invoking the handler; test that the handler was never called. Its tests include malformed network-shaped inputs and CIDR ranges whose base address alone would look permitted. | A missing scope disables this gate. Configured hosts also admit subdomains; optional private/loopback allowances are broader than AgentScan's exact host/origin enrollment. A parameter-level host gate is not DNS pinning or OS-level egress containment. These policies should not be transplanted. |
| [Scope and authorization model](https://github.com/elder-plinius/T3MP3ST/blob/29824d5625ede419ac8cdae418c8f4c72c6270f7/docs/SCOPE_AND_AUTHORIZATION.md) | Separate operator intent, approved action classes, execution modes, evidence, findings and retests. | Documentation describes intended authority layers. Their presence does not prove every adapter enforces them. A permitted destination also does not authorize every action or disclosure of credentials to it. |
| [Live evidence gate](https://github.com/elder-plinius/T3MP3ST/blob/29824d5625ede419ac8cdae418c8f4c72c6270f7/src/evidence/gate.ts) | Keep unsupported claims from being promoted merely because an operator supplied a severity. | The inspected gate accepts certain declared evidence types with nonempty contents. This is an evidence-presence check, not independent proof of execution, authenticity, authorization or impact. AgentScan's private-reference and trusted-witness criteria remain necessary. |
| [Finding verifier](https://github.com/elder-plinius/T3MP3ST/blob/29824d5625ede419ac8cdae418c8f4c72c6270f7/scripts/verify-finding.mjs) and [adversarial refuter](https://github.com/elder-plinius/T3MP3ST/blob/29824d5625ede419ac8cdae418c8f4c72c6270f7/scripts/refute-finding.mjs) | Check source anchors, distinguish built versus executed PoCs, and look for guards in callers and other files. Cite-checking refutations helps catch invented guards. | A source match does not establish path dominance or exploitability. A finding that survives model reviewers is still not independently confirmed. AgentScan can use adversarial engineering review without treating votes as detector ground truth or sending sensitive source to providers. |
| [Refusal-frontier experiment](https://github.com/elder-plinius/T3MP3ST/blob/29824d5625ede419ac8cdae418c8f4c72c6270f7/scripts/refusal-frontier.mjs) | Compare several framings of related synthetic tasks, sample repeatedly, and include benign controls instead of treating a single refusal as a security conclusion. | This experiment uses a model judge to classify response disposition. Its labels do not establish private disclosure, tool execution or unauthorized effects. A refusal map needs a declared task/policy oracle and benign utility measurement before it can support AgentScan security claims. |
| [Claim recomputation](https://github.com/elder-plinius/T3MP3ST/blob/29824d5625ede419ac8cdae418c8f4c72c6270f7/scripts/verify-claims.mjs) | Derive published counters from versioned artifacts; keep distinct metrics and contamination checks explicit. | The script itself says it checks internal artifact consistency, not an independent rerun or transcript audit. AgentScan should preserve source hashes and frozen manifests, but must not relabel authored controls as customer accuracy. |

No T3MP3ST benchmark, live exploit, model judge or repository script was executed
for this comparison. Its headline success rates were not independently verified
and are not transferable to AgentScan's different tasks or evidence criteria.

## The selected AgentScan improvement

The first implementation scope is the scanner's **captured-request redirect
credential boundary**. It applies the general execution-boundary lesson without
adding an offensive-tool orchestrator or a new model-based judge.

An approved redirect destination must not automatically receive credentials
belonging to the original request. A captured HTTP profile can contain private
custom headers in addition to ordinary Authorization/Cookie fields. Destination
enrollment and credential forwarding therefore require separate treatment.

Acceptance criteria for this scope are:

1. Inspect the actual captured-profile and client-merged request headers at the
   redirect boundary, including credentials outside standard header names.
2. Strip the relevant request credentials before a cross-origin hop. Preserve
   normal same-origin behavior and existing authorization, request-budget,
   response-size and redirect limits.
3. Reject an unenrolled hop before sending its request. Exercise destination and
   credential checks independently with intercepted HTTP requests.
4. Use synthetic header values; keep them out of errors, logs and public reports.
   Verify normal and captured HTTP paths and existing connector regressions.

The implemented shared HTTP path strips captured header names on origin changes,
then regenerates destination Host and body framing without reapplying client
defaults. Once a chain crosses origins, all later redirect requests suppress
Cookie, including same-origin continuations where HTTPX could otherwise restore
a source cookie from its jar. Same-origin-only chains retain their cookies.
This conservative policy also suppresses new destination cookies in the crossed
chain; it does not mutate the client's cookie jar or affect a fresh request.

The rule protects headers, not captured JSON bodies or query parameters. A
307/308 can still replay its body to an authorized destination. Sensitive captured
context therefore needs exact-origin enrollment or redirects disabled; see the
[data-policy boundary](../DATA_POLICY.md#http-redirect-credentials-and-assessment-scope).
Eighteen new synthetic controls and fourteen existing egress tests passed locally.
They exercise real request construction and HTTP/1.1 framing with intercepted
responses, not a live network. The final non-slow engineering suite passed
3,056 tests, with 32 skipped and eight slow tests excluded on 31 October 2026.
Ruff lint/format, mypy on 190 runtime files and the configured pre-commit hooks
passed. These checks do not measure model accuracy or defense benefit.
This comparison does not claim live-network containment, operating-system isolation
or real-agent efficacy. Verification details belong with the implementation's
completion record; live target assessments remain separately authorized work.

## Where AI boundary failures can occur

This map separates the agent under assessment from AgentScan's own operating
boundary. A failure in the scanner's credential handling is a scanner defect;
it must not be presented as a vulnerability discovered in the target AI.

| Boundary and question | AgentScan coverage already present | Evidence still required for a broader claim |
|---|---|---|
| User text to protected context: can instructions induce disclosure? | [ATK-001](../modules/prompt_injection.md), [ATK-002](../modules/jailbreak.md), [ATK-003](../modules/pii_exfiltration.md), [ATK-010](../modules/crescendo.md), [ATK-011](../modules/multilingual.md), [ATK-012](../modules/system_prompt_leak.md) and [ATK-027](../modules/model_theft.md) assess specified complete private references. | Independent representative agents, declared confidentiality policies and held-out positive/negative cases. Text disclosure does not prove arbitrary policy bypass, model theft, tenant escape or execution. |
| Retrieved content to trusted instructions: was adversarial data consumed and did it change an authorized result? | [ATK-005](../modules/indirect_injection.md) has an explicit document adapter; [ATK-008](../modules/rag_poisoning.md) includes separate owned retrieval evidence. | Genuine independent ingestion, authorization/effect witnesses and measured benign task utility. A receipt or suspicious document alone does not prove causal compromise. |
| Tool descriptions/proposals to actual authority: did a tool definition change or an unapproved action execute? | [ATK-006](../modules/mcp_shadow.md) compares an independently approved catalog; [ATK-013](../modules/excessive_agency.md) inventories proposals/status claims. | Independently approved action policies, approval events and observed effects. A changed catalog or a model saying it acted is insufficient. |
| Model output to a consumer: did text become executable browser/SQL behavior? | [ATK-007](../modules/output_handling.md) separates text indicators from optional trusted owned consumer witnesses. | Evidence at the real application consumer. Fixture findings do not establish a customer's execution boundary. |
| Answer text to a decision: did an answer violate a declared source/answer policy? | [ATK-009](../modules/overreliance.md) supports an approved exact-answer comparison. | A policy deviation does not establish general factual truth or downstream security harm; end-user decisions and effects require separate witnesses. |
| Work request to shared resources: did adversarial work deny legitimate service? | [ATK-004](../modules/dos.md) has finite observations and an optional owned work/admission witness. | Separately scoped serving-stack and concurrent-user measurements. Long text, client timing or errors alone do not prove denial of service. |
| Scanner authority to network effects: did AgentScan stay on approved targets and protect its credentials? | Core enrollment, exact-origin checks, DNS/IP pinning for selected service profiles, budgets and bounded responses. The selected redirect fix hardens one credential-forwarding path. | Host/deployment policy validation and explicit scope for any live assessment. Application checks do not establish that arbitrary external subprocesses or a target's own tools are contained. |

The [module matrix](../module_matrix.md) records per-module engineering status;
the [roadmap](../../ROADMAP.md) retains deferred work. Broader coverage should
add a supported boundary and an independent oracle, then complete its error,
privacy, reporting and evaluation paths. More payloads alone do not establish
that broader boundary.

## Reuse, privacy and follow-up

The inspected [LICENSE](https://github.com/elder-plinius/T3MP3ST/blob/29824d5625ede419ac8cdae418c8f4c72c6270f7/LICENSE)
is GNU AGPL version 3; the repository's package metadata declares
`AGPL-3.0-or-later`. AgentScan declares Apache-2.0. This work records concepts
and source attribution and makes an independent change to AgentScan; it does
not copy T3MP3ST source, prompts, datasets or benchmark outputs, add it as a
dependency, or change AgentScan's license. No legal compatibility conclusion is
implied.

Useful later investigations are artifact-derived metric validation, a frozen
paired benign/adversarial boundary matrix, and stronger source/effect witnesses
for ATK-013. These are follow-up candidates, not delivered features or permission
to run probes. Provider-backed refutation and response judging remain subject to
AgentScan's [data policy](../DATA_POLICY.md). Sensitive scans stay deterministic
or explicitly local; a provider key alone does not permit external processing.
