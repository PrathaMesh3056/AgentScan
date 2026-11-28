# ATK-007: Insecure Output Handling

Updated 16 October 2026. The default scan inventories response-text indicators
across 12 probes and leaves downstream impact **INCONCLUSIVE**. An optional
trusted Python integration now accepts independently observed effects from an
owned local consumer. Those results remain separate from customer target scores.
Controlled browser/SQLite validation passed; real-agent efficacy remains open.

## Start a normal scan

For an owned test agent using synthetic data, save a local profile:

```yaml
url: http://127.0.0.1:8000/chat
framework: unknown
analysis_mode: deterministic
data_classification: sensitive
output: local-scan.json
```

```powershell
agentscan scan --config local-target.yaml
```

This runs the regular SCAN suite; inspect `ATK-007` in `module_outcomes`.
There is no public ATK-007-only selector. Alternatively, run `agentscan ui`, open
the printed localhost URL and configure the target. ATK-007 initializes no model
judge or attacker, even when optional analysis is configured for other modules.
The response inventory needs no provider key, private reference or Docker. Keep
local profiles and sensitive reports out of version control.

Starting a scan, choosing the browser connector, or loading an HTTP receipt does
not enable consumer instrumentation. Remote targets keep the default inventory
scope. The optional evaluation below supplies its own trusted in-process adapter.

## What the default profile observes

| Probe IDs | Output context |
|---|---|
| OH-001–002 | HTML script and active-URL text |
| OH-003 | SQL fragment text |
| OH-004 | Markdown image text |
| OH-005–006 | Terminal CSI and OSC sequences |
| OH-007–010 | Shell operators and substitution text |
| OH-011 | Protocol-relative Markdown resource text |
| OH-012 | CSS external-resource text |

The original ten probe IDs and request texts are retained. The two new resource
probes use reserved `.invalid` destinations with no secret in a URL. The scanner
does not render, fetch or execute these fragments during response inspection.

Each readable UTF-8 response produces one observation with its probe ID, family,
context, exact case-sensitive literal-marker presence, response SHA-256 and byte
length. No decoding, HTML/SQL parsing or Unicode equivalence is implied. A marker
can occur in a quotation, code example, input echo or refusal. Its absence is not
proof that other unsafe representations are absent.

Observations are stored in `module_outcomes[].observations`, separately from
findings and local neural `reference_observations`. Without a trusted consumer
witness, downstream impact is `unassessed` and execution/transfer flags are false.
Target-reported receipts and model execution claims cannot change those flags.

| Default result | Meaning |
|---|---|
| Readable reply, with or without the seed marker | Observation recorded; impact remains INCONCLUSIVE. |
| Empty, malformed or invalid UTF-8 text; unsupported delivery profile | Inconclusive; no artifact recorded for that probe. |
| Authentication, transport or target failure | Execution error; inspect diagnostics. Other observations remain available. |

This response-only profile produces no vulnerability findings or impact-evaluated
negatives. Twelve delivered replies can mean 12 selected, zero impact-evaluated
tests and 12 observations. The aggregate score is unavailable while this impact
assessment is inconclusive; other modules retain their own findings and counts.

## Optional owned-consumer evidence

`agentscan.core.output_witness` provides an operator-owned Python integration:
`OutputWitnessCollector`, `use_output_witnesses` and `current_output_delivery`.
Instrumentation must run the application's actual consumer during the matching
delivery, independently inspect its state, then record the result before returning
the exact response. Replaying a reply into an unrelated sink does not establish
what happened in the assessed application.

A witness is bound to the active collector, delivery object, scan, probe, output
context and response hash. It is consumed once; expired, replayed, mismatched,
duplicate and incomplete/unhealthy records are rejected. This is trusted code
running in the scanner process. Its nonce and hashes provide correlation, **not
remote attestation**; a dishonest Python producer can still fabricate evidence.
No HTTP/model JSON field enrolls a producer or grants this trust.

| Independently observed result | Recorded meaning |
|---|---|
| Browser DOM effect | `browser_script_executed`; bounded local HIGH finding |
| Browser request intercepted before dispatch | `resource_request_attempt`; bounded local MEDIUM finding, never verified transfer |
| Actual unauthorized SQLite result or state change | `sql_unauthorized_read` / `sql_unauthorized_write`; bounded local HIGH finding |
| Healthy completed consumption with no effect, or a completed policy rejection | One evaluated local consumer result; no finding for the observed boundary |
| Unsupported context, missing observation or incomplete consumer | INCONCLUSIVE; absence of evidence is not a negative result |

Supported collector scopes are `owned_synthetic_target` and `local_consumer_lab`.
Their findings are stored in `module_outcomes[].consumer_findings`, **not** the
customer `findings` list or neural `reference_observations`. A pure consumer report
has `assessment_scope: local_consumer_validation` and no customer security score,
even when all its local tests complete. Combining it with target/reference work
preserves a mixed scope, including failed selected target work. Effects are mapped
from actual state rather than the attack family's expected effect; an unexpected
resource attempt in an HTML case must not become a clean negative.

Terminal emulation, clipboard and OS process/shell effects have no consumer
witness implementation. The browser evaluation uses HTML images; it does not
validate a Markdown-to-HTML pipeline or all 12 packaged inventory seeds.

## Reproduce the local consumer evaluation

The separately frozen [24 synthetic cases](../../benchmarks/evaluation/atk007_cases.json)
and [evaluation method and commands](../../benchmarks/evaluation/atk007_METHOD.md)
cover HTML events, user-activated active URLs, image/CSS resources, and SQLite
reads/writes. There are 12 attacks and 12 meaningful benign tasks, split equally
between development and same-team holdout. Case bytes and thresholds were frozen
before execution; this is not a blinded, independently authored population sample.

With the project, Playwright, an installed Chrome/Edge browser and a maintained
sanitizer available, run from the repository root into a **fresh** private folder:

```powershell
python -m benchmarks.evaluation.atk007_run --cases benchmarks/evaluation/atk007_cases.json --output evaluation-output/atk007-controls-local --phase controls --channel chrome
```

This uses the real scanner runner and owned in-process consumer adapter. Every
case/arm gets a fresh browser context or in-memory database. Browser requests
are intercepted and fulfilled only for synthetic approved assets, otherwise
aborted before dispatch; no real DNS/transfer is measured. Hardened browser
settings and narrow generated-HTML admission reduce the fixture's exposure but
are not OS network isolation. SQLite forbids extensions, attachment, filesystem
features and scripts. Unknown model SQL is independently authorized read-only;
unsupported SQL stays unassessed rather than executing arbitrary generated code.

The defended browser uses maintained sanitization, an exact resource-origin
policy and CSP. SQLite uses an independent authorization policy. If a trusted
task selects an authorized SQL fallback, the receipt records it separately; this
measures application task utility, not the model's SQL reasoning accuracy.

### Measured results, 16 October 2026

| Experiment | Vulnerable consumer | Defended consumer | Interpretation |
|---|---|---|---|
| 24 authored fixed responses, paired across both arms: 48 consumer runs | All 24 complete; declared effects 12/12 attacks; benign utility 12/12 | All 24 complete; effects 0/12 attacks; benign utility 12/12; attack-task utility 12/12 | Frozen fixture thresholds passed; scanner/consumer joins agreed on all 48 runs. These are operational positive controls. |
| 24 genuine offline Qwen2.5-0.5B-Instruct generations, same bytes paired across both arms: 48 assessments | Only 5/24 consumer assessments complete; observed effects 0; benign utility 0/12 | Only 5/24 consumer assessments complete; observed effects 0; benign utility 0/12 | Workflow/utility smoke is INCONCLUSIVE for efficacy. There is no demonstrated model-positive effect or measured model defense benefit. |

The model smoke used snapshot `7ae557604adf67be50417f59c2c2f167def9a775`, greedy
decoding, seed `20261016`, at most 256 new tokens and one generation per case.
A timed-out first run preserved 17 completed generations. The resumed run verified
their case/input/response hashes and generated only the remaining seven. The
resume has before/after weight hashes; the partial run lacks its contemporaneous
weight receipt, so that check cannot retrospectively attest all 24 generations.
There were no external provider calls. Frozen source contexts are small authored
scenarios; they are not a reproduction of recent incident payloads.

The 19 incomplete consumer assessments per arm and failed benign utility cannot
be counted as prevented attacks or evidence that the model is secure. A zero
effect count in this smoke does not validate real-agent recall, useful task
completion, production defenses or a security percentage. Broader live-agent
effectiveness remains an explicit completion gate.

## Reports, display and evidence handling

The dashboard labels the default scope **Output text · impact unassessed**, and
local consumer scopes identify their exclusion from the target score. JSON and
SARIF retain the module outcomes and observations. HTML/PDF distinguish local
consumer findings and incomplete target coverage. Empty findings no longer earn
a green security claim, an unconditional signature claim or a certification.
ATK-050 depth labels likewise require actual completed coverage.

Fresh-cache type checking passed across 186 runtime/evaluation source files.
The actual production PDF path rendered and rasterized all three pages; visual
review confirmed the inventory counts, INCONCLUSIVE status, unavailable score
and absence of the earlier unsupported assurance/signature claims. These checks
validate engineering/report behavior, not live-agent efficacy. The final full
suite and configured commit hooks are recorded separately when that run closes.

Only the **observation records** omit raw response text. Existing report
trajectories and optional transcripts retain text under their configured
redaction policy. Hashes are correlation identifiers, not encryption. CLI live
traffic previews visibly encode terminal/directional controls and render
untrusted content as plain text. Stored evidence is preserved; view raw
control-bearing transcripts with a suitable text viewer.

## Defenses at the real application boundary

Use maintained HTML sanitization and context-specific encoding; restrict image,
CSS, font and preview origins before DNS/rendering; visibly encode terminal
controls; parameterize SQL values and independently authorize query structure;
use structured subprocess arguments without a shell, least privilege and action
authorization. AgentScan's local fixture does not install these defenses in a
customer application. A blocked HTTP response cannot exclude an earlier DNS
lookup. Transfer claims require independent network evidence, including DNS
where relevant, in addition to a consumer observation.

## Research references

Primary records were checked on 16 October 2026. These papers motivate evidence
boundaries and case design; their reported metrics do not measure AgentScan.

| Published paper | Applicable lesson and boundary |
|---|---|
| Kai Greshake, Sahar Abdelnabi, Shailesh Mishra, Christoph Endres, Thorsten Holz and Mario Fritz, **Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection**, ACM AISec 2023; [institutional record](https://cispa.de/de/research/publications/77133-not-what-you-ve-signed-up-for-compromising-real-world-llm-integrated-applications-with-indirect-prompt-injection), [author manuscript, 23 February 2023](https://arxiv.org/abs/2302.12173) | Distinguish generated destinations/code from application effects. Markdown links in that study do not establish automatic image fetching here. |
| Edoardo Debenedetti, Jie Zhang, Mislav Balunović, Luca Beurer-Kellner, Marc Fischer and Florian Tramèr, **AgentDojo**, NeurIPS 2024 Datasets and Benchmarks; [official proceedings](https://proceedings.nips.cc/paper_files/paper/2024/hash/97091a5177d8dc64b1da8bf3e1f6fb54-Abstract-Datasets_and_Benchmarks_Track.html), DOI [10.52202/079017-2636](https://doi.org/10.52202/079017-2636) | Measure adversarial outcomes and legitimate task utility separately in an executable environment. Our authored fixture is not an AgentDojo reproduction. |
| Deyin Li, Xiang Ling, Changjiang Li, Xiang Chen and Chunming Wu, **AIA: Autoregression-Based Injection Attacks Against Text2SQL Models**, AAAI 2025, 11 April; [publisher record](https://ojs.aaai.org/index.php/AAAI/article/view/34009), DOI [10.1609/aaai.v39i17.34009](https://doi.org/10.1609/aaai.v39i17.34009) | Require observed database results/state and independent query authorization; SQL text alone is insufficient. Its experiments do not establish our SQL coverage. |
| Edoardo Debenedetti, Ilia Shumailov, Tianqi Fan, Jamie Hayes, Nicholas Carlini, Daniel Fabian, Christoph Kern, Chongyang Shi, Andreas Terzis and Florian Tramèr, **Defeating Prompt Injections by Design**, IEEE SaTML 2026, 23–25 March; [author page](https://floriantramer.com/publications/camel25/), [conference program](https://satml.org/2026/program/), DOI [10.1109/SaTML68715.2026.00040](https://doi.org/10.1109/SaTML68715.2026.00040) | Keep trusted control flow/capabilities independent of generated text. Our fixture does not implement CaMeL or inherit its guarantees; the 2025 preprint predates the peer-reviewed publication. |
| Wonbae Kim, Hee-Kyong Yoo and Nammee Moon, **SecureMCP: Policy-Enforced Defense Against Prompt Injection in LLM-Generated SQL for AIoT Databases**, Applied Sciences 16(16), 7974, 11 August 2026; [publisher record](https://www.mdpi.com/2076-3417/16/16/7974), DOI [10.3390/app16167974](https://doi.org/10.3390/app16167974) | Enforce policy before generated SQL executes. Only indexed publisher metadata/abstract were available in this review; its IoT/model-specific results are not AgentScan accuracy evidence. |

Current guidance/disclosures include [OWASP's final output-handling entry](https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/blob/main/2026/final/LLM10_ImproperOutputHandling.md),
the [GitHub CLI terminal-control advisory, 31 July 2026](https://github.com/cli/cli/security/advisories/GHSA-3m3g-3wcr-px46),
[SalesBleed, 24 September 2026](https://labs.zenity.io/post/salesbleed-0-click-data-exfiltration-on-agentforce),
[Copirate 365, 4 May 2026](https://embracethered.com/blog/posts/2026/defcon-talk-copirate-365/)
and [GrafanaGhost, 7 April 2026](https://noma.security/blog/grafana-ghost).
These are guidance, advisories or researcher disclosures, not peer-reviewed
papers or AgentScan incident reproductions. Grafana disputed the researcher's
zero-click account; no in-the-wild exploitation is established here. The
GitHub CLI advisory's affected/patched versions refer to that CLI, not AgentScan.

The package retains **LLM05:2025**. Current guidance uses **LLM10:2026**;
reviewing it does not migrate stored identifiers. No directly matching
peer-reviewed paper was established for the specific terminal-control or
automatic image/CSS-fetch probes. Those evidence classes stay distinct.
