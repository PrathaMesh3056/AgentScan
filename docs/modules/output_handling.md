# ATK-007: Insecure Output Handling

Updated 16 October 2026. This module inventories response-text indicators across
12 probes. It does **not** establish browser, terminal, SQL, shell or network
effects. Its engineering update is implemented; consumer-backed and live-model
evaluation remain pending.

## Start a scan

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
It needs no provider key, confidential reference or Docker. Keep local profiles
and sensitive reports out of version control.

## What is observed

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
does not render, fetch or execute these fragments during inspection.

Each readable UTF-8 response produces one observation with its probe ID, family,
context, exact case-sensitive literal-marker presence, response SHA-256 and byte
length. No decoding, HTML/SQL parsing or Unicode equivalence is implied. A marker
can occur in a quotation, code example, input echo or refusal. Its absence is not
proof that other unsafe representations are absent.

Observations are stored in `module_outcomes[].observations`, separately from
findings and local neural `reference_observations`. Their downstream-impact
field is `unassessed`; browser, tool and transfer verification flags are false.
Target-reported receipts and model execution claims cannot change those flags.

## Interpret results

| Result | Meaning |
|---|---|
| Readable reply, with or without the seed marker | Observation recorded; impact remains INCONCLUSIVE. |
| Empty, malformed or invalid UTF-8 text; unsupported delivery profile | Inconclusive; no artifact recorded for that probe. |
| Authentication, transport or target failure | Execution error; inspect diagnostics. Other completed observations remain available. |

No vulnerability finding or impact-evaluated negative is produced by this
response-only profile. Twelve delivered replies can therefore mean 12 selected,
zero impact-evaluated tests and 12 observations. Those counts describe different
things. The aggregate score remains unavailable while this impact assessment is
inconclusive; other modules retain their own findings and evaluated counts.

The dashboard's module table labels this scope **Output text · impact unassessed**
and shows the observation count in its reason. JSON and SARIF retain the structured
observations; HTML reports show the scope, count and limitation. PDF uses the
HTML template, but its optional rendering runtime was not verified here.

Only the **observation records** omit raw response text. Existing report
trajectories and optional transcripts still retain text under their configured
redaction policy. Hashes are correlation identifiers, not encryption or execution
attestation. AgentScan's CLI live traffic preview now visibly encodes terminal and
directional controls and renders untrusted content as plain text. Stored evidence
is preserved; use a suitable text viewer for raw transcripts rather than sending
control-bearing files directly to an interpreting terminal.

## Defenses and evidence needed

Apply controls at the actual consumer: maintained HTML sanitization and
context-specific encoding; restricted image/CSS/font/preview resource origins
before DNS or rendering; visible terminal-control encoding; parameterized SQL
values plus independent query-structure authorization; structured subprocess
arguments without a shell, least privilege and action authorization.

These are target recommendations. The module does not install target defenses.
A parameterized value does not authorize arbitrary model-generated SQL. A blocked
HTTP response does not exclude an earlier DNS lookup. Rendering, execution or
transfer claims need independently correlated consumer/network/state evidence,
separate from model text and target-provided receipts.

## Research references

Primary publication records were checked on 16 October 2026. These papers inform
the evidence boundary and future evaluation design; their results do not measure
AgentScan's accuracy or certify its implementation.

| Published paper | Applicable lesson and boundary |
|---|---|
| Greshake et al., [indirect injection in integrated applications](https://arxiv.org/abs/2302.12173), ACM AISec 2023 ([institutional publication record](https://cispa.de/de/research/publications/77133-not-what-you-ve-signed-up-for-compromising-real-world-llm-integrated-applications-with-indirect-prompt-injection)) | Separate generated links/code from effects in the consuming application. Its link demonstrations do not establish automatic image fetching. |
| Debenedetti et al., [AgentDojo](https://proceedings.nips.cc/paper_files/paper/2024/hash/97091a5177d8dc64b1da8bf3e1f6fb54-Abstract-Datasets_and_Benchmarks_Track.html), NeurIPS 2024 | Measure adversarial outcomes and legitimate task utility separately in an executable environment. This inventory is not that evaluation. |
| Li et al., [AIA: Autoregression-Based Injection Attacks Against Text2SQL Models](https://ojs.aaai.org/index.php/AAAI/article/view/34009), AAAI 2025, published 11 April | Database effects require an observed database boundary. Its results do not establish our SQL coverage. |
| Debenedetti et al., [Defeating Prompt Injections by Design](https://floriantramer.com/publications/camel25/), IEEE SaTML 2026 ([conference program](https://satml.org/2026/program/)) | CaMeL separates trusted control flow and enforces capabilities. We have not implemented its architecture or inherited its guarantees. Its 2025 arXiv copy is an earlier manuscript. |
| Kim et al., [SecureMCP](https://www.mdpi.com/2076-3417/16/16/7974), Applied Sciences, 11 August 2026, DOI 10.3390/app16167974 | Policy checks belong before generated SQL executes. Its specific IoT/model study is not general accuracy evidence; only publisher metadata/abstract were available for this review. |

Current guidance also includes [OWASP's final output-handling entry](https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/blob/main/2026/final/LLM10_ImproperOutputHandling.md),
the [GitHub CLI terminal-control advisory, 31 July 2026](https://github.com/cli/cli/security/advisories/GHSA-3m3g-3wcr-px46),
[Copirate 365 research, 4 May 2026](https://embracethered.com/blog/posts/2026/defcon-talk-copirate-365/)
and [GrafanaGhost research, 7 April 2026](https://noma.security/blog/grafana-ghost).
These are guidance/advisory/disclosure sources, not peer-reviewed papers or
AgentScan reproductions. Grafana disputed the researcher's zero-click account;
no in-the-wild exploitation is established here. OH-011 and OH-012 are analogous
resource-channel probes rather than copies of those demonstrations.

The package retains its explicit **LLM05:2025** mapping. Current guidance calls
output handling **LLM10:2026**; reviewing it does not migrate other module IDs.
This review found no directly matching peer-reviewed paper for the specific
terminal-control or automatic image/CSS-fetch probes. Those evidence classes
remain distinct. Real-consumer positives, matched defenses, benign utility and
held-out live-model effectiveness remain deferred validation gates.
