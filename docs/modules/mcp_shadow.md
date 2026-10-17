# ATK-006: MCP Shadow Server

Updated 17 October 2026. ATK-006 separates response observations from a bounded
comparison of a real MCP server's advertised tool catalog against an
operator-approved baseline. Neither profile establishes downstream tool
execution, successful impersonation or data transfer. No model judge is used.

## Choose the evidence profile

| Profile | Input and delivery | Result |
| --- | --- | --- |
| Default response inventory | Eight retained user-message probes to a chat-capable target | Hashed target-reported proposal observations; impact remains INCONCLUSIVE. Native MCP targets without a baseline are not probed by ATK-006. |
| Optional MCP catalog policy | An MCP connector's initialized, paginated tool catalog plus an independently approved baseline | One catalog comparison; complete deviations produce bounded MEDIUM catalog-policy findings. |

The eight probe IDs and request texts are retained. They cover endpoint migration,
typosquatted tool names, configuration blobs, callback URLs and fake rename or
backup notices. Sending these as user messages does not install a server, inject
tool metadata through `tools/list`, change a client's configuration, or perform
a post-approval rug pull.

## Run the default profile

For an owned synthetic target, save a private local `target.yaml` profile:

```yaml
url: http://127.0.0.1:8000/chat
analysis_mode: deterministic
data_classification: sensitive
output: local-scan-report.json
```

```powershell
agentscan scan --config target.yaml
```

This launches the regular SCAN suite. Inspect the `ATK-006` entry in
`module_outcomes`; there is no public module-only CLI selector. In the dashboard,
run `agentscan ui`, open its printed localhost URL and configure the separate
target application. No MCP baseline means the response-inventory profile.

A native MCP endpoint without an approved baseline is unavailable to ATK-006's
chat-probe profile; it does not guess the first exposed tool is a chat interface.
Other modules in the ordinary nonbaseline suite keep their existing behavior.

Readable replies produce digest-only observations with the probe identity and
bounded indicator/proposal information. A quoted hostname, refusal, example call,
structured proposal, or target-supplied execution receipt is not an independent
execution trace. Missing indicators do not establish resistance. The module
records these observations without producing an execution vulnerability finding
or counting them as impact-evaluated negatives. Authentication and transport
failures remain execution errors rather than clean results.

ATK-006 does not initialize a judge or attacker even if other selected modules
have optional analysis configured. This module needs no provider key, private
reference or Docker. The repository ignores `target.yaml` and the example
`*report*.json` outputs. Keep local target profiles and transcripts out of Git.

## Compare an approved MCP catalog

Set `Target.mcp_inventory_baseline` in a local target profile or Python SDK target.
Use the exact MCP endpoint already selected by the operator:

```yaml
url: mcp+sses://owned-agent.example/mcp
analysis_mode: deterministic
data_classification: sensitive
mcp_inventory_baseline:
  algorithm: mcp-tool-json-sha256-v1
  endpoint: mcp+sses://owned-agent.example/mcp
  tools: {}
output: local-mcp-catalog-report.json
```

The example deliberately approves **no tools**. Every advertised tool is therefore
unexpected. It is not a ready-made approval profile for a working server. Replace
`tools` with the exact reviewed tool names and their complete-definition SHA-256
digests when approving a real catalog. A missing baseline (`null` or omitted) is
different from the explicitly approved empty catalog (`tools: {}`).

The algorithm fingerprints each entire advertised JSON tool definition, including
the description, input/output schemas, annotations and additional fields. Review
the server's identity and implementation, exact tool names, schemas, descriptions
and allowed effects before recording hashes. Do not approve the first response
automatically. A hash detects byte-representation changes under the documented
canonicalization; it does not authenticate a publisher or make metadata safe.
Tool-array order is not an identity; definition changes remain significant.

After independently reviewing a complete tool definition, calculate its digest
with the shared helper; do not hash only its name or description:

```python
from agentscan.core.mcp_inventory import fingerprint_mcp_tool

reviewed_tool = {
    "name": "approved_lookup",
    "description": "Read an approved synthetic record.",
    "inputSchema": {"type": "object", "additionalProperties": False},
}
print(fingerprint_mcp_tool(reviewed_tool))
```

This sample definition does not approve any real server. Substitute the complete,
independently reviewed JSON definition, including every additional field the
server actually advertises. Canonicalization uses sorted object keys,
`ensure_ascii=True`, compact separators `(',', ':')`, `allow_nan=False`, UTF-8
and SHA-256. JSON object ordering is ignored; values and array ordering remain
significant.

The connector's actual initialized catalog is used. A chat reply containing a
`tools` array, an arbitrary response receipt, or the scanner's wrapper `tools/call`
is not a replacement for discovery. `serverInfo.name` is self-reported and is not
an identity anchor. Tool names are exact and case-sensitive; a substring or
similarly spelled alias does not approve a different tool.

| Complete comparison | Meaning |
| --- | --- |
| Advertised tool absent from the approved map | Unexpected catalog entry; bounded MEDIUM policy finding. |
| Approved name with a different full-definition hash | Metadata/schema drift from the reviewed definition; bounded MEDIUM policy finding. |
| Approved tool absent from the complete catalog | Missing approved entry; bounded MEDIUM policy finding. |
| All approved names and definitions match | One evaluated catalog-policy comparison; no observed deviation in this snapshot. |
| Duplicate/malformed entries, incomplete pagination or missing discovery support | INCONCLUSIVE; no clean catalog comparison. |
| Baseline endpoint differs from selected endpoint | Field validation failure; defensive runtime checks remain inconclusive if validation was bypassed. |

One finding aggregates catalog deviations, with bounded metadata and total counts.
This is **one catalog comparison, not eight evaluated attacks**. Its assessment
scope is `mcp_catalog_policy`. The report score and SSP behavioral classification
stay unavailable (`null`), even for a complete matching catalog. Catalog deviations
are stored in
`module_outcomes[].catalog_findings` with `catalog_finding_count`; they do not enter
the general `report.findings` list or an overall agent-security score.
A clean snapshot does not prove metadata stayed
unchanged afterwards, that approved code is benign, or that an agent resisted a
prompt injection. A changed description can be legitimate; the finding identifies
a deviation needing review, not malicious intent.

Setting a non-null `mcp_inventory_baseline` deliberately selects a **catalog-only
SCAN** in the CLI, Python SDK and local dashboard: only ATK-006 is selected, and
it does not send `tools/call`. It is not a generic attack-selection option.
The baseline requires SCAN mode, `analysis_mode: deterministic` and an MCP
endpoint; local/external model analysis, browser and captured-request profiles
cannot be combined with it. Without a baseline, the ordinary suite may
select other modules that invoke target tools. The tenant service's
HTTP-only target policy is unchanged; local MCP support does not enable arbitrary
MCP subprocess targets in that service.

Discovery initializes the selected server, follows bounded catalog pagination
and can list advertised resources. With a stdio connector, initialization starts
the operator-selected local server program. Catalog-only selection does not
establish that starting an untrusted executable has no side effects.
The Python SDK's `request_budget`, when configured, limits logical MCP JSON-RPC requests and
notifications, including initialization and catalog pages. It is not a hard cap
on physical HTTP requests: transport fallback, bounded stream resumption and
session cleanup can require additional HTTP traffic. This profile does not
perform load testing or evaluate session-exhaustion resistance.

The same explicit empty-catalog policy can be constructed through the Python SDK:

```python
import asyncio

from agentscan.core.models import Target
from agentscan.core.runner import run_scan

endpoint = "mcp+sses://owned-agent.example/mcp"
target = Target(
    url=endpoint,
    analysis_mode="deterministic",
    mcp_inventory_baseline={
        "algorithm": "mcp-tool-json-sha256-v1",
        "endpoint": endpoint,
        "tools": {},  # Approves no tools; populate only after independent review.
    },
)
report = asyncio.run(run_scan(target))
print(report.model_dump_json(indent=2))
```

Use an endpoint you own or are authorized to inspect, with matching locally
configured authentication. The placeholder endpoint is not a public test service.

## Dashboard setup and validation

The scan form's optional **MCP inventory baseline** accepts the same JSON object
as the YAML `mcp_inventory_baseline` value. Enter `algorithm`, the exact enrolled
`endpoint`, and the reviewed `tools` digest map. Empty text omits the baseline;
an explicit object with an empty `tools` map approves an empty catalog.
Malformed JSON, unsupported algorithms, invalid digest values, endpoint
mismatches and incompatible mode/analysis settings are field errors, not
assessment results. Baselines allow at most
1,000 exact ASCII tool names (1–128 characters using letters, digits, `_`, `-`
or `.`), each mapped to a 64-character lowercase hexadecimal SHA-256 digest.
Unknown baseline fields are rejected. A saved baseline is an
operator approval artifact; review it before reusing it on another endpoint.

## Research and defense references

Initial sources checked on 16 October 2026. Published-paper metadata and SDK
guidance were rechecked on 17 October; the two recent reports below were checked
on 17 October.

- [MCP Tools specification, 2026-07-28](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/specification/2026-07-28/server/tools.mdx)
  defines per-server tool-name uniqueness and treats annotations as untrusted
  without a trusted source. [Official SDK migration guidance](https://ts.sdk.modelcontextprotocol.io/v2/migration/support-2026-07-28)
  also treats `serverInfo` as self-reported information, not a security identity.
- [Invariant Labs' original disclosure, 1 April 2025](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)
  demonstrates tool-description poisoning, changed descriptions after approval,
  and cross-server shadowing. These are controlled demonstrations, not proof
  that ATK-006 reproduces those metadata-delivery mechanisms.
- [Microsoft's original research, 30 June 2026](https://www.microsoft.com/en-us/security/blog/2026/06/30/securing-ai-agents-ai-tools-move-from-reading-acting/)
  describes metadata updates, silent re-trust and unauthorized forwarding through
  an approved integration. It provides an observed attack-pattern account without
  naming a compromised customer. Review metadata changes and constrain actual
  arguments, destinations and data flows at the host boundary.
- [Pillar Security / Ariel Fogel's Deadbugz disclosure, 12 August 2026](https://www.pillar.security/blog/deadbugz-currently-active-mcp-supply-chain-campaign)
  reports a 10 August delivery campaign with metadata changes gated behind three
  tool calls. ATK-006's discovery-only snapshot does not exercise delayed triggers.
  The reported unmerged delivery PRs do not establish successful victim compromise.
- [Upstream memory-server issue #5058, opened 6 October 2026](https://github.com/modelcontextprotocol/servers/issues/5058)
  reports destructive behavior despite non-destructive annotations. It remained
  an open behavior report when checked, not a verified released fix. Matching an
  unchanged metadata hash does not validate implementation behavior or safety hints.
- **Zhiqiang Wang, Yichao Gao, Yanting Wang, Suyuan Liu, Haifeng Sun, Haoran Cheng,
  Guanquan Shi, Haohua Du and Xiangyang Li.** *MCPTox: A Benchmark for Tool Poisoning
  on Real-World MCP Servers*. AAAI **40(42), 35811–35819**, **14 March 2026**.
  Peer-reviewed [publication and DOI: 10.1609/aaai.v40i42.40895](https://ojs.aaai.org/index.php/AAAI/article/view/40895).
  Its registration-stage threat model motivates catalog checks; its attack rates
  are not AgentScan measurements.
- **Wenpeng Xing, Zhonghao Qi, Yupeng Qin, Yilin Li, Caini Chang, Jiahui Yu,
  Changting Lin, Zhenzhen Xie and Meng Han.** *MCP-Guard: A Multi-Stage Defense-in-Depth
  Framework for Securing Model Context Protocol in Agentic AI*. Findings of ACL
  **2026, 4877–4889**, **July 2026**. Peer-reviewed
  [publication and DOI: 10.18653/v1/2026.findings-acl.240](https://aclanthology.org/2026.findings-acl.240/).
  Layered defense research informs the design; its trained classifier and model
  arbitration results do not validate this deterministic module.

Pin and review server origins, executable/package provenance, tool identity and
metadata together. Require reapproval of meaningful changes, enforce allowed
arguments and network destinations, and preserve legitimate task utility in
testing. Tool annotation hints and prompt wording do not provide these controls.

## Validation and remaining limits

Local verification on 17 October 2026 passed **2,189 repository tests**, with
32 skipped and eight slow tests excluded. Four actual CLI process cases covered
matching, changed, malformed and invalid catalogs; their method journals confirmed
discovery without `tools/call`. JSON, HTML and SARIF retain the policy scope and
unavailable security/behavioral verdicts. A real local Chrome check verified
separate catalog details and inline validation with no scan dispatch on invalid
input. These engineering checks do not measure real-agent attack resistance.
No live provider calls or customer-target reproduction are claimed.

The existing connector negotiates protocol revisions through **2025-06-18**.
The latest **2026-07-28** specification informs this review but is not implemented
by adding this module profile. Metadata injection into an agent's actual catalog,
post-approval refresh/rug-pull behavior, authenticated multi-server routing,
downstream effects, and independent real-agent efficacy remain unverified.
Response-inventory records and catalog-policy results must remain distinguishable
from those future execution-based evaluations.
