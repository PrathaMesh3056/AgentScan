# ATK-004: bounded resource-pressure observations

ATK-004 maps to **OWASP LLM10:2025 Unbounded Consumption**. Its default scan
sends nine finite chat prompts, sequentially, through a direct enrolled HTTP(S)
target. Captured request templates, browser and WebSocket transports are outside
this bounded profile. It observes response byte length, request/response hashes and
client elapsed time. Each request has a ten-second deadline, an 8 KiB probe-text
cap and a 64 KiB encoded-response cap, no retries or redirects, no mutation
expansion and no model judge.
The scan stops on the first transport error or unreadable/oversize response.

These default observations **do not establish denial of service**. Long or repetitive
output, a copied canary, a target-reported timeout and a client timeout cannot
show cross-user availability, server resource exhaustion or cost. Successful
responses also cannot prove resilience. ATK-004 therefore reports zero impact
findings and zero impact-evaluated tests by default, with an inconclusive module
outcome and no score for an ATK-004-only scan. Transport failures remain errors.
Only hashes, lengths and bounded timing enter observations; ATK-004 suppresses
raw target output in the scan trajectory and optional transcript.

An opt-in in-process `ResourceWitnessCollector` is available for a disposable
owned application. Its instrumentation must bind the exact application-observed
probe and response hashes to pre/post work counters, per-probe attributed work,
and actual neutral-task admission checks before and after the probe. A local
finding requires an approved work budget to be
exceeded **and** the neutral task to change from admitted to denied. Scanning
stops immediately on degradation or a budget breach. These local findings are
kept in `resource_findings` on the module outcome, outside customer findings,
score and SSP. A missing, malformed, stale or uncorrelated witness is inconclusive.
The Python integration is trusted by its operator; it is not remote attestation.

Run this module through an authorized normal SCAN target:

```powershell
agentscan scan http://127.0.0.1:8000/chat
```

That command runs the applicable SCAN modules, not ATK-004 alone. Choose a
disposable owned target when testing resource behavior. The ordinary scan's
target request budget still applies across modules. Check the ATK-004 module
outcome and its nine observation records; do not interpret a clean findings
list as an availability pass.

For a reproducible local contract check, run the [owned evaluation](../../benchmarks/evaluation/atk004_METHOD.md):

```powershell
python -m benchmarks.evaluation.atk004_run --output .test-tmp/atk004-owned-new
```

The authored fixture compares an output-capped service, an uncapped service
and a service that merely prints timeout words. A trusted application counter
and a separate neutral admission check distinguish actual synthetic availability
loss from response appearance. On 25 October 2026, the capped and text-spoof
arms each completed nine probes with no local finding. The uncapped arm crossed
the 4,000-unit budget at 4,620 units on its sixth probe; its neutral task was
denied, so ATK-004 recorded one separately scoped local finding and stopped.
The other arms used 1,728 and zero units and remained available. This validates
the evidence boundary in an authored fixture. It does not measure a real model,
serving scheduler, production agent or customer DoS resistance.

Current research motivates keeping resource and availability evidence
separate. [OWASP LLM10:2025](https://genai.owasp.org/llmrisk/llm102025-unbounded-consumption/)
recommends input, output, request and queue limits. The published
[AgentDoS study (USENIX Security 2026)](https://www.usenix.org/conference/usenixsecurity26/presentation/luo)
distinguishes per-turn, per-session and persistent resource lifecycles; this
module's owned witness covers only its declared cumulative-work fixture.
[ThinkTrap (NDSS 2026)](https://www.ndss-symposium.org/wp-content/uploads/2026-f639-paper.pdf)
demonstrates that low request rates alone need not bound inference work.
[Wang et al., 2026,
*Rethinking Latency Denial-of-Service*](https://arxiv.org/abs/2602.07878)
show that serving-scheduler behavior can determine whether costly generation
affects other users, so output length alone is not enough. [*From Shield to
Target*, 2026](https://arxiv.org/abs/2606.14517) reports a different guardrail
reasoning-loop surface. Those attack classes need a separately authorized,
instrumented environment with trusted resource/neutral-traffic measurements;
the default ATK-004 probes do not claim to reproduce them.
