# ATK-004 owned availability-witness control, v1

Frozen 25 October 2026 for the nine `DOS-001` through `DOS-009` seeds. The
script rejects a changed seed-ID sequence and verifies the exact request
digests/order. Its three arms are authored synthetic applications, not models
or independently authored adversarial targets. All HTTP traffic is handled by
an in-process `respx` fixture at a loopback-shaped URL; no socket request is
sent to a remote target. No provider key, model weights or customer data is
used. The only output artifacts contain hashes, byte counts, trusted work
units, admission booleans and scanner status. A fresh output directory is
required.

The trusted fixture defines a 4,000-unit work budget. The `bounded` arm caps
each synthetic output at 192 bytes; the `unbounded` arm returns the same
770-byte synthetic text for each probe. A third arm returns the words "timed
out" in an HTTP 200 body while charging no work. Each probe executes a neutral
request through the application's handler immediately before and after its
work. Additional HTTP neutral checks run before and after each scan. A neutral
request is admitted only if the fixture's
internal spent units remain below budget. The scanner cannot read those
trusted counters through the target response: an in-process witness binds the
application-observed probe/response digests to pre/post counters, attributed
work and pre/post neutral admission state. A digest labels a local receipt; it
does not authenticate instrumentation. The fixture has no concurrent work.
This is an intentionally simple admission rule, not a
real serving scheduler, throughput measure or economic-cost model.

Each arm runs the real `DosModule` through AgentScan's `run_scan`, HTTP JSON
connector and outcome ledger with deterministic sensitive analysis, one
concurrent target request and an exact nine-request budget. The contract gate
requires the expected probe prefix in order, nine selected, no customer
findings/score, an initially admitted neutral request, and different post-scan
admission for capped versus uncapped output. The local unbounded arm must yield
one separately scoped resource finding and stop on degradation.
The timeout-text arm must remain available. Any failure exits nonzero.

The observed authored-control run produced 24 scanner requests: nine in each
bounded/spoof arm, six in the uncapped arm. Internal work was 1,728, 4,620 and
0 units, respectively. Only the uncapped arm lost neutral admission and yielded
one local resource finding; the scanner stopped without sending the remaining
three probes. These results validate the
scanner's evidence separation and a local application's cap behavior. They
**do not** establish attack success, sensitivity, specificity, false-positive
rate or defense benefit on real agents. An independent production-grade
evaluation would need an owned instrumented serving stack, benign concurrent
traffic, repeated baseline/stress trials, declared throughput/latency and cost
or resource metrics, known cleanup, and explicit operator-approved load limits.

```powershell
python -m benchmarks.evaluation.atk004_run --output .test-tmp/atk004-owned-new
python -m pytest tests/test_atk004_evaluation.py -q
```

Evidence rationale: [OWASP LLM10:2025](https://genai.owasp.org/llmrisk/llm102025-unbounded-consumption/)
defines unbounded consumption and recommends resource controls. The
[AgentDoS paper (USENIX Security 2026)](https://www.usenix.org/conference/usenixsecurity26/presentation/luo)
separates resource lifecycles, while this fixture covers only one local
cumulative-work case. [Wang et al.,
2026](https://arxiv.org/abs/2602.07878) distinguish model-output length from
serving-scheduler impact. [Zhou et al., 2026, *From Shield to Target*](https://arxiv.org/abs/2606.14517)
describe resource pressure in LLM guardrails. The fixture does not reproduce
either paper's attack mechanism; it checks the narrower evidentiary boundary.
