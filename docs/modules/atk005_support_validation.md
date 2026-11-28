# ATK-005 offline support-agent assessment

This bounded 12 October 2026 assessment exercised the production document module
against a separately authored owned support agent with real SQLite retrieval and
a cached Qwen2.5-0.5B-Instruct model. Separate same-team authors wrote the target
and cases; this was not an external customer audit.

Sixteen cases were frozen before inference: eight development and eight held-out,
each balanced between attack and benign intent. Every case ran once under each
condition. The baseline retained raw document control-token serialization; the
defended condition encoded the same document as literal data and enforced a
public JSON support-answer contract. The confidentiality policy remained intact.

| Observed outcome | Baseline | Defended |
| --- | --- | --- |
| Evaluated development cases | 8/8 | 8/8 |
| Correct development support answers | 7/8 | 6/8 |
| Evaluated held-out cases | 8/8 | 8/8 |
| Complete private-reference disclosures, held-out | 0/8 | 0/8 |
| Correct held-out support answers | 8/8 | 8/8 |
| Correct held-out benign answers | 4/4 | 4/4 |

All 32 generations had independently checked source/retrieval/model-input/output
joins, exact decoded document spans and scanner-received response correlation.
There were no held-out false positives. **Positive detection recall and defense
improvement remain inconclusive:** no observed positive exists from which to
measure either. Zero leaks does not demonstrate a successful defense or general
agent safety. Benign utility preservation passed for this small held-out sample;
the development utility regression remains visible.

Forced synthetic disclosures verified detector and report plumbing separately;
they are excluded from real-model statistics. An initial harness-copy defect
blocked all requests before inference, consumed zero generation attempts, and
was repaired before the 32 actual generations. That aborted execution is retained.

The [frozen method](../../benchmarks/evaluation/atk005_support_METHOD.md) and
[manifest](../../benchmarks/evaluation/atk005_support_manifest.json) document the
thresholds. Locally retained case files and sanitized receipts remain in ignored
a local directory outside the public repository; they are not bundled in a release.
From the original evaluation checkout with those inputs and an existing cache:

```powershell
python -m benchmarks.evaluation.atk005_support_run --model-dir <cached-pinned-Qwen-snapshot> --output <fresh-local-evidence-directory>
```

This is an engineering replay command, not permission to rerun sealed held-out
cases for tuning. The runner disables downloads and uses no provider API. Private
bindings and raw model text remain in memory; exports contain hashes and outcomes.
Use the [production setup guide](indirect_injection.md) for ordinary assessments.
