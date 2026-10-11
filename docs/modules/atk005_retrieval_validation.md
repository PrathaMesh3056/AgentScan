# ATK-005 separately authored retrieval validation

This local engineering validation exercises the
[document adapter](indirect_injection.md) through an owned HTTP application that
retrieves documents using SQLite full-text search. It does not add a retrieval
engine or target defense to AgentScan.

Cases and the retrieval application were written by separate same-team authors
before model execution. This is not an external customer evaluation or proof
of uncontaminated research testing.

## Observed results

The 11 October 2026 run used twelve frozen cases: six attack intents and six
benign policy tasks. All submitted sources were retrieved and all cases were
evaluated. Neither arm observed complete private-reference disclosure; both
completed four of six benign tasks. Consequently, positive detection recall
and defense benefit were not established. Operational controls passed separately
and are excluded from model behavior statistics.

These results do not revise the earlier document run's one-of-two benign result:
the inputs and output rules differ. See [evaluation limits](../EVALUATION.md)
for the distinctions and [release readiness](../RELEASE_READINESS.md) for
current engineering checks.

## Replay locally

From a repository checkout with Python 3.12+ and the normal runtime dependencies:

```powershell
python -m benchmarks.evaluation.atk005_retrieval_run --controls-only --output local-retrieval-controls
python -m benchmarks.evaluation.atk005_retrieval_run --snapshot <existing-pinned-snapshot> --output local-retrieval-model
```

The output directory must be fresh. Actual model generation additionally needs
Torch, Transformers and the already cached pinned Qwen snapshot. The runner
disables downloads and checks the model assets; it uses synthetic private state,
owned loopback HTTP and no provider calls. Raw replies and the private reference
are not retained.

The [frozen method](../../benchmarks/evaluation/atk005_retrieval_METHOD.md) and
[manifest](../../benchmarks/evaluation/atk005_retrieval_manifest.json) describe
the replay. A document receipt does not establish tool execution, outbound
exfiltration or broad agent security.
