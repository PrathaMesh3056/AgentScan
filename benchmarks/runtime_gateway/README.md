# Runtime gateway latency benchmark and soak

Reproducible, local-only performance evidence for the AgentScan runtime gateway
(`docs/RUNTIME_GATEWAY.md` §13 and §16). The harnesses use fake data, a real
`ReceiptChainStore` on a temporary directory, and an in-process fake upstream.
They open no sockets, read no credentials, and call no tool.

## What is measured

| Metric | Code path | Budget (p99) |
| --- | --- | --- |
| Policy decision | `evaluate_policy` on a validated high-risk policy | < 10 ms |
| Decision-receipt append | `ReceiptChainStore.append` (WAL + JSONL + fsync) | < 20 ms |
| End-to-end gateway overhead | `GatewayRuntime.call_tool`, fake upstream service time subtracted | < 40 ms |

The gateway-overhead measurement includes argument validation, policy
evaluation, the durable `pending` decision append, idempotency indexing,
upstream dispatch, and the outcome append. It excludes the fake upstream's own
handler time, which the fake records with `time.perf_counter_ns`; the residual
is clamped at zero. Both chains are re-verified from disk after each measurement,
and the harness fails if any receipt is missing.

## Run the benchmark

```bash
python benchmarks/runtime_gateway/bench_gateway.py --samples 500
python benchmarks/runtime_gateway/bench_gateway.py --samples 500 --out bench.json --json
```

Options:

- `--samples` — append and gateway-overhead samples (default 500);
- `--policy-samples` — policy samples (default 5000);
- `--warmup` — discarded calls per metric (default 50);
- `--out` — write the full JSON report, including every raw sample in ms;
- `--json` — print that JSON report;
- `--receipt-dir` — reuse a directory instead of a temporary one.

Exit status is 0 only when all three p99 values are under budget and both
chains verify. A miss is reported as `FAIL`; the raw numbers are never adjusted.
The report records the host profile (platform, CPU count, machine), Python
version, exact command, sample counts, settings, budgets, per-metric p50/p99/
mean/max, raw samples, and chain-verification counts.

## Run the soak

```bash
# Shortened smoke (used for the Phase 6 checkpoint)
python benchmarks/runtime_gateway/soak_gateway.py --seconds 60 --rate 5 --receipt-dir .benchmarks/soak-smoke

# Full one-hour v1 soak (docs/RUNTIME_GATEWAY.md §16)
python benchmarks/runtime_gateway/soak_gateway.py --seconds 3600 --rate 2 --receipt-dir .benchmarks/soak-1h --out .benchmarks/soak-1h.json
```

The soak dispatches repeated allowed, high-risk tool calls through the real
runtime, verifies the JSONL chain and the decision/outcome pairing every
`--verify-every` iterations (default 50), samples `tracemalloc` and best-effort
RSS every `--memory-every` iterations, and reports throughput, latency, receipt
counts, lost receipts, and heap growth. It exits 0 only when the chain is valid,
every decision has a terminal `success` outcome, no call failed, and heap growth
is within the documented per-decision bound.

v1 keeps the verified chain and idempotency index in memory, so heap growth is
linear in receipts by design. `MAX_HEAP_BYTES_PER_DECISION` (32 KiB) catches a
leak beyond that retention; it is not a claim of constant memory.

## Slow tests

The harnesses have slow-marked pytest coverage:

```bash
python -m pytest tests/test_gateway/test_gateway_phase6_performance.py -q -m slow
```

`pytest -m "not slow"` (the CI profile) never runs them, so the default suite
stays fast and independent of host fsync and scheduler noise.

## Interpretation limits

- Numbers are host-specific and dominated by fsync cost on the local filesystem.
  A Windows developer laptop or shared CI runner is not production capacity
  evidence.
- The fake upstream returns a trivial result, so the gateway overhead is the
  enforcement path, not upstream tool latency.
- There is one writer, one chain, and one tool. Multi-tenant or multi-chain
  scaling is not measured.
- The full one-hour soak is recorded in `PROGRESS.md` with the exact command
  above. A shortened smoke run is evidence for the harness, not for one-hour
  stability.
