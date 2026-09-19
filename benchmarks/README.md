# AgentScan Benchmark Suite

This directory contains the methodology, runner, and reference definitions for validating the discriminating power and performance of AgentScan.

---

## 1. Objectives & Methodology

A security scanner is only as trustworthy as its ability to discriminate between vulnerable and non-vulnerable systems. A scanner that reports "0 findings" on a broken agent is dangerous; a scanner that reports false positives on a secure agent is noisy.

The AgentScan benchmark suite validates:
1. **Discriminating Power**: Proves that the scanner produces strictly decreasing findings and strictly increasing scores across agents with increasing defensive maturity.
2. **Scan Latency & Throughput**: Measures execution duration across both synchronous and concurrent scan modes.
3. **Reproducibility**: Uses deterministic in-process reference agents without requiring external LLM API keys or unpredictable network conditions.

---

## 2. Reference Agents

The benchmark suite defines three deterministic reference agents in [`agentscan/core/benchmark.py`](../agentscan/core/benchmark.py):

| Agent Profile | Implementation | Expected Verdict | Expected Findings |
|---|---|---|---|
| **Wide-Open** | Naively echoes or complies with any attack payload (`_wide_open`) | Low Score (0–30) | High findings count |
| **Partial** | Defends against ~50% of attacks, falls for the rest (`_partial`) | Medium Score (30–75) | Moderate findings count |
| **Guarded** | Strong scope guard deflection on all prompts (`_guarded`) | High Score (80–100) | Zero or near-zero findings |

---

## 3. Running the Benchmarks

### Via the CLI:
```bash
agentscan benchmark
```

### Via the Benchmark Script:
```bash
python benchmarks/run_benchmarks.py
```

Options:
- `--json`: Output benchmark results as structured JSON.
- `--iterations <N>`: Run multiple iterations to compute average latency and variance.

---

## 4. Acceptance Criteria

A benchmark run passes if:
- `findings(wide-open) > findings(partial) > findings(guarded)`
- `score(guarded) > score(wide-open)`
- Zero unhandled exceptions or crashes across the entire suite.
