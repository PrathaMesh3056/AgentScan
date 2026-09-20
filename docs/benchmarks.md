# AgentScan Benchmark Methodology & Architecture Comparison

This document describes the benchmarking methodology used to measure scan latency, throughput, and detection behavior across security evaluation architectures.

---

## Evaluation Architecture Comparison

Execution latency in security scanning is fundamentally determined by the tool's evaluation architecture:

| Framework / Architecture | Primary Execution Model | External Token Cost | Hardware Requirement | CI/CD PR Gate Viability |
| :--- | :--- | :---: | :---: | :---: |
| **AgentScan (SCAN)** | In-process concurrent async (`asyncio.gather`) | **$0.00** | Standard CPU (1 core) | **Viable (< 3s gate)** |
| **AgentScan (DEEP)** | SCAN heuristics + local CPU neural probing | **$0.00** | Standard CPU (8GB RAM) | Fast nightly regression |
| **Promptfoo** | Node.js concurrent runner + Cloud LLM judge | $0.50 – $3.00 | Standard CPU | Moderate PR check |
| **PyRIT (Microsoft)** | Multi-turn red-teaming loops (Attacker + Judge) | $2.00 – $10.00 | Standard CPU | Scheduled audit |
| **Garak (NVIDIA)** | Sequential generator-detector probe matrix | $10 – $30 *(or GPU)* | GPU recommended | Deep model benchmark |

---

## Methodology & Context

When evaluating security tools in the AI ecosystem, keep the following distinctions in mind:

1. **Different Evaluation Scopes**:
   - Tools like **Garak** focus on testing foundation model text generation (measuring toxic output, hallucinations, or copyright infringement).
   - Tools like **Promptfoo** focus on prompt engineering regression testing and output assertions.
   - Tools like **PyRIT** are red-teaming orchestration SDKs designed for custom multi-turn campaign authoring.
   - **AgentScan** focuses on the agentic runtime layer: verifying whether an autonomous agent executes unauthorized tools, leaks system instructions, accepts malicious Model Context Protocol (MCP) server definitions, or alters persistent memory.

2. **Network and Cloud Dependencies**:
   - Cloud LLM-as-a-judge frameworks incur variable latency (typically 1–2 seconds per roundtrip API call) and are subject to rate limiting (HTTP 429) and network jitter.
   - AgentScan's core `SCAN` mode evaluates responses locally using in-process heuristics and regex patterns, eliminating external API calls during standard runs.

3. **Hardware Considerations**:
   - Benchmarks for AgentScan were measured on standard x86_64 CPU hardware against local mock agent endpoints.
   - Local neural activation probing (`DEEP` mode) executes on CPU using quantized or small reference models (such as `Qwen2.5-0.5B`) to avoid GPU requirements.

---

## Reproducing the Local Benchmark

AgentScan includes a built-in benchmark command that evaluates reference mock agents with known vulnerability levels (wide-open, partial defenses, and guarded):

```bash
uv run agentscan benchmark
```

### Expected Behavior

The benchmark verifies that:
- **Wide-open agent**: Receives a critical risk rating (0/100) due to multiple detected vulnerabilities.
- **Partial defense agent**: Receives an elevated risk rating reflecting unmitigated attack vectors.
- **Guarded agent**: Successfully resists test probes and receives a safe score (100/100).

```
                    AgentScan Benchmark — reference agents
+-----------------------------------------------------------------------------+
| Reference agent      | Expectation         | Findings |               Score |
|----------------------+---------------------+----------+---------------------|
| wide-open (no def.)  | expect LOW score    |       98 |    0/100  [CRITICAL |
|                      |                     |          |               RISK] |
| partial (some def.)  | expect MEDIUM score |       47 |    0/100  [CRITICAL |
|                      |                     |          |               RISK] |
| guarded (strong def.)| expect HIGH score   |        0 |     100/100  [SAFE] |
+-----------------------------------------------------------------------------+
[PASS] scores rank the agents correctly by vulnerability.
```

The benchmark runs completely offline and requires no external API keys or network access.
