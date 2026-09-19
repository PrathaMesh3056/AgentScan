<div align="center">

<img src="assets/logo.svg" alt="AgentScan Emblem" width="110" height="110" />

# AgentScan

**Open-source security scanner and red-teaming toolkit for AI agents and LLM-powered applications.**

[![CI](https://github.com/PrathaMesh3056/AgentScan/actions/workflows/ci.yml/badge.svg)](https://github.com/PrathaMesh3056/AgentScan/actions/workflows/ci.yml)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg?logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-482%20passed-brightgreen.svg?logo=pytest&logoColor=white)](https://github.com/PrathaMesh3056/AgentScan/actions)
[![OWASP LLM Top 10](https://img.shields.io/badge/OWASP-LLM%20Top%2010-red.svg)](https://genai.owasp.org/llmtop10/)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg?logo=ruff&logoColor=white)](https://github.com/astral-sh/ruff)
[![Checked with mypy](https://img.shields.io/badge/types-mypy%20clean-blue.svg)](https://mypy-lang.org/)
[![Packaged with uv](https://img.shields.io/badge/packaged%20with-uv-de5fe9.svg?logo=uv&logoColor=white)](https://github.com/astral-sh/uv)
[![llms.txt](https://img.shields.io/badge/llms.txt-standard-orange.svg)](llms.txt)

<p align="center">
  <a href="#overview">Overview</a> •
  <a href="#who-is-this-for">Who It's For</a> •
  <a href="#key-capabilities">Key Capabilities</a> •
  <a href="#supported-targets">Supported Targets</a> •
  <a href="#installation">Installation</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#architecture--workflow">Architecture</a> •
  <a href="#benchmarks--performance">Benchmarks</a> •
  <a href="#documentation">Docs</a> •
  <a href="#contributing">Contributing</a>
</p>

---

<img src="assets/dashboard_preview.png" alt="AgentScan Threat Posture & Defense Grid Dashboard" width="100%" style="border-radius: 12px; border: 1px solid #1e293b;" />

</div>

<br>

AgentScan helps security teams, developers, and red teams evaluate risks in autonomous agents and LLM-powered systems, including:

- **Prompt Injection & System Prompt Leakage** (direct, indirect, and multilingual bypasses)
- **Jailbreak Behavior & Multi-Turn Escalation** (PAIR-style refinement and Crescendo dialogues)
- **Tool Misuse & Unauthorized Actions** (unsolicited command execution and tool hijacking)
- **Data Exfiltration & Memory Poisoning** (sensitive credential extraction and context pollution)
- **Identity & RBAC Violations** (over-privileged tool scopes and multi-hop privilege escalation)
- **MCP & Supply-Chain Vulnerabilities** (Model Context Protocol risks, unsafe dependencies, and dangerous code patterns)

---

## Overview

Modern AI agents do not simply generate text — they execute tools, query databases, read sensitive files, trigger shell processes, and coordinate across external APIs. Traditional security scanners focus on source code syntax, static dependencies, or open network ports, while prompt evaluation frameworks focus primarily on generation quality and model alignment. Neither approach evaluates whether an autonomous agent will execute unauthorized actions when confronted with adversarial inputs.

AgentScan bridges this gap by treating an AI agent like a web application under penetration testing. It actively probes live agent endpoints with adversarial payloads, simulates downstream exploits to measure real blast radius, audits local source repositories for supply-chain CVEs, and inspects agent identity configurations.

The platform produces standardized security reports in multiple formats (JSON, interactive HTML, executive PDF, and OASIS SARIF 2.1.0 for GitHub Code Scanning), generates CycloneDX 1.6 Artificial Intelligence Bill of Materials (AIBOM), maps findings to major compliance frameworks (**OWASP Top 10 for LLMs**, **NIST AI RMF 1.0**, and the **EU AI Act**), and can synthesize automated self-healing patches (`agentscan fix`) to remediate identified vulnerabilities.

---

## Who Is This For?

- **AI Application Developers**: Validate system prompt resilience, audit tool-calling boundaries, and catch prompt injection vulnerabilities before deploying agents to production.
- **Security & AppSec Engineers**: Assess agentic systems against the OWASP Top 10 for LLMs, verify tool authorization controls (RBAC), and scan AI dependencies for known CVEs.
- **Red Teams & Penetration Testers**: Execute automated adversarial simulations, test multi-turn escalation pathways (Crescendo/PAIR), and prove blast-radius impact through simulated exploits.
- **Platform & DevSecOps Teams**: Integrate deterministic, sub-second agent security gates into GitHub Actions and CI/CD pipelines with native SARIF output.
- **Organizations Deploying Tool-Using Agents**: Audit Model Context Protocol (MCP) servers, manage agent identity policies, and generate compliance-ready AIBOMs.
- **Researchers Evaluating LLM Security**: Benchmark model defenses and examine internal representation shifts via CPU-based neural activation probing.

---

## Key Capabilities

### Live Agent Testing
- **HTTP Endpoint Scanning**: Probe live REST/JSON agent endpoints with single-turn and multi-turn payloads.
- **cURL Replay**: Ingest captured browser sessions (`--curl`) to test complex web agents with cookies, headers, and multipart requests.
- **Headless Browser Testing**: Automate chat widget testing in real browsers via Playwright (`--browser-url`).
- **WebSocket Streaming**: Scan persistent real-time streaming agents over `ws://` and `wss://`.
- **Model Context Protocol (MCP) Probing**: Audit MCP servers (`mcp://stdio` and `mcp+sse://`) via `tools/list`, `tools/call`, and `resources/read`.
- **Adversarial & Multi-Turn Testing**: Automated PAIR-style iterative attacker (`ATK-050`), Crescendo escalation scripts (`ATK-010`), and optional LLM-as-a-Judge validation.

### Static Repository Auditing
- **Dependency & Supply-Chain Audits**: Query the OSV.dev database in live batches with offline fallbacks to identify vulnerable AI packages.
- **Lockfile & Version Range Analysis**: Parse `uv.lock` and `poetry.lock` to trace transitive dependency vulnerability paths.
- **AST Security Inspections**: Detect dangerous calls natively via Python AST (`eval`, `exec`, `subprocess(shell=True)`, `torch.load` without `weights_only=True`, and insecure unpickling).
- **CycloneDX 1.6 AIBOM Generation**: Produce machine-readable AI Bill of Materials (`--aibom`) detailing models, dependencies, and datasets.
- **Identity & RBAC Graph Analysis**: Map declared agent permissions against role definitions and detect multi-hop privilege escalation using NetworkX.

### Reporting & CI/CD
- **Multi-Format Export**: Output findings as structured JSON, standalone HTML, print-ready PDF, or OASIS SARIF 2.1.0.
- **Interactive Control Grid**: Local web dashboard (`agentscan ui`) with real-time SSE streaming, defense grids, and full session trajectory inspection.
- **GitHub Actions Integration**: Official composite action (`action.yml`) with automated SARIF upload to GitHub Code Scanning.
- **Configurable Failure Thresholds**: Enforce CI/CD policy gates using `--fail-on` (e.g., `--fail-on HIGH` or `--fail-on CRITICAL`).

### Advanced Analysis
- **DEEP Mode (Neural Activation Probing)**: Inspect latent representation shifts on a local aligned reference model (`Qwen2.5-0.5B` on CPU) using $L_2$ and cosine metric deltas against a calibrated benign noise floor.
- **EXPLOIT Mode (Blast Radius Proofs)**: Simulate active downstream exploits including data exfiltration (`ATK-014`), tool hijacking (`ATK-015`), and memory poisoning (`ATK-016`).
- **Automated Self-Healing (`agentscan fix`)**: Generate unified git diff patches and NeMo Guardrail policies to remediate detected vulnerabilities.
- **SSP Behavioral Classification**: Classify agent response trajectories into Servant, Stalker, or Predator behavioral profiles.

---

## Supported Targets

| Target Type | Command Flag / Input | Description |
| :--- | :--- | :--- |
| **HTTP REST** | `agentscan scan <url>` | Probes standard JSON chat endpoints (`{"message": ...}`, `{"prompt": ...}`, etc.). |
| **cURL Replay** | `--curl <file>` | Replays captured browser network requests with headers, tokens, and cookies intact. |
| **Browser Widget** | `--browser-url <url>` | Drives headless Playwright browsers to locate inputs, send payloads, and capture reply elements. |
| **WebSocket** | `agentscan scan ws://<host>/<path>` | Connects to persistent bidirectional WebSocket streaming agents. |
| **MCP Server** | `agentscan scan mcp+sse://<host>/<path>` | Connects to Model Context Protocol servers over SSE or stdio to audit exposed tools. |
| **Source Directory** | `agentscan audit <path>` | Scans local repositories, manifests, lockfiles, and codebases without running live targets. |

---

## Output Formats

| Format | Option / Command | Purpose |
| :--- | :--- | :--- |
| **JSON** | `--output report.json` | Complete machine-readable findings, severity ratings, and SSP metadata. |
| **HTML** | `--output report.html` | Self-contained, styled visual security report for review and sharing. |
| **PDF** | `--output report.pdf` | Executive print-ready report generated via WeasyPrint. |
| **SARIF 2.1.0** | `--output report.sarif` | Standardized format for native integration into GitHub Code Scanning. |
| **CycloneDX 1.6** | `audit --aibom -o aibom.cdx.json` | Industry-standard AI Bill of Materials capturing packages and model metadata. |
| **Session Transcript**| `--transcript session.txt` | Chronological record of every request payload and target reply. |
| **Interactive UI** | `agentscan ui --report report.json` | Real-time web dashboard with filtering, search, and defense grid inspection. |

---

## Installation

### Requirements
- **Python**: 3.12 or higher
- **Package Manager**: [`uv`](https://github.com/astral-sh/uv) (recommended) or `pip`

### 1. Clone and Install

```bash
# Clone the repository
git clone https://github.com/PrathaMesh3056/AgentScan.git
cd AgentScan

# Install dependencies using uv
uv sync
```

*(Alternatively with pip: `pip install -e .`)*

### 2. Optional Dependencies (DEEP Mode Neural Probing)

To run DEEP mode neural activation probing locally on CPU:

```bash
# Install PyTorch CPU build and HuggingFace transformers
uv add torch --extra-index-url https://download.pytorch.org/whl/cpu
uv add transformers
```

---

## Quick Start

### 1. Scan a Live Agent (60 Seconds)

```bash
# Run a security scan against a live agent endpoint
uv run agentscan scan http://localhost:8000/chat --output report.json
```

### 2. Run the Offline Benchmark

If you do not have an agent endpoint running yet, you can immediately verify AgentScan's detection and scoring engine locally (no network or API keys required):

```bash
uv run agentscan benchmark
```

Expected output:
```
                    AgentScan Benchmark — reference agents
+-----------------------------------------------------------------------------+
| Reference agent      | Expectation         | Findings |               Score |
|----------------------+---------------------+----------+---------------------|
| wide-open (no def.)  | expect LOW score    |       89 |    0/100  [CRITICAL |
|                      |                     |          |               RISK] |
| partial (some def.)  | expect MEDIUM score |       44 |    0/100  [CRITICAL |
|                      |                     |          |               RISK] |
| guarded (strong def.)| expect HIGH score   |        0 |     100/100  [SAFE] |
+-----------------------------------------------------------------------------+
[PASS] scores rank the agents correctly by vulnerability — 369 tests evaluated.
```

### 3. Launch the Web Dashboard

```bash
# Start the local dashboard to inspect findings and trajectories
uv run agentscan ui --report report.json
```
Open `http://127.0.0.1:8765` in your browser.

---

## Architecture & Workflow

```
┌──────────────────────────────────────────────────────────────────────────────────────────┐
│                                    AgentScan Pipeline                                    │
└──────────────────────────────────────────────────────────────────────────────────────────┘
             │                                                          │
             ▼                                                          ▼
  [ 1. LIVE TARGET MODES ]                                   [ 2. STATIC AUDIT MODES ]
  Connectors: HTTP / cURL / Playwright / WS / MCP            Target: Repository / Project Root
             │                                                          │
             ├──────────────────────────────────────┐                   ├─────────────────────────────┐
             ▼                                      ▼                   ▼                             ▼
   Active Probing (SCAN/EXPLOIT)           Neural Probing (DEEP)   Supply Chain (AICS)       Identity & MCP Audit
   • Prompt Injection (ATK-001)            • Qwen2.5-0.5B CPU      • OSV.dev CVE Database    • Manifest Parser
   • Multi-Turn Jailbreaks (ATK-002)       • L2 / Cosine Shift     • AST Unsafe Calls        • Tool Scope Mapping
   • Tool Hijacking (ATK-015)              • Benign Noise Floor    • CycloneDX 1.6 AIBOM     • RBAC Escalation Graph
   • Memory Poisoning (ATK-016)            • Layer Anomaly Check   • Secret & Key Leakage    • Cross-Agent Credentials
             │                                      │                   │                             │
             └──────────────────────────────────────┴───────────────────┴─────────────────────────────┘
                                                    │
                                                    ▼
                                         [ 3. EVALUATION ENGINE ]
                                         • In-Process Embeddings (MiniLM)
                                         • Deterministic Signature Heuristics
                                         • Optional LLM-as-a-Judge Scoring
                                                    │
                                                    ▼
                                         [ 4. OUTPUTS & REMEDIATION ]
                                         • Interactive Web Dashboard (FastAPI)
                                         • SARIF 2.1.0 / HTML / PDF Reports
                                         • Automated Self-Healing Diff Patches (`agentscan fix`)
                                         • Regulatory Profiles (EU AI Act, NIST AI RMF)
```

1. **Target Ingestion**: Normalizes communication across disparate protocols (HTTP, Playwright, cURL, WebSockets, MCP) through a unified client interface.
2. **Concurrency-Controlled Dispatch**: Runs attack modules concurrently under an in-flight connection semaphore to protect target servers from rate limits, while preserving deterministic finding order.
3. **Dual-Perspective Analysis**:
   - *Behavioral (Black-Box)*: Evaluates responses locally using regex patterns, MiniLM sentence embeddings, and optional LLM judges.
   - *Neural (White-Box / DEEP)*: Measures internal layer activation deltas ($L_2$ distance and cosine similarity) on a local CPU model to verify latent prompt injection.
4. **Static Code & Dependency Analysis**: Audits repository lockfiles against OSV.dev, inspects Python AST for dangerous functions, and models agent tool permissions as an RBAC graph.
5. **Remediation & Compliance**: Translates findings into actionable remediation patches (`agentscan fix`), CycloneDX AIBOMs, and compliance frameworks.

---

## Common Workflows

### 1. Scanning Live Agents with Advanced Flags

```bash
# Scan with active exploit verification and neural probing
uv run agentscan scan http://localhost:8000/chat --exploit --deep --output report.html

# Provide the target's system prompt to verify exfiltration resilience
uv run agentscan scan http://localhost:8000/chat \
  --system-prompt "You are a customer support agent. Secret: SECRET-KEY-9" \
  --exploit

# Replay a captured browser request with custom message path
uv run agentscan scan --curl request.curl --message-path "messages.0.content"

# Drive a web chat interface using Playwright
uv run agentscan scan --browser-url http://localhost:3000 \
  --input-selector "#prompt-input" \
  --response-selector ".assistant-message"

# Auto-discover endpoints and save a reusable target profile
uv run agentscan init http://localhost:8000/chat -o target.yaml
uv run agentscan scan -c target.yaml
```

### 2. Static Auditing & AIBOM Generation

```bash
# Run a full static audit on a local agent project
uv run agentscan audit ./my-agent-project

# Generate a CycloneDX 1.6 Artificial Intelligence Bill of Materials
uv run agentscan audit ./my-agent-project --aibom --output aibom.cdx.json

# Enforce security gates during CI builds
uv run agentscan audit ./my-agent-project --fail-on HIGH --output audit.sarif
```

### 3. Automated Self-Healing (`agentscan fix`)

```bash
# Preview proposed remediation diffs (dry-run mode)
uv run agentscan fix ./my-agent-project

# Apply fixes directly to disk
uv run agentscan fix ./my-agent-project --apply

# Generate NeMo Guardrails policies and patch insecure AST calls
uv run agentscan fix ./my-agent-project --apply --kind ast_patch,guardrails
```

### 4. GitHub Actions CI/CD Integration

Block vulnerable agent deployments directly in pull requests:

```yaml
# .github/workflows/agentscan.yml
name: Agent Security Gate
on: [pull_request]

jobs:
  security-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: PrathaMesh3056/AgentScan@v1
        with:
          command: scan
          target-url: http://localhost:8000/chat
          fail-on: HIGH
          sarif-output: report.sarif

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: report.sarif
```

---

## Benchmarks & Performance

Execution speed in security scanning is fundamentally determined by evaluation architecture:

<div align="center">

<img src="assets/benchmark_speed.svg" alt="Evaluation Architecture Latency Comparison" width="100%" style="border-radius: 10px; margin: 12px 0;" />

</div>

| Framework / Tool | Observed Runtime *(350+ tests)* | Primary Architecture | External Token Cost | Hardware Requirement | CI/CD PR Gate Viability |
| :--- | :---: | :--- | :---: | :---: | :---: |
| **AgentScan (SCAN)** | **~2.1s** | In-process concurrent async (`asyncio.gather`) | **$0.00** | Standard CPU (1 core) | **Viable (< 3s gate)** |
| **AgentScan (DEEP)** | **~4.8s** | SCAN heuristics + local CPU neural probing | **$0.00** | Standard CPU (8GB RAM) | Fast nightly regression |
| **Promptfoo** | ~45s – 120s | Node.js concurrent runner + Cloud LLM judge | $0.50 – $3.00 | Standard CPU | Moderate PR check |
| **PyRIT (Microsoft)** | ~180s – 600s | Multi-turn red-teaming loops (Attacker + Judge) | $2.00 – $10.00 | Standard CPU | Scheduled audit |
| **Garak (NVIDIA)** | ~1,980s *(~33m)* | Sequential generator-detector probe matrix | $10 – $30 *(or GPU)* | GPU recommended | Deep model benchmark |

> [!NOTE]
> **Methodology & Context**:
> - Benchmarks illustrate architectural throughput characteristics rather than identical evaluation scopes.
> - AgentScan's measurement was conducted on a local testbed (Python 3.12, x86_64 CPU, localhost HTTP mock agent endpoint).
> - Cloud LLM-as-a-judge timings are modeled assuming a 100-probe suite requiring 200–400 sequential or batch API calls at ~1.5s p50 latency, excluding potential HTTP 429 rate-limit backoffs.
> - In our latest performance release, full test suite execution was optimized from **154.0s** down to **114.9s** (**~26% overall speedup** across 482 tests) via bounded concurrency semaphores, precompiled regex caching, and vectorized PyTorch tensor operations.

### Reproducing the Benchmark
Verify discriminating power and scoring integrity on your own hardware:
```bash
uv run agentscan benchmark
```

---

## Documentation

| Document | Description |
| :--- | :--- |
| 📖 [**Project Manual**](docs/AgentScan_Manual.md) | Complete guide covering threat models, CLI usage, connectors, and configuration options. |
| 🥊 [**Comparison Guide**](docs/comparison.md) | Detailed technical and architectural comparison with Garak, Promptfoo, PyRIT, and Snyk. |
| 🔬 [**DEEP Mode Guide**](docs/deep_mode.md) | Mathematical formulation and usage for latent activation and cosine divergence probing. |
| 🧩 [**Module Matrix**](docs/module_matrix.md) | Comprehensive status matrix covering all 24 engineering modules and deliverables. |
| 🤖 [**LLM Context (`llms.txt`)**](llms.txt) | LLM-optimized summary and canonical CLI reference. |
| 📜 [**Full LLM Spec (`llms-full.txt`)**](llms-full.txt) | Full technical schemas, threat catalogs, and CLI flag dictionary. |

---

## Project Status & Roadmap

AgentScan is actively maintained and under continuous development.

- **Current Version**: `0.1.0-alpha`
- **Test Suite**: 482 passing unit and integration tests (clean `ruff` linting and `mypy` type checking)
- **Maturity**: Core scanning, static auditing, and reporting engines are stable.

### Milestones
- [x] OWASP Top 10 for LLMs 2025 automated suites
- [x] Universal Connectors (HTTP, cURL Replay, Playwright, WebSocket, MCP)
- [x] Graph-based RBAC and multi-hop privilege escalation analysis
- [x] Neural activation probing on local CPU (`Qwen2.5-0.5B`)
- [x] Automated self-healing with unified git diff generation (`agentscan fix`)
- [x] Real-time SSE dashboard and interactive defense grid
- [ ] **Distributed Swarm Red-Teaming**: Multi-agent adversarial teams (Recon, Bypass, Exploit, Judge)
- [ ] **eBPF Agent Sandbox**: Real-time syscall inspection for tool-executing agents
- [ ] **Live AI Gateway Exporters**: Native rule exports for LiteLLM Proxy, Cloudflare AI Gateway, and AWS Bedrock

---

## Security & Responsible Use

AgentScan is an offensive and defensive security evaluation toolkit created to help developers and security teams build safer AI systems.

- **Authorized Testing Only**: AgentScan should only be run against agents, endpoints, and systems that you own or have explicit, documented permission to test. Unauthorized security testing against third-party systems may violate applicable laws and terms of service.
- **Reporting Vulnerabilities in AgentScan**: If you discover a security vulnerability within AgentScan itself, please disclose it responsibly. Do not open public GitHub issues for security vulnerabilities. Instead, submit a report via GitHub Private Vulnerability Reporting or contact the maintainers directly.

---

## Contributing

We welcome contributions from the community!

### 1. Development Setup
```bash
git clone https://github.com/PrathaMesh3056/AgentScan.git
cd AgentScan
uv sync
```

### 2. Running Quality Checks
Before submitting a PR, ensure all checks pass:
```bash
# Run the fast test suite
uv run pytest tests/ -m "not slow"

# Run the full test suite
uv run pytest tests/ -q

# Code formatting and linting
uv run ruff check .
uv run ruff format .

# Static type checking
uv run mypy agentscan/
```

### 3. Adding a New Attack Module
Adding a custom attack module requires minimal boilerplate:
```python
from agentscan.attacks.base import AttackModule
from agentscan.core.models import Finding, ScanMode, Severity, Target

class CustomAuditModule(AttackModule):
    attack_id = "ATK-099"
    attack_name = "Custom Probe"
    owasp_id = "LLM01"
    supported_modes = [ScanMode.SCAN]

    async def run(self, target: Target) -> list[Finding]:
        # Implement async probing logic here
        return []
```
The registry auto-discovers any `AttackModule` subclass placed in `agentscan/attacks/scan/`, `exploit/`, or `deep/`.

---

## License

Distributed under the **Apache 2.0 License**. See [`LICENSE`](LICENSE) for details.

Authored and maintained by [Prathamesh](https://github.com/PrathaMesh3056).

---

## REST API (Multi-Tenant)

```bash
# 1. Start the local dev stack
docker compose -f docker-compose.api.yml up

# 2. Get a JWT token
curl -X POST http://localhost:8080/token \
  -H "Content-Type: application/json" \
  -d '{"tenant_id": "my-org", "secret": "dev-psk"}'

# 3. Run a scan (returns immediately with scan_id)
curl -X POST http://localhost:8080/scans \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"target_url": "http://my-agent:8000/chat", "scan_mode": "SCAN"}'

# 4. Poll for results
curl http://localhost:8080/scans/<scan_id> \
  -H "Authorization: Bearer <token>"

# 5. Stream live progress (SSE)
curl -N http://localhost:8080/scans/<scan_id>/stream \
  -H "Authorization: Bearer <token>"
```

