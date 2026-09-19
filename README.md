<div align="center">

<img src="assets/logo.svg" alt="AgentScan Emblem" width="110" height="110" />

# AgentScan

**Open-source security scanner and red-teaming toolkit for AI agents and LLM applications.**

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
  <a href="#why-agentscan">Why AgentScan</a> •
  <a href="#who-is-this-for">Who It's For</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#how-it-works">How It Works</a> •
  <a href="#key-capabilities">Key Capabilities</a> •
  <a href="#benchmarks--performance">Benchmarks</a> •
  <a href="#documentation">Docs</a> •
  <a href="#contributing">Contributing</a>
</p>

---

<img src="assets/dashboard_preview.png" alt="AgentScan Threat Posture & Defense Grid Dashboard" width="100%" style="border-radius: 12px; border: 1px solid #1e293b;" />

</div>

<br>

AgentScan helps developers, security engineers, and red teams evaluate prompt injection, tool misuse, identity abuse, jailbreak behavior, and supply-chain vulnerabilities across live endpoints, browser widgets, MCP servers, and source repositories.

---

## Why AgentScan?

Modern AI agents are not just text completions — they can call tools, access databases, read files, execute shell commands, and interact with third-party APIs. Traditional vulnerability scanners only check code syntax or open network ports, while prompt evaluation tools focus primarily on generation quality rather than security blast radius.

AgentScan bridges this gap by unifying active red-teaming with static security analysis:

- **Live Agent Probing**: Tests live endpoints against prompt injections, multi-turn jailbreaks (PAIR/Crescendo), PII leaks, and denial-of-service vectors.
- **Active Exploit Simulation**: Validates whether injection leads to real downstream impact (tool hijacking, credential exfiltration, memory poisoning).
- **Static Repository & Supply Chain Auditing**: Scans dependencies against OSV.dev advisories, audits AST for dangerous operations (`eval`, `subprocess(shell=True)`, unsafe unpickling), and inspects MCP configs.
- **AIBOM & Compliance Generation**: Produces CycloneDX 1.6 Artificial Intelligence Bill of Materials and maps findings to the **OWASP Top 10 for LLMs**, **NIST AI RMF 1.0**, and the **EU AI Act**.
- **Automated Self-Healing**: Synthesizes unified git diff patches (`agentscan fix`) and NeMo Guardrail policies to remediate detected vulnerabilities.
- **Fast CI/CD Security Gates**: In-process heuristic evaluation enables sub-5-second pre-commit checks without mandatory external LLM API dependencies.

---

## Who Is This For?

- **AI Engineers & Developers**: Validate system prompt robustness, test tool-calling boundaries, and prevent prompt injection before deploying agents to production.
- **Security & AppSec Teams**: Audit LLM applications for OWASP Top 10 for LLMs compliance, over-privileged tool scopes (RBAC), and dependency CVEs.
- **Red Teams & Penetration Testers**: Conduct automated multi-turn adversarial simulations, assess blast radius, and evaluate agent autonomy limits.
- **Platform & DevOps Engineers**: Embed deterministic, non-blocking security checks and SARIF reporting into GitHub Actions and CI/CD pipelines.

---

## Quick Start

### Prerequisites
- **Python**: 3.12 or higher
- **Package Manager**: [`uv`](https://github.com/astral-sh/uv) (recommended) or `pip`

### 1. Installation

```bash
# Clone the repository
git clone https://github.com/PrathaMesh3056/AgentScan.git
cd AgentScan

# Install dependencies using uv
uv sync
```

*(Alternatively with pip: `pip install -e .`)*

### 2. Run Your First Scan (60 Seconds)

To scan an active agent running locally or remotely:

```bash
# Scan a live agent endpoint and export a JSON report
uv run agentscan scan http://localhost:8000/chat --output report.json
```

If you don't have an agent running yet, verify AgentScan's evaluation engine instantly using the built-in benchmark (zero network required):

```bash
# Run the deterministic reference agent benchmark (369 test cases)
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

### 3. Launch the Threat Posture Dashboard

View findings, interact with the defense grid, and inspect full session trajectories:

```bash
uv run agentscan ui --report report.json
```
Navigate to `http://127.0.0.1:8765` to explore the interactive dashboard.

---

## How It Works

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

1. **Target Ingestion**: Communicates with agents over HTTP REST, captured cURL commands, Playwright headless browsers, WebSockets, or Model Context Protocol (MCP stdio/SSE).
2. **Adversarial Orchestration**: Dispatches attack suites concurrently using bounded async workers (`asyncio.Semaphore`) to avoid target rate-limiting, while guaranteeing deterministic finding order.
3. **Dual-Perspective Analysis**:
   - *Behavioral (Black-Box)*: Matches outputs against regex signatures, MiniLM semantic similarity embeddings, and optional LLM judges.
   - *Neural (White-Box / DEEP)*: Measures hidden state activation deltas on a local reference model to corroborate prompt injections at the latent representation level.
4. **Static Analysis & Supply Chain**: Parses dependency lockfiles (`uv.lock`, `poetry.lock`), queries OSV.dev for active advisories, audits AST for dangerous functions (`eval`, `torch.load` without `weights_only`), and analyzes MCP permission graphs.
5. **Remediation & Compliance**: Generates unified git diffs, exports CycloneDX 1.6 AIBOMs, and produces compliance mappings for NIST AI RMF and EU AI Act Articles 15/50.

---

## Key Capabilities

### 1. Live Target Scanning
- **OWASP Top 10 for LLMs 2025 Coverage**: Automated tests for prompt injection (`LLM01`), sensitive information disclosure (`LLM02`), supply chain vulnerabilities (`LLM05`), excessive agency (`LLM06`), and system prompt leakage (`LLM07`).
- **Exploit Verification**: Proves real-world blast radius via simulated data exfiltration, unauthorized tool invocation, and persistent agent memory poisoning.
- **Universal Connectors**:
  | Transport | Usage | Example |
  | :--- | :--- | :--- |
  | **HTTP JSON** | Standard API endpoints | `agentscan scan http://localhost:8000/chat` |
  | **cURL Replay** | Replays captured browser network requests | `agentscan scan --curl request.curl --message-path "prompt"` |
  | **Browser Widget** | Headless browser for UI-only chat widgets | `agentscan scan --browser-url http://localhost:3000 --input-selector "#msg"` |
  | **WebSocket** | Real-time streaming agents | `agentscan scan ws://localhost:8000/ws` |
  | **MCP (Stdio/SSE)** | Model Context Protocol servers | `agentscan scan mcp+sse://localhost:3000/sse` |

### 2. Static Code & Supply Chain Audit
Audit local agent projects without running active endpoints:
```bash
# Run a full static audit (dependencies, AST checks, secrets, MCP configs)
uv run agentscan audit ./my-agent-project

# Generate a CycloneDX 1.6 Artificial Intelligence Bill of Materials (AIBOM)
uv run agentscan audit ./my-agent-project --aibom --output aibom.cdx.json

# Fail CI builds on high-severity findings
uv run agentscan audit ./my-agent-project --fail-on HIGH --output audit.sarif
```

### 3. Automated Self-Healing (`agentscan fix`)
Plan and safely apply patches for vulnerabilities identified during scans or static audits:
```bash
# Preview proposed diffs in dry-run mode (safe preview)
uv run agentscan fix ./my-agent-project

# Apply fixes directly to disk
uv run agentscan fix ./my-agent-project --apply
```
Automated fixers include:
- `pin_bump`: Upgrades vulnerable dependencies in `requirements.txt` / `pyproject.toml` based on OSV.dev advisories.
- `ast_patch`: Enforces `torch.load(weights_only=True)`, removes `shell=True` subprocess calls, and disables debug flags.
- `identity_shrink`: Trims over-privileged or undeclared tool scopes in agent manifests.
- `guardrails`: Synthesizes Colang policy files for NeMo Guardrails targeting detected injection vectors.

---

## Benchmarks & Performance

Evaluation speed is fundamentally governed by evaluation architecture:

<div align="center">

<img src="assets/benchmark_speed.svg" alt="Evaluation Architecture Latency Comparison" width="100%" style="border-radius: 10px; margin: 12px 0;" />

</div>

| Framework / Tool | Observed Runtime *(350+ tests)* | Primary Architecture | External Token Cost | Hardware Requirement | CI/CD Integration Fit |
| :--- | :---: | :--- | :---: | :---: | :---: |
| **AgentScan (SCAN)** | **~2.1s** | In-process concurrent async (`asyncio.gather`) | **$0.00** | Standard CPU (1 core) | **Ideal (< 3s gate)** |
| **AgentScan (DEEP)** | **~4.8s** | SCAN heuristics + local CPU neural probing | **$0.00** | Standard CPU (8GB RAM) | Fast nightly regression |
| **Promptfoo** | ~45s – 120s | Node.js concurrent runner + Cloud LLM judge | $0.50 – $3.00 | Standard CPU | Moderate PR check |
| **PyRIT (Microsoft)** | ~180s – 600s | Multi-turn red-teaming loops (Attacker + Judge) | $2.00 – $10.00 | Standard CPU | Scheduled audit |
| **Garak (NVIDIA)** | ~1,980s *(~33m)* | Sequential generator-detector probe matrix | $10 – $30 *(or GPU)* | GPU recommended | Deep model benchmark |

> [!NOTE]
> **Methodology & Context**:
> - Benchmarks reflect architectural throughput characteristics rather than identical evaluation scopes.
> - AgentScan's baseline measurement was conducted on a local testbed (Python 3.12, x86_64 CPU, localhost HTTP mock agent endpoint).
> - Cloud LLM-as-a-judge timings are modeled assuming a 100-probe suite requiring 200–400 sequential or batch API calls at ~1.5s p50 latency, excluding potential HTTP 429 rate-limit backoffs.
> - In our latest performance release, full test suite execution was optimized from **154.0s** down to **114.9s** (**~26% overall speedup** across 482 tests) via bounded concurrency semaphores, precompiled regex caching, and vectorized PyTorch tensor operations.

### Reproducing the Benchmark
Verify discriminating power and scoring integrity on your own hardware:
```bash
uv run agentscan benchmark
```

---

## Documentation

Comprehensive guides, architectural details, and references are available in the [`docs/`](docs/) directory:

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

### Upcoming Milestones
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

We welcome contributions from the community! Adding a new attack module, improving documentation, or optimizing connectors is straightforward:

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

# Run full test suite
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
