<div align="center">

<img src="assets/logo.svg" alt="AgentScan Logo" width="100" height="100" />

# AgentScan

**AgentScan is an open-source security scanner for testing prompt injection, jailbreaks, tool misuse, and other risks in LLM applications and AI agents.**

[![CI](https://github.com/PrathaMesh3056/AgentScan/actions/workflows/ci.yml/badge.svg)](https://github.com/PrathaMesh3056/AgentScan/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg?logo=python&logoColor=white)](https://www.python.org/)
[![Version](https://img.shields.io/badge/version-0.1.0--alpha-orange.svg)](https://github.com/PrathaMesh3056/AgentScan/releases)

<br>

<img src="assets/dashboard_preview.png" alt="AgentScan Dashboard Preview" width="100%" style="border-radius: 10px; border: 1px solid #1e293b;" />

</div>

---

AgentScan helps developers and security teams evaluate AI agents before deployment. It can test live agent endpoints, audit source repositories and dependencies, and export findings for local review or CI/CD workflows.

---

## Key Features

- **Prompt injection and jailbreak testing**: Evaluate resistance against direct and indirect prompt injection, system prompt leakage, and multi-turn escalation.
- **Tool-use and agent behavior testing**: Verify tool authorization boundaries, detect unsolicited command execution, and test for privilege escalation.
- **Static source and dependency auditing**: Identify vulnerable AI packages via OSV.dev and detect dangerous Python calls (`eval`, `exec`, unpinned deserialization) using AST inspection.
- **Multiple target interfaces**: Scan HTTP endpoints, cURL replays, headless browser chat widgets, WebSocket streams, and Model Context Protocol (MCP) servers.
- **Standardized reporting**: Export findings to JSON, self-contained HTML, print-ready PDF, and OASIS SARIF 2.1.0 for GitHub Code Scanning.
- **CLI and optional web/API interfaces**: Run scans from the command line, explore results in an interactive local dashboard (`agentscan ui`), or dispatch jobs through an optional REST API.

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

# Install dependencies with uv
uv sync
```

*(Alternatively with pip: `pip install -e .`)*

### 2. Run a Security Scan

Run a scan against a local or staging agent endpoint:

```bash
uv run agentscan scan http://localhost:8000/chat --output report.json
```

### 3. Run the Local Benchmark

Verify the scoring engine locally against reference agents without needing external network access or API keys:

```bash
uv run agentscan benchmark
```

> [!IMPORTANT]
> **Authorized Testing Only**: Only scan systems, applications, or endpoints that you own or have explicit, documented permission to test.

---

## Supported Targets

| Target Type | Command Example | Description |
| :--- | :--- | :--- |
| **HTTP Endpoint** | `agentscan scan <url>` | Probes REST/JSON chat endpoints. |
| **cURL Request** | `agentscan scan --curl request.curl` | Replays captured HTTP requests with headers and cookies. |
| **Browser Application** | `agentscan scan --browser-url <url>` | Automates web chat widgets using headless Playwright. |
| **WebSocket Endpoint** | `agentscan scan ws://<host>/<path>` | Connects to persistent streaming WebSocket agents. |
| **MCP Server** | `agentscan scan mcp+sse://<host>/<path>` | Audits Model Context Protocol tools and resources. |
| **Local Source Tree** | `agentscan audit <path>` | Scans repositories, lockfiles, and codebases statically. |

---

## CI/CD Integration

AgentScan can run as a quality and security gate in GitHub Actions workflows:

```yaml
name: Agent Security Scan
on: [pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run AgentScan
        uses: PrathaMesh3056/AgentScan@v1
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

See [`action.yml`](action.yml) and the [Project Manual](docs/AgentScan_Manual.md) for full configuration options, failure thresholds, and local action usage.

---

## Output & Documentation

Findings can be exported as JSON, HTML, PDF, and SARIF. For detailed configuration and usage guides, refer to the documentation:

| Document | Description |
| :--- | :--- |
| 📖 [**Project Manual**](docs/AgentScan_Manual.md) | Complete guide covering CLI flags, connectors, and configuration options. |
| 🛡️ [**Threat Model**](docs/threat_model.md) | Security assumptions, detection boundaries, and OWASP Top 10 for LLMs mapping. |
| 🥊 [**Comparison Guide**](docs/comparison.md) | Technical comparison with Garak, Promptfoo, PyRIT, and Snyk. |
| 🔬 [**DEEP Mode Guide**](docs/deep_mode.md) | Mathematical formulation and usage for latent neural activation probing. |
| 🌐 [**REST API Guide**](docs/api.md) | Setting up the optional FastAPI service, Redis task queue, and SSE streaming. |
| 📊 [**Benchmark Methodology**](docs/benchmarks.md) | Latency benchmarks, architectural comparison, and reproducibility instructions. |
| 🤝 [**Contributing Guide**](CONTRIBUTING.md) | Development setup, code quality standards, and custom attack module authoring. |

---

## Project Status

AgentScan is currently in alpha (`v0.1.0-alpha`). Core scanning, static auditing, reporting, and CLI workflows are under active development. Interfaces and output formats may change between releases.

See [ROADMAP.md](ROADMAP.md) for completed milestones and planned features.

---

## Responsible Use

AgentScan is intended for authorized security testing only. Do not scan systems, applications, or endpoints without explicit permission from the owner.

To report a security vulnerability in AgentScan itself, please refer to our [Security Policy](SECURITY.md).

---

## Contributing & License

Contributions are welcome. Please review our [Contributing Guidelines](CONTRIBUTING.md) and [Code of Conduct](CODE_OF_CONDUCT.md) before submitting pull requests.

Distributed under the [Apache 2.0 License](LICENSE).
