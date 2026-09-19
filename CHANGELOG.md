# Changelog

All notable changes to **AgentScan** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0-alpha] - 2026-09-19

### Added
- **OWASP Top 10 for LLMs 2025 Automated Test Suites**: Direct prompt injection (`ATK-001`), jailbreak attacks (`ATK-002`), PII exfiltration (`ATK-003`), denial-of-service (`ATK-004`), indirect prompt injection (`ATK-005`), MCP shadowing (`ATK-006`), output handling (`ATK-007`), RAG poisoning (`ATK-008`), overreliance (`ATK-009`), Crescendo escalation (`ATK-010`), multilingual alignment bypass (`ATK-011`), system prompt leakage (`ATK-012`), and excessive agency (`ATK-013`).
- **Universal Connectors**: HTTP REST, cURL replay (`--curl`), Playwright headless browser widgets (`--browser-url`), WebSockets (`ws://`, `wss://`), and Model Context Protocol (`mcp://stdio`, `mcp+sse://`).
- **AI Supply Chain & Dependency Security (AICS)**: Batch queries to OSV.dev database with offline fallbacks, lockfile version range analysis (`uv.lock`, `poetry.lock`), and CycloneDX 1.6 Artificial Intelligence Bill of Materials (AIBOM) export.
- **Native Python AST Security Engine**: Zero-external-dependency static analysis detecting unsafe `pickle`, `torch.load` without `weights_only=True`, `subprocess(shell=True)`, `eval`, and `exec`.
- **Zero-Trust Identity & RBAC Analysis**: Agent manifest parser, NetworkX multi-hop privilege escalation graph, and permission shrink remediation.
- **DEEP Mode (Neural Activation Probing)**: Local CPU hidden state representation shift analysis ($L_2$ distance and cosine similarity) on `Qwen/Qwen2.5-0.5B-Instruct` against calibrated benign noise floors.
- **EXPLOIT Mode (Active Impact Verification)**: Blast-radius proofs for data exfiltration (`ATK-014`), tool hijacking (`ATK-015`), and persistent memory poisoning (`ATK-016`).
- **Automated Self-Healing (`agentscan fix`)**: Generates unified git diff patches and NeMo Guardrail Colang policies to remediate detected vulnerabilities.
- **Reporting Engine**: Machine-readable JSON, OASIS SARIF 2.1.0 for GitHub Code Scanning, standalone HTML, and print-ready PDF via WeasyPrint.
- **Interactive Web Dashboard**: Local FastAPI application (`agentscan ui`) with real-time SSE streaming, defense grids, and full session trajectory inspection.
- **Multi-Agent Red-Team Swarms (`agentscan swarm`)**: Coordinated Recon, Bypass, Exploit, and Judge agent teams over a shared blackboard.
- **Native MCP Server (`agentscan mcp-serve`)**: Exposes AgentScan scanning, auditing, and attack listing tools over Model Context Protocol JSON-RPC 2.0 stdio.

### Changed
- **High-Throughput Concurrency & Latency Optimization**:
  - Implemented bounded intra-module variant execution via `asyncio.Semaphore(target.concurrency)` with indexed sorting for deterministic findings order.
  - Added global in-flight connection throttling (`_GLOBAL_SEMAPHORE` in `AgentScanClient`) to prevent target rate-limiting and connection resets.
  - Implemented compiled regex caching (`_compile_regex`) and LLM judge verdict memoization (`_cached_judge`).
  - Vectorized CPU neural activation distance and cosine similarity calculations with `torch.inference_mode()`.
  - Parallelized HTTP API discovery body shape probing (`discover_http`) with 6.0s timeouts.
  - Reduced full test suite execution time from 154.0s to 114.9s (~26% speedup across 482 tests).
