# Changelog

All notable changes to **AgentScan** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added

- Updated ATK-011 with 18 multilingual confidentiality probes, private-reference evidence, honest per-language coverage and paired local evaluation. Public words and activation markers no longer establish a breach; see [setup, limits and research references](docs/modules/multilingual.md).
- Updated ATK-002 with 18 bounded persona probes, known-reference confidentiality evidence, completion/provenance checks and offline paired validation. Public markers and judge opinion no longer establish safeguard failure; see [setup, evaluation and published references](docs/modules/jailbreak.md).
- Added ATK-009's optional client-approved exact-answer baseline across CLI profiles, dashboard and service jobs. Paired neutral/pressure checks produce separate factuality-policy deviations, with digest-only traffic retention and no security score; see [setup, evaluation and references](docs/modules/overreliance.md).
- Explore scan coverage, finding severity, module status and elapsed time in the dashboard's **Overview → Scan evidence** charts. Keyboard severity filters open matching findings; the module table retains scopes, errors and unevaluated checks. See [chart behavior](docs/DASHBOARD_ANALYTICS_PLAN.md).
- Expanded ATK-001 to 24 direct-user seeds for its known-reference confidentiality assessment. See [terminal/dashboard setup and detection limits](docs/modules/prompt_injection.md).
- Added ATK-005's opt-in HTTP `document_v1` adapter with seven document patterns, separate task/source delivery and probe/source/content-bound consumption receipts. Dashboard, CLI profiles and service jobs expose the setting; see [setup and receipt requirements](docs/modules/indirect_injection.md).
- Added ATK-008's owned SQLite retrieval fixture with authenticated source admission, a narrow structured-answer reconciliation policy, local consume-once witnesses, and optional cached offline-model evaluation. Owned effects appear separately in CLI, dashboard and HTML reports; see [scope and setup](docs/modules/rag_poisoning.md).

### Fixed

- Completed YAML-runner findings survive connector cleanup failures, with safe diagnostics and incomplete status retained. ATK-002 excludes generated HTTP-header reflections from private-disclosure evidence and keeps captured HTTP errors, unverified browser completion and budget exhaustion outside evaluated safety results.
- ATK-009's eight legacy probes now retain bounded observations without promoting marker echoes, fabricated facts or reported tool calls into verified impact. Invalid, incomplete and failed replies remain visible; approved-answer inputs reject ambiguous duplicate keys and incompatible workflows before target access.
- ATK-001 requires complete supported disclosure of an operator-known private reference; public markers and judge inference cannot substitute for evidence. Missing references remain inconclusive, attacker-supplied references are excluded, and supported private representations are redacted in ordinary transcripts.
- ATK-005 requires a complete known private reference and target-reported document ingestion evidence. Public markers and fabricated chat/tool roles no longer count as indirect-boundary proof. Unsupported connectors are unavailable; missing or mismatched receipts remain inconclusive, and completed findings survive partial coverage. The original nine simulation seeds remain archived; actual tool ingestion is unassessed.
- ATK-008's eight retained remote probes now require explicit document delivery. Marker echoes, fabricated citations and model-judge claims remain bounded observations rather than poisoning findings; missing ingestion evidence and unassessed effects remain visible without changing customer scores.
- Tenant-scoped persistent `Idempotency-Key` support for scan submissions, including concurrent retries, quotas, retention and changed-request conflicts.
- MCP client configuration audits support nested declarations and common client filenames while retaining incomplete coverage and static provenance.
- HTTPS MCP target selection is consistent between the target model, dashboard forms and connector registry.
- Deployment profiles install locked dependencies and run as non-root; dashboard publishing defaults to loopback. Kubernetes templates require verified image digests and explicit target egress.

### Documentation and validation

- Marked the scoped ATK-001 and chart implementation complete on 10 October 2026: 1,627 ordinary tests passed, 32 skipped and 8 slow tests deselected; 82 chart contracts are included in that total. All 18 synthetic-report browser checks passed, and configured Linux/Python 3.12 mypy passed for 182 source files. These results do not establish independent detector accuracy or production deployment readiness.
- Added startup/attack, data-policy, architecture, deployment-readiness and dashboard feature guides. Detailed diagrams and local verification receipts remain private in `internal_docs/diagrams/`.
- Verified repeated submissions and worker recovery against disposable PostgreSQL/Redis, offline CPU reference inference and Linux Docker sandbox controls. GPU and production Kubernetes remain separate verification requirements.

## [0.2.0] - 2026-09-27

### Added
- **Zero-CVE Cryptographic Subsystem & Asymmetric Ed25519 Auth (Phase 0)**:
  - Completely replaced `python-jose` with `cryptography>=43.0.0` and `pyjwt[crypto]>=2.9.0`, permanently remediating CVE-2024-33663 and CVE-2024-33664.
  - Added `CryptographicEngine` (`agentscan.guard.crypto`) featuring AES-256-GCM-SIV nonce-misuse-resistant authenticated encryption (RFC 8452), Argon2id key derivation (RFC 9106), CSPRNG nonces (NIST SP 800-90A), and constant-time secret comparison.
  - Added `Ed25519TokenManager` (`agentscan.api.auth`) providing asymmetric Ed25519 (EdDSA / RFC 8032) token minting and public-key verification.
- **Runtime Capability Firewall & Tool Protection (Phase 1)**:
  - `CanonicalPathGuard` (`agentscan.guard.path`): Realpath containment engine defeating directory traversal (`../`), null-byte injection, and symlink escapes with <0.5ms average latency.
  - `PosixCommandGuard` (`agentscan.guard.command`): Parameterized execution engine enforcing binary allowlists, strict `shell=False`, and neutralizing shell injection vectors (pipes, subshells, chaining).
  - `CapabilityGuard` & `@protect_tool` (`agentscan.guard.firewall`): In-flight parameter validation decorator supporting Pydantic schema validation, domain allowlisting, and structured JSON error feedback for agent self-correction.
  - `MCPCapabilityProxy` (`agentscan.guard.mcp_proxy`): Transparent stdio JSON-RPC 2.0 proxy inspecting tool call parameters at the protocol layer.
- **Tiered Exploit Verification Sandbox (Phase 2)**:
  - `select_sandbox()` (`agentscan.sandbox.selector`): Tiered sandbox selector auto-negotiating the highest isolation tier available on the host: gVisor (`runsc`) -> Docker (`ContainerSandbox`) -> Bubblewrap (`BubblewrapSandbox`) -> Subprocess Audit (`SubprocessAuditSandbox`).
  - Standardized `SandboxResult` schema capturing exit code, stdout/stderr, execution duration in milliseconds, memory ceiling status, and before/after filesystem mutation diffs.
  - Hardened container profiles with `CapDrop=ALL`, `ReadonlyRootfs=True`, `--network none`, `Memory=512MB`, `NanoCPUs=1`, and writable tmpfs mounts.
- **Bounded Swarm Red-Teaming & TAP Pruning (Phase 3)**:
  - `BoundedSwarmController` (`agentscan.swarm.budget`): Strict resource bounds preventing runaway agent reasoning loops via round ceilings, token ceilings, and Tree of Attacks with Pruning (TAP)-style early exit upon confirmed exploit discovery.
  - Enriched `SwarmReport.budget_summary` telemetry recording rounds used, tokens consumed, and exact termination reasons.
- **Self-Healing Git PR Automation (Phase 4)**:
  - `GitPRAutomator` (`agentscan.remediation.git_pr`): Automated local branch checkout, diff application, semantic commit authoring, and GitHub Pull Request publication via `gh pr create`.
  - Added `--apply --pr` flag to `agentscan fix` command, generating ready-to-merge GitHub pull requests complete with OWASP categorization and unified diff summaries.
- **Cross-Agent Workspace Poisoning Exploit Module (Phase 5)**:
  - `WorkspacePoisonModule` (`ATK-020`, OWASP `LLM03`): Multi-hop exploit simulation testing indirect prompt injection through shared SQLite conversation databases, in-memory/vector RAG backdoors, and workspace override files (`WORKSPACE_INSTRUCTIONS.md`).
  - Added `agentscan/attacks/payloads/workspace_poison.yaml` defining test vectors, canaries, and override instructions.
  - Enriched exploit findings with `SandboxResult` telemetry when sandbox subsystem is active.
- **Integration Test & Benchmark CI Gates (Phase 6)**:
  - Full end-to-end integration test (`tests/integration/test_e2e_pipeline.py`) validating the scan -> find -> fix -> rescan resolution lifecycle.
  - Performance benchmark (`benchmarks/test_scan_speed.py`) asserting deterministic scan pack executes in <3000ms mean (~71ms achieved).
  - CLI version flag (`agentscan --version`) exposing `0.2.0`.

### Security
- Resolved all known cryptographic CVEs across the AgentScan dependency tree.
- Hardened sandbox execution by running workloads with dropped capabilities, read-only root filesystems, and unprivileged user mappings.

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
