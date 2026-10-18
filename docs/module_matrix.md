# Complete Module Engineering Status Matrix

This document lists engineering features in **AgentScan**. Status indicates implementation presence, not verified production readiness or detector accuracy. The current [architecture and function guide](../internal_docs/diagrams/README.md) and [repair status](../internal_docs/diagrams/repair-status.md) provide source coverage, verification and limits.

---

## 📋 Comprehensive Module Status

| Module | Scope | Status | Key Subsystems & Deliverables |
| :--- | :--- | :---: | :--- |
| **0** | Foundation | ✅ | Pydantic v2 core models, strict typing, base runner, registry auto-discovery, CI pipeline |
| **1** | Core Attack Engine | ✅ | CLI commands (`scan`, `audit`, `fix`, `ui`), severity scorer, parallel async runner, 24 direct prompt-injection seeds assessed against known confidentiality criteria ([ATK-001 setup and limits](modules/prompt_injection.md)) |
| **ATK-001 update** | Direct prompt injection against a known private reference | Complete for scope, 10 October 2026 | 24 seeds, deterministic complete-disclosure evidence, missing-reference inconclusive states, input provenance, redaction and CLI/UI setup; broader representations and independent real-agent efficacy remain follow-up work ([completion verification](modules/prompt_injection.md#completion-verification)) |
| **ATK-012 update** | Complete known confidential prompt/reference disclosure | Engineering update, 16 October 2026; live evaluation pending | Ten retained probes, reference preflight, payload/mutation/captured-body provenance, digest-only evidence and disabled judge fallback. Encoded/partial extraction and independent model efficacy remain outside verified scope ([setup and limits](modules/system_prompt_leak.md)). |
| **ATK-003 update** | Complete known private-value disclosure | Engineering update, 16 October 2026; live evaluation pending | 13 direct-user probes, private-value-only baseline, shared captured-body provenance, digest-only evidence and disabled judge fallback. No inferred record authenticity, tenant switch or network-transfer proof; current primary-source review documented ([setup and limits](modules/pii_exfiltration.md)). |
| **ATK-007 update** | Default response inventory; optional owned browser/SQLite consumer witnesses | Consumer engineering/control validation, 16 October 2026; real-agent efficacy open | Default 12-probe inventory stays inconclusive without a trusted Python consumer witness. Local findings are excluded from customer scores. Frozen controls passed all 48 runs; 24 offline model generations produced only 5/24 complete consumer assessments per arm and 0/12 benign utility, so efficacy remains inconclusive. Includes truthful report labels, terminal-preview defense and published references ([setup, results and limits](modules/output_handling.md)). |
| **ATK-006 update** | Default response inventory; optional approved MCP catalog comparison | Implemented and locally verified, 17 October 2026 | Eight retained user-message probes produce hashed proposal observations and remain impact-inconclusive. An independent endpoint/tool-definition baseline selects a catalog-only SCAN with one `mcp_catalog_policy` comparison, separately scoped MEDIUM deviations and no overall score. No judge, automatic first-response approval or downstream execution proof; metadata injection/rug pulls and real-agent efficacy remain open ([setup and references](modules/mcp_shadow.md)). |
| **ATK-013 update** | Target-reported agency proposals/status inventory | Engineering locally verified, 18 October 2026 | Ten unchanged seeds; bounded whole-response hashes and proposal/completion/pending counts, separate CLI/dashboard/HTML presentation, no judge/attacker/mutation expansion. No authorization/effect findings or evaluated negatives; pure inventory score/SSP are null. Independent witnesses and real-agent efficacy remain open ([setup and references](modules/excessive_agency.md)). |
| **2A** | AI Supply-Chain (AICS) | ✅ | Dependency CVE scanning, unsafe config audit, hardcoded secret regexes, typosquatted AI packages, MCP server config inspection |
| **2B** | Identity & Authorization | ✅ | Agent manifest parser, tool privilege mapping, over-scoped identity detection (`ID-001`..`ID-010`) |
| **3A/3B** | EXPLOIT Mode | ✅ | System prompt exfiltration proof, tool hijacking, memory poisoning, cross-agent injection, credential harvesting |
| **4** | Enterprise Reporting | ✅ | Dark-mode interactive HTML reports, vector PDF reports (WeasyPrint), SARIF (GitHub Code Scanning), NIST / EU AI Act / MITRE ATLAS compliance mapper |
| **5A** | DEEP Mode Infrastructure | ✅ | PyTorch CPU activation hooks, latent noise floor calibration, $L_2$ & cosine shift probes (`ATK-023`) |
| **5B** | AI-Driven Engine | ✅ | Deterministic default; explicit installed local Ollama analysis; optional OpenAI/Anthropic/Gemini analysis for designated non-sensitive scans only; semantic MiniLM similarity |
| **5C** | Universal Connectors | ✅ | `HttpJsonConnector`, `RequestTemplateConnector` (`--curl` with SSE streaming & multi-turn), `BrowserConnector` (Playwright headless), `AgentScanClient` facade, `agentscan init` auto-discovery |
| **5D** | Traffic Visibility | ✅ | Always-on `TrafficRecorder`, real-time verbose payload streaming (`--verbose`), full session trace export (`--transcript`) |
| **5E** | Adaptive Red-Teaming | ✅ | Adaptive attacker (`ATK-050`), strict boolean judge, seeds, synthetic local protocol controls (`calibrate`), synthetic fixture smoke check (`benchmark`), opt-in local transcripts; independent accuracy unverified |
| **6A** | Advanced SCAN Payloads | ✅ | Persona jailbreak (`ATK-002`), PII exfiltration (`ATK-003`), DoS/context explosion (`ATK-004`), opt-in document injection (`ATK-005`, [HTTP adapter contract](modules/indirect_injection.md)), MCP proposal inventory/approved-catalog comparison (`ATK-006`, [scope](modules/mcp_shadow.md)), multi-encoding mutation (`--mutate`). ATK-005 tool ingestion is unassessed; unsupported adapters stay unavailable. |
| **6B** | Live OSV.dev CVE Ingestion | ✅ | Real-time batch vulnerability querying (`querybatch`) with exact PyPI pin resolution; offline vulnerability database fallback |
| **6C** | Graph-Based RBAC Audit | ✅ | NetworkX multi-hop privilege escalation graph modeling (`ID-010`), cross-agent calling edges, shared credential discovery |
| **6D** | Trajectory & SSP Analysis | ✅ | Autonomous agent trajectory tracing, Servant / Stalker / Predator behavioral classification engine |
| **6E** | OWASP LLM Scenarios | ✅ | OWASP 2025: output handling (`ATK-007` / LLM05), RAG integrity (`ATK-008` / LLM08), misinformation (`ATK-009` / LLM09), Crescendo (`ATK-010` / LLM01), model/data disclosure (`ATK-027` / LLM02); unmapped evidence stays unmapped |
| **7A** | Advanced Neural Probing | ✅ | Reference-model rare-token anomalies (`ATK-024`), attention statistics (`ATK-025`), fingerprinting (`ATK-026`); reference observations excluded from remote-target score |
| **7B** | Real-Time Agent Transports | ✅ | MCP stdio/SSE connector (`mcp://`), WebSocket streaming connector (`ws://`, `wss://`) |
| **7C** | Supply-Chain Standards | ✅ | CycloneDX 1.6 AIBOM generation (`audit --aibom`), Composite GitHub Action (`action.yml`) |
| **7D** | Interactive Web Dashboard | ✅ | FastAPI local control center (`agentscan ui`), dynamic RBAC graph visualization, live traffic inspector, attack suite launcher and local coverage/severity/status/duration charts with keyboard filters and module table ([chart contract](DASHBOARD_ANALYTICS_PLAN.md)) |
| **8** | Self-Healing Remediation | ✅ | Automated AST patching (`torch.load`, `shell=False`, `DEBUG=False`), OSV dependency auto-bump, NeMo Guardrail policy synthesis (`agentscan fix`) |

---

## 🏛️ Architecture Map

```
                     ┌─────────────────────────────────────────┐
                     │            User Interfaces              │
                     │  CLI (Typer/Rich)  •  Web UI (FastAPI)  │
                     └────────────────────┬────────────────────┘
                                          │
                     ┌────────────────────▼────────────────────┐
                     │            AgentScan Engine             │
                     │    Target Models  •  Execution Runner   │
                     └──────┬───────────────────────────┬──────┘
                            │                           │
         ┌──────────────────▼──────────┐     ┌──────────▼─────────────────┐
         │       Offensive Core        │     │       Defensive Core       │
         │ • SCAN: Static & Semantic   │     │ • AICS: CVEs & Secrets     │
         │ • EXPLOIT: Active Proofs    │     │ • Identity: RBAC Graph     │
         │ • DEEP: Neural Activations  │     │ • Remediation: AST Patches │
         │ • AI Attacker: Multi-Turn   │     │ • Compliance: EU AI / NIST │
         └─────────────────────────────┘     └────────────────────────────┘
```
