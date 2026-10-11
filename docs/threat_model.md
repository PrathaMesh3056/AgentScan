# AgentScan — Security Threat Model

This document outlines the security assumptions, capabilities, detection boundaries, and data handling practices of **AgentScan**.

---

## 1. System Overview

AgentScan is an evaluation and security assessment platform for autonomous AI agents and Large Language Model (LLM) applications. It operates in two primary modes:
1. **Live Target Mode (`scan`)**: Actively dispatches structured adversarial payloads across network interfaces (HTTP REST, cURL replay, Playwright browser widgets, WebSockets, or Model Context Protocol) and evaluates agent responses.
2. **Static Audit Mode (`audit`)**: Passively inspects local repository files, Python ASTs, lockfiles (`uv.lock`, `poetry.lock`), agent manifests, and MCP configuration files.

---

## 2. Detection Capabilities (What AgentScan Can Detect)

AgentScan is designed to identify vulnerabilities aligned with the **OWASP Top 10 for LLMs 2025**, **NIST AI RMF 1.0**, and the **EU AI Act**:

| Category | Finding Types | Detection Technique |
| :--- | :--- | :--- |
| **LLM01: Prompt Injection** | Direct injection, system prompt override, multilingual bypasses | In-process MiniLM sentence embeddings, regex heuristics, and optional LLM-as-a-Judge |
| **LLM02: Sensitive Information** | Credential disclosure, API key leakage, PII extraction | Deterministic pattern matching, regex scanning, ground-truth comparison |
| **LLM03: Supply Chain Risks** | Known CVEs in dependencies, lockfile version range vulnerabilities | Batch queries to OSV.dev database with offline cache |
| **LLM05: Insecure Deserialization** | Unsafe `pickle.loads()`, `torch.load()` without `weights_only=True`, `numpy.load(allow_pickle=True)` | Native Python AST inspection (`NativeSemgrepEngine`) |
| **LLM06: Excessive Agency** | Over-privileged tool access, unsolicited destructive tool calls | Manifest scope parsing, NetworkX multi-hop privilege escalation graph |
| **LLM07: System Prompt Leakage** | Extraction of developer instructions, hidden constraints, and secrets | Refusal suppression, seed jailbreak libraries, semantic distance scoring |
| **Neural Representation Shifts** | Latent activation spikes corroborating behavioral prompt injection | Dual-axis $L_2$ and cosine divergence probing on local CPU models (`ATK-023`) |

---

## 3. Limitations & Non-Goals (What AgentScan Cannot Detect)

AgentScan is an automated evaluation harness and cannot provide mathematical guarantees of immunity against all adversarial risks:

- **Novel Zero-Day Jailbreaks**: Adaptive or bespoke prompt injections that do not match existing behavioral heuristics, embedding thresholds, or evaluation rubrics may bypass detection.
- **Physical & Network-Level Attacks**: AgentScan does not assess transport-layer vulnerabilities, TLS misconfigurations, DNS spoofing, or infrastructure-level DDoS attacks.
- **Hardware & Memory Tampering**: Side-channel attacks, GPU rowhammer, or direct RAM manipulation outside the Python runtime process are out of scope.
- **Business Logic Flaws**: Domain-specific logical errors that do not violate security policies or tool authorization boundaries cannot be detected automatically.

---

## 4. False Positives & False Negatives

- **False Positives**:
  - May occur when an agent legitimately quotes an adversarial instruction as part of a safe refusal (e.g., *"You asked me to print my system prompt, but I cannot do that"*).
  - Mitigation: AgentScan combines exact keyword exclusions, sequence matchers, and sentence embedding similarity thresholds (calibrated at $\ge 0.40$) to distinguish compliance from refusal.
- **False Negatives**:
  - May occur if an agent complies with an attack using highly obfuscated, creative, or metaphorical language that evades both regex and MiniLM cosine thresholds.
  - Mitigation: Enabling `--judge-model` adds semantic LLM-as-a-Judge evaluation, and `--deep` corroborates findings via internal model hidden states.

---

## 5. Non-Destructive Scanning Guarantee

By default, AgentScan is **strictly non-destructive**:
- The standard `agentscan scan` suite tests responses without executing mutating state changes on the target system.
- In `EXPLOIT` mode (`--exploit`), active proofs (such as tool hijacking or memory poisoning simulations) are executed against the target agent. Users must only execute `EXPLOIT` mode against designated staging, test, or isolated sandbox environments.
- In `agentscan fix`, remediation diffs run in **dry-run mode by default**. Changes are only written to disk when the user explicitly passes the `--apply` flag.

---

## 6. Data Storage & Privacy

### Local Telemetry
- **Reports & Transcripts**: Generated JSON, HTML, PDF, and SARIF reports are written strictly to the user's local filesystem at the path specified by `--output` or `--transcript`.
- **Credential Redaction**: By default, transcripts, traffic logs, and output reports redact detected API keys (`sk-...`, Bearer tokens) and passwords unless `--include-sensitive-data` is explicitly enabled.
- **Local Dashboard**: The `agentscan ui` web interface binds to `127.0.0.1` by default and does not transmit telemetry to external cloud servers.

### Analysis destinations and sensitive data

Analysis defaults to deterministic checks and sensitive classification. An explicit local mode uses installed Ollama weights at a literal loopback address, with no automatic cloud fallback. Configure the daemon with cloud features disabled and restrict its outbound network access independently when offline operation is required.

External analysis is optional for client-designated non-sensitive scans only. It requires explicit mode, classification, provider/model and a locally configured OpenAI, Anthropic or Gemini key; API tenants also need administrator permission. A key by itself never enables a provider call. Sensitive or undesignated external work is rejected before analysis I/O.

External opt-in can send relevant objectives and target responses to the selected provider. Credential redaction does not classify arbitrary confidential prose, so clients must determine which scans can be designated non-sensitive. No provider URL or key is accepted in an API scan body or dashboard scan form. See [data policy](DATA_POLICY.md) for setup, encrypted service jobs, report retention and the distinction between analysis traffic and explicitly selected target/OSV traffic.
