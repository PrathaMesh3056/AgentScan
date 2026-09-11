# AgentScan

**Open-source security scanner for AI agents** — red-teaming attack engine, active exploit proofs, AI supply-chain auditing, identity/authorization analysis, and neural activation probing, with HTML / PDF / SARIF reporting.

AgentScan treats an LLM agent the way a pentest tool treats a web app: it fires a battery of attack modules at a live endpoint, statically audits the project that ships it, and produces a single scored report mapped to the OWASP LLM Top 10.

---

## Highlights

- **Zero-wiring plugin architecture.** Drop a file into `attacks/scan/`, `exploit/`, or `deep/` and the registry auto-discovers it — no central list to edit.
- **Three escalating scan modes.** `SCAN` (passive detection) → `EXPLOIT` (active proof-of-impact) → `DEEP` (model-internal activation analysis).
- **Static project auditing.** Dependencies (CVEs), dangerous config, hardcoded secrets, typosquatted packages, MCP server configs, and agent identity/RBAC.
- **Adaptive AI red-teaming.** An attacker LLM fires proven jailbreaks + an LLM-as-a-Judge scores each reply, adapting over N turns — plus a **positive-control `calibrate`** (proves the attacker/judge actually detect a jailbreak) and a **`benchmark`** (proves the score ranks vulnerable vs. safe agents). Runs on OpenRouter, local Ollama, or any cloud model.
- **Provider-agnostic AI testing.** A single `litellm`-backed `AIClient` drives attacker/judge models across OpenAI, Anthropic, Gemini, and Ollama; semantic detection uses MiniLM sentence embeddings, not brittle word overlap.
- **Reach real agents, not just documented endpoints.** Pluggable transport connectors — captured-request replay (`--curl`, with SSE streaming + multi-turn handled), a real-browser driver (`--browser-url`, Playwright), **MCP stdio/SSE**, and **WebSocket** (`ws://` / `wss://`) — let every attack module test an agent unchanged.
- **Report anywhere.** JSON, styled HTML, PDF, and SARIF (for CI / code scanning), plus a compliance mapper.
- **Production-grade engineering.** Pydantic models as the single source of truth, immutable findings, fully async execution, strict typing, `ruff` + `mypy` clean, 208+ tests.

---

## Install

Requires Python **3.12+** and [`uv`](https://docs.astral.sh/uv/).

```bash
git clone <repo-url> AgentScan
cd AgentScan
uv sync
```

PyTorch (used only by DEEP mode) pulls the CPU wheel; the model is downloaded lazily on first `--deep` run.

---

## Usage

AgentScan exposes three commands via the `agentscan` entry point.

### `scan` — attack a live agent endpoint

```bash
uv run agentscan scan http://localhost:8000/chat
```

| Flag | Effect |
|---|---|
| `--framework <name>` | Agent framework (`auto` detects it) |
| `--exploit` | Also run active EXPLOIT modules (data exfiltration, tool hijack, memory poison, cross-agent injection, credential harvest) |
| `--deep` | Also run DEEP mode neural activation probes (local open-weight model) |
| `--mutate` | Expand SCAN YAML payloads with Base64, leetspeak, ZWSP, token-split, homoglyph, and wrap variants (skips timeout / min_length / payload_repeat) |
| `--system-prompt <text>` | Known system prompt — enables exfiltration verification |
| `--output report.{json,html,pdf,sarif}` | Write a report in the format inferred from the extension |
| `--fail-on <SEVERITY>` | Exit code 1 if any finding is at or above this severity (CI gate) |
| `--auth-header <value>` | Send an Authorization header (`Bearer …` or `Header: value`) on HTTP scans |
| `--curl <file>` | Replay a captured request (Chrome → Copy as cURL) with payloads substituted — scan an agent behind a website widget. Pair with `--message-path` (and optional `--response-path`) |
| `--config <file>` / `-c` | Load a target profile (YAML) — url, connector (browser/curl), and scan settings — so a long setup runs with one flag. CLI flags override it |
| `--browser-url <url>` | Drive a UI-only chat widget in a real browser (Playwright). Pair with `--input-selector` and `--response-selector` (and optional `--send-selector`) |
| `--attacker-model <id>` | Enable the adaptive **AI attacker** (ATK-050): an attacker LLM + LLM-as-a-Judge run proven jailbreaks over N turns. Any litellm id (`openrouter/…`, `ollama/…`, `gpt-4o-mini`). Implies `--exploit` |
| `--attacker-turns <n>` | Max adaptive turns for the AI attacker |
| `--calibrate` | Verify the attacker/judge can actually detect a jailbreak before the scan (so a "resisted" verdict is trustworthy) |
| `--llm-log <file>` | Write every attacker/judge call — exact prompt in, raw model output out |
| `--verbose` / `-v` | Print every payload sent and the agent's reply live, plus findings as they occur |
| `--transcript <file>` | Write the full transcript (every payload + reply + findings) to a file — the `--output` report stays findings-only |

```bash
# Full-depth scan with a CI gate and an HTML report
uv run agentscan scan http://localhost:8000/chat \
  --exploit --deep \
  --output report.html \
  --fail-on HIGH
```

### `audit` — statically audit a project directory

```bash
uv run agentscan audit ./my-agent-project
```

With no flags, all categories run. Narrow it with any combination of:
`--scan-deps`, `--scan-config`, `--scan-secrets`, `--scan-typo`, `--scan-mcp`, `--scan-identity`, `--scan-semgrep`, `--aibom` (CycloneDX 1.6), `--fail-on <SEVERITY>`, and `--output findings.json`.

`--scan-semgrep` is optional and not part of the default `audit` sweep. Install the extra (`pip install 'agentscan[semgrep]'` or `uv sync --extra semgrep`) so the `semgrep` binary is on PATH; if it is missing, that flag logs a warning and skips. AST `--scan-config` stays the zero-dependency default.

### `fix` — automated remediation & patching

Plan and safely apply fixes for vulnerabilities discovered during audit or live scans:

```bash
# Preview proposed diffs in dry-run mode (no files modified)
uv run agentscan fix ./my-agent-project

# Apply fixes directly to disk
uv run agentscan fix ./my-agent-project --apply

# Fix from an existing scan report JSON
uv run agentscan fix report.json --apply --kind pin_bump,ast_patch
```

Fix kinds supported:
- `pin_bump`: Bumps vulnerable dependencies in `requirements.txt` / `pyproject.toml` to secure versions from OSV.dev (`SC-001`).
- `ast_patch`: Safely patches `torch.load(weights_only=True)`, `subprocess(shell=False)`, and disables insecure `DEBUG=True` (`SC-011..SC-014`).
- `identity_shrink`: Prunes over-privileged or undeclared tool scopes from `*.agent.json` and `mcp_config.json` (`ID-001..ID-010`, `SC-020`).
- `guardrails`: Generates NeMo Guardrails (`guardrails/agent_guardrails.co`) and defensive prompt preambles targeting detected attack vectors (`ATK-*`).

### `ui` — local dashboard

```bash
uv sync --extra ui
uv run agentscan ui --report report.json --identity ./manifests
# http://127.0.0.1:8765 — RBAC graph, trajectory/SSP, traffic inspector
```

### GitHub Action

```yaml
- uses: PrathaMesh3056/AgentScan@v1
  with:
    target: http://localhost:8000/chat
    fail-on: HIGH
    exploit: "false"
    deep: "false"   # scan-only image; set true to pull torch and run --deep
```

The composite action installs **without PyTorch** unless `deep: true`. A scan-only `Dockerfile` at the repo root is the same contract.

### `list-attacks` — show every registered module

```bash
uv run agentscan list-attacks
```

### `init` — auto-discover a target → scan profile

Point it at a URL; it figures out the transport and writes a profile, then scan with one flag. It **tries the HTTP JSON API first (no browser)** and falls back to browser‑widget discovery only if needed:

```bash
uv run agentscan init https://example.com/backend/chat -o target.yaml   # --http / --browser to force a mode
uv run agentscan scan -c target.yaml
```

### `calibrate` / `benchmark` — trust the results

```bash
uv run agentscan calibrate --attacker-model openrouter/...   # prove the attacker/judge can detect a jailbreak
uv run agentscan benchmark                                    # prove the score ranks vulnerable vs safe agents
```

---

## Scan modes

| Mode | Flag | What it does | Network? |
|---|---|---|---|
| **SCAN** | *(default)* | Passive detection — fires static payloads and checks responses | Yes (HTTP) |
| **EXPLOIT** | `--exploit` | Active proof-of-impact — demonstrates real damage (exfiltration, hijack, poisoning) | Yes (HTTP) |
| **DEEP** | `--deep` | Inspects a local reference model's hidden states to corroborate injection payloads at the activation level | No (local model) |

### DEEP mode — payload-corroborating activation probe

`SCAN` decides success from an agent's **textual** response, which paraphrase or an implicit refusal can hide. DEEP mode replays the *same* prompt-injection payloads through a local aligned reference model (`Qwen/Qwen2.5-0.5B-Instruct`) and measures how far each one shifts the model's internal representation away from a benign baseline, along two axes:

- **magnitude** — L2 distance from the benign activations
- **direction** — cosine similarity vs. the benign-to-benign coherence

Each payload that clears the **benign noise floor** (mean pairwise distance across several ordinary prompts, not a single fixed threshold) becomes a ranked finding. Every DEEP finding carries `metadata["yaml_variant_id"]` — the same id `SCAN`'s ATK-001 uses — so a report can **join the behavioural and activation-level views of the same payload**.

Additional `--deep` probes (skipped if the local model cannot load):

- **ATK-024** rare-token / suffix trojan scanner (KL shift vs baseline)
- **ATK-025** attention entropy / sink concentration vs benign prompts
- **ATK-026** activation fingerprint over a fixed probe set (`AGENTSCAN_MODEL_FINGERPRINT` to pin)

---

## Architecture

```
Target (pydantic) ─▶ Registry (auto-discovery) ─▶ Runner (asyncio.gather)
                                                        │
                                            AttackModule subclasses
                                            scan/ · exploit/ · deep/
                                                        │
                                                   list[Finding]
                                                        │
                                          Scorer ─▶ ScanReport ─▶ Reporting
                                                              (JSON/HTML/PDF/SARIF)
```

- **`core/models.py`** — the single source of truth. `Target`, `Finding`, `ScanReport`, and the `Severity` / `ScanMode` / `Framework` enums. If you reach for a `dict`, use one of these instead.
- **`attacks/base.py`** — the `AttackModule` contract. `__init_subclass__` enforces required class attributes; `supported_modes` decides when a module runs.
- **`attacks/registry.py`** — walks the `scan/`, `exploit/`, `deep/` packages and registers every `AttackModule` subclass automatically.
- **`core/runner.py`** — discovers applicable modules and runs them concurrently; a module that raises is logged and excluded, never crashing the scan.

### Adding an attack module

```python
from agentscan.attacks.base import AttackModule
from agentscan.core.models import Finding, ScanMode, Severity, Target

class MyAttack(AttackModule):
    attack_id = "ATK-099"
    attack_name = "My New Attack"
    owasp_id = "LLM01"
    supported_modes = [ScanMode.SCAN]

    async def run(self, target: Target) -> list[Finding]:
        return [self.make_finding(Severity.HIGH, "…")]
```

Drop it in `agentscan/attacks/scan/` — the registry picks it up. No other change needed.

---

## Module status

| Module | Scope | Status |
|---|---|---|
| **0** | Foundation — models, client, registry, CI | ✅ |
| **1** | Core attack engine — CLI, scorer, runner, prompt injection | ✅ |
| **2A** | AI supply-chain scanner — deps, config, secrets, typosquat, MCP | ✅ |
| **2B** | Identity & authorization audit | ✅ |
| **3A/3B** | EXPLOIT mode — exfiltration, tool hijack, memory poison, cross-agent, credential harvest | ✅ |
| **4** | Reporting engine — HTML, PDF, SARIF, compliance mapper | ✅ |
| **5A** | DEEP mode — activation infrastructure + payload-corroborating probe | ✅ |
| **5B** | AI-driven foundation — `litellm` unified client (`core/ai_client.py`) + MiniLM embedding-based detection (`core/semantic.py`) | ✅ |
| **5C** | Transport connectors — `HttpJsonConnector` + `RequestTemplateConnector` (`--curl`) + `BrowserConnector` (Playwright); SSE streaming; multi-turn fix; `AgentScanClient` facade; `agentscan init` auto-discovery | ✅ |
| **5D** | Traffic visibility — `core/trace.py` (`TrafficRecorder`), `scan --verbose` + `scan --transcript <file>` | ✅ |
| **5E** | AI red-teaming — `ai_attacker.py` (ATK-050, PAIR-style adaptive), `evaluator.py` (LLM-as-a-Judge), `jailbreaks.py` (seed library), `calibration.py` + `calibrate`, `benchmark.py` + `benchmark`, `--llm-log`, `.env` support | ✅ |
| **6A** | SCAN expansion — ATK-002 jailbreak, ATK-003 PII exfiltration, ATK-004 DoS, ATK-005 indirect injection, ATK-006 MCP shadow (`YamlScanRunner` channel delivery + resource/tool detectors) | ✅ |
| **6E** | OWASP closeout — ATK-007 insecure output handling (LLM02), ATK-008 RAG poisoning (LLM03), ATK-009 overreliance (LLM09), ATK-010 Crescendo EXPLOIT (multi-turn, not ATK-050) | ✅ |
| **6B** | Live OSV.dev CVE API — `querybatch` + hydrate for PyPI exact pins; `known_vulnerabilities.yaml` offline fallback | ✅ |
| **6C** | Graph-based RBAC — `networkx` multi-hop privilege escalation (`ID-010`) via `calls_agents` and shared-credential paths | ✅ |
| **6D** | Trajectory tracing + SSP mapper — always-on `TrajectoryRecorder`, Servant/Stalker/Predator classification on every scan | ✅ |
| **7A** | DEEP extensions — attention analyzer, ATK-024 trojan scanner, model fingerprint (`--deep`) | ✅ |
| **7B** | MCP stdio/SSE + WebSocket connectors | ✅ |
| **7C** | GitHub Action + CycloneDX 1.6 AIBOM (`audit --aibom`) | ✅ |
| **7D** | Local `agentscan ui` FastAPI dashboard | ✅ |

---

## Development

```bash
uv run pytest tests/ -m "not slow"   # fast suite (skips model-download tests)
uv run pytest tests/                 # full suite (DEEP tests download Qwen)
uv run ruff check agentscan/ tests/
uv run mypy agentscan/ --ignore-missing-imports
```

DEEP-mode tests are marked `@pytest.mark.slow` because they download and run a local model.

### Project layout

```
agentscan/
  core/          models, client, runner, scorer
  attacks/
    base.py      AttackModule contract
    registry.py  auto-discovery
    payloads/    YAML attack payloads (single source of truth)
    scan/        passive detection modules
    exploit/     active proof-of-impact modules
    deep/        neural activation probes
  neural/        activation capture hooks + tensor metrics
  identity/      identity & authorization audit
  supply_chain/  dependency / config / secret / typosquat / MCP audit
  reporting/     HTML / PDF / SARIF / compliance mapping
```

---

## License

See repository for license details.
