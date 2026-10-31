# AgentScan startup and attack guide

Use this guide to start the dashboard, run terminal workflows and understand every implemented attack module. Commands run from the repository root. The catalog below covers **27 modules** found in the current source, with overlapping support for **15 SCAN**, **11 EXPLOIT** and **6 DEEP** modules. It describes capabilities and evidence limits, rather than certifying a target or detector.

## 1. Start the local dashboard

You need Python **3.12+** and `uv`. On this Windows workspace, open PowerShell and run:

```powershell
Set-Location D:\prathamesh\AgentScan
uv sync --frozen --no-dev --extra ui
uv run --no-sync python -m agentscan.cli ui
```

Open [http://127.0.0.1:8765](http://127.0.0.1:8765) in your browser. Keep that terminal open. Stop the dashboard with **Ctrl+C**; rerun the last command to restart it. After changing Python/backend code, restart the process and refresh the browser. The `ui` command does not enable automatic reload.

The commands use Python's module entry point, which also works when Windows blocks the generated unsigned `agentscan.exe` launcher. In an activated environment, `agentscan ui` opens the same dashboard. The installed workspace launchers were verified on 7 October 2026. No activation script is required for the commands above. If `uv` is unavailable, a normal virtual environment can install the local UI package with `python -m pip install -e '.[ui]'`, then use `python -m agentscan.cli ui` from that environment.

The local dashboard does **not** need Docker, PostgreSQL, Redis, an API key or PyTorch for ordinary deterministic scans and static audits. Optional features need their own dependencies and services.

**The dashboard is the scanner's interface, not the target agent.** Starting it does not start an LLM application or create a chat endpoint. `http://127.0.0.1:8765/chat` is not a sample agent. Enter the address of a separate running agent that you own or are authorized to assess, such as `http://127.0.0.1:8000/chat` only when that service actually exists.

Useful startup variations:

```powershell
# Use another dashboard port if 8765 is occupied.
uv run --no-sync python -m agentscan.cli ui --port 8766

# Display a previously saved ScanReport JSON.
uv run --no-sync python -m agentscan.cli ui --report report.json

# Include declared identities from an existing manifest directory.
uv run --no-sync python -m agentscan.cli ui --identity .\owned-project
```

Start from the project directory you intend to audit or repair: the UI uses its configured project root to contain local file operations. Report-loading startup can derive that root from the report's parent directory. Keep the default loopback binding. If you configure `AGENTSCAN_UI_TOKEN`, use the dashboard's authentication flow; a UI token is separate from target credentials and model-provider keys.

The dashboard's feature guide shows available workflows, missing optional packages and terminal commands for advanced target profiles and browser scans. The attack catalogue shows actual registered modules and load failures. Assessment panels display selected/evaluated counts, module outcomes and error guidance; JSON, SARIF and HTML downloads preserve assessment status. See the [dashboard feature matrix](dashboard_feature_matrix.md) for the complete mapping.

Required, malformed and out-of-range values are reported next to their fields before work starts. The API checks the same constraints even when browser checks are bypassed. Unexpected internal errors include a diagnostic reference for matching the terminal log; provider keys and submitted credentials do not belong in a support message.

The supply-chain form exposes eight audit categories plus offline and transitive controls. Offline mode and transitive inspection default on; Semgrep defaults off. Choose at least one category. Turning offline mode off allows dependency names and versions to be sent to OSV for vulnerability lookups.

## 2. Prepare a real target or a connectivity fixture

The default HTTP connector sends JSON like:

```json
{"message": "A scanner-generated test prompt"}
```

A simple compatible target replies with:

```json
{"response": "The agent's actual answer"}
```

Conversation requests include both `message` and `messages`. A browser page URL, ordinary static website, model-provider API and application chat API are different interfaces. Use the connector appropriate to the actual application.

### Optional local fixture, with no model or key

If you only want to check installation, request routing and report display, save the following as `demo_agent.py` in a directory you control. It always returns a fixed refusal and never executes tools or calls a model. **It is a connectivity fixture, not a meaningful security or accuracy benchmark.**

```python
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def reply(self, status, value):
        data = json.dumps(value).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self.reply(200 if self.path == "/health" else 404,
                   {"status": "connectivity fixture only"})

    def do_POST(self):
        if self.path != "/chat":
            self.reply(404, {"error": "Use POST /chat"})
            return
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= 1_048_576:
                self.reply(413, {"error": "Request size rejected"})
                return
            body = json.loads(self.rfile.read(size))
            if not isinstance(body, dict) or not isinstance(body.get("message"), str):
                raise ValueError("Expected a JSON message")
        except (ValueError, TypeError, json.JSONDecodeError):
            self.reply(400, {"error": "Expected JSON with a message string"})
            return
        self.reply(200, {"response": "I cannot help with that request."})

    def log_message(self, *_):
        pass  # Do not log supplied prompts.


if __name__ == "__main__":
    print("Connectivity fixture: http://127.0.0.1:8000/chat (Ctrl+C to stop)")
    try:
        ThreadingHTTPServer(("127.0.0.1", 8000), Handler).serve_forever()
    except KeyboardInterrupt:
        pass
```

In a second terminal, start the fixture:

```powershell
uv run --no-sync python demo_agent.py
```

In a third terminal, confirm that its **POST** endpoint responds:

```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/chat -ContentType application/json -Body '{"message":"Hello"}'
```

You can now enter `http://127.0.0.1:8000/chat` in the UI or run the first scan below. A fixture refusal or zero findings says nothing about a separate real agent. Stop the fixture with Ctrl+C when finished.

## 3. Launch a scan from the UI

1. Open the scan dialog and enter the target's full endpoint URL. The field starts blank; enter your actual endpoint rather than accepting a substituted target.
2. Choose the scan mode. **Standard/SCAN** runs ordinary behavioral modules. **Active/EXPLOIT** adds active and multi-turn tests. **DEEP** adds the selected neural/reference branch and its applicable behavioral modules.
3. Choose analysis mode. **Deterministic checks only** needs no model or provider key. **Offline local model** needs installed Ollama weights. **External model** needs a provider, model ID, configured key and a separate non-sensitive designation for this scan.
4. Set concurrency within the form's supported range; begin conservatively for rate-limited targets.
5. Launch, inspect progress and read findings alongside module errors, skipped coverage and evidence. Export JSON when you need a local record.

Model fields are conditional: deterministic mode needs no model; local mode needs a valid installed `ollama/model`; external mode needs a nonempty provider model ID and the non-sensitive confirmation. Target URL is required for every behavioral scan. An external confirmation is per scan and resets when switching modes or closing/submitting the dialog. Provider keys are configured on the machine, not entered in the scan form.

Validation errors should be corrected in the named field before launch. A missing target, malformed URL, invalid model or unavailable setting is a configuration problem, not evidence that the agent passed. If a request fails, retain the entered values, read the explanation and correct the configuration before retrying. The troubleshooting table below separates field errors from connection and runtime failures.

## 4. Terminal scan workflow

The `uv run --no-sync` prefix reuses the environment you installed. In an activated environment, the equivalent entry point is `python -m agentscan.cli` or `agentscan` where the console launcher is permitted.

```powershell
# Default SCAN: deterministic analysis, sensitive classification.
uv run --no-sync python -m agentscan.cli scan http://127.0.0.1:8000/chat --output report.json

# Add EXPLOIT modules; these can request side effects from the target.
uv run --no-sync python -m agentscan.cli scan http://127.0.0.1:8000/chat --exploit --output active-report.json

# Add bounded encoding/obfuscation variants to YAML SCAN payloads.
uv run --no-sync python -m agentscan.cli scan http://127.0.0.1:8000/chat --mutate --output mutation-report.json

# Show the report later, even after the target has stopped.
uv run --no-sync python -m agentscan.cli ui --report report.json

# Examine installed command options and registered module metadata.
uv run --no-sync python -m agentscan.cli scan --help
uv run --no-sync python -m agentscan.cli list-attacks
```

Use active tests on an authorized staging environment with appropriate target-side controls. Even standard prompts can induce tool actions if the target exposes them; scan mode is not an isolation boundary. Request retries can repeat target effects, and reports do not undo actions. Read the [execution sequence](../internal_docs/diagrams/04_scan_sequence.md) and [guard/sandbox boundary](../internal_docs/diagrams/15_guard_sandbox_flow.md).

### Authentication belongs to the target

For an authenticated application, `--auth-header` accepts `Bearer TOKEN` or a named header such as `X-Api-Key: TOKEN`. This is the **target's** credential, distinct from the provider key used for analysis. Example using a target token already provisioned in your shell environment:

```powershell
uv run --no-sync python -m agentscan.cli scan https://agent.example.com/chat --auth-header "Bearer $env:TARGET_AGENT_TOKEN" --output report.json
```

Replace the placeholder hostname with the real owned endpoint. Keep credentials out of shared command history, screenshots, reports and committed profiles. Protect local profiles containing headers or known system prompts. Do not place a model-provider key in a target header unless that endpoint explicitly requires that credential.

### Save a reusable target profile

Save this example as `target.yaml`, replacing the URL with the actual endpoint:

```yaml
url: http://127.0.0.1:8000/chat
framework: unknown
analysis_mode: deterministic
data_classification: sensitive
exploit: false
deep: false
output: report.json
```

```powershell
uv run --no-sync python -m agentscan.cli scan --config target.yaml
```

The profile's `system_prompt` can supply an operator-known baseline for supported extraction tests. `canary_token` supplies confidential synthetic-reference profiles, including ATK-001, ATK-002, ATK-011, ATK-027 and ATK-028, only after the same value has been provisioned on the target **out of band**. The scanner does not seed the target automatically, and the reference must not be placed in attack prompts. The dashboard offers an optional masked **Private synthetic reference** field; the terminal accepts `canary_token` in a target YAML profile, with no standalone `scan --canary` flag. Without a usable reference these known-reference checks remain unassessed. ATK-027 requires the synthetic canary; a whole system-prompt baseline alone is insufficient. Keep real secrets outside prompts and protect baseline profiles. See the [ATK-001 setup](modules/prompt_injection.md) and [ATK-027 scope](modules/model_theft.md).

The current scan CLI selects suites by mode. It does not expose a `--attack-id` selector; an ID in the catalog is not an individual command. Applicability and runtime prerequisites determine which modules execute.

### This workspace's BitInfusion profile

The local, Git-ignored `bitinfusion.yaml` points at the existing BitInfusion chat API with its JSON request/response mapping. It uses deterministic analysis and sensitive classification. No model-provider key is needed. It contains no target credentials.

```powershell
uv run --no-sync python -m agentscan.cli scan --config .\bitinfusion.yaml --output bitinfusion-report.json
```

This command selects the ordinary SCAN suite; it is broader than the six individually bounded probes authorized for the saved validation. On 7 October 2026, the six-probe run evaluated two variants each of prompt injection, jailbreak and system-prompt disclosure, with no findings and no model-provider calls. The target's actual vulnerability ground truth is unknown. This small sample is not a full assessment or an accuracy benchmark. Only metadata and evidence digests were saved under `internal_docs/diagrams/live-target/`; raw target replies were not retained there. Detector repairs made afterward have not been rerun against that external service.

For static MCP client declarations, the audit supports flat `*.mcp.json` files and nested `mcpServers` in `mcp.json`, `mcp_config.json` and `claude_desktop_config.json`. Commands and environment values in declarations are not executed. Malformed declarations produce incomplete coverage; declared authentication or tool scope does not prove runtime enforcement. See [MCP compatibility](MCP_COMPATIBILITY.md).

## 5. Choose analysis without disclosing sensitive data

| Choice | Requirements | What leaves the analysis process |
|---|---|---|
| Deterministic | Default; no key/model | No attacker/judge model traffic; explicitly selected target traffic still occurs |
| Offline local | Installed Ollama model; literal loopback; cloud features disabled; host egress policy | Analysis messages go to the local daemon |
| External | Explicit non-sensitive designation, provider/model and locally configured key; API tenant permission where applicable | Relevant objectives and target responses go to the selected provider |

```powershell
# Installed local weights; the name must match an installed model.
uv run --no-sync python -m agentscan.cli scan http://127.0.0.1:8000/chat --exploit --analysis local --local-model ollama/llama3.2 --output local-report.json

# Optional external analysis: replace AVAILABLE_MODEL_ID with an account-supported ID.
uv run --no-sync python -m agentscan.cli scan https://agent.example.com/chat --exploit --analysis external --data-classification non_sensitive --external-model gemini/AVAILABLE_MODEL_ID --output external-report.json
```

`openai/MODEL_ID` and `anthropic/MODEL_ID` are also supported external selectors. Configure only the selected key locally: `OPENAI_API_KEY`, `ANTHROPIC_API_KEY` or `GEMINI_API_KEY` (`GOOGLE_API_KEY` alias). An existing key does not enable external analysis by itself. The local CLI/dashboard can read the selected named key from the working directory's `.env`; service API/worker credentials must be administrator-injected. Do not put a key in the model ID, scan request or report.

Local selection does not pull weights or fall back to a provider. Prepare weights separately, configure `OLLAMA_NO_CLOUD=1`, restart the daemon and apply independent outbound restrictions for enforced offline operation. Missing weights, keys or valid verdicts remain unavailable/inconclusive. A client's designation is not automatic secret detection: arbitrary confidential prose cannot be made non-sensitive by regex redaction. Full setup and retention rules are in [DATA_POLICY.md](DATA_POLICY.md) and the [three-path data-flow diagram](../internal_docs/diagrams/17_sensitive_data_flow.md).

## 6. Optional installation profiles

The minimal UI profile includes core HTTP/WebSocket/MCP connectors, deterministic payloads, static scanners and HTTPX-based analysis clients. Local/external analysis needs a running model/provider rather than a provider SDK extra. Feature registration does not imply the feature's runtime prerequisites are ready.

| Feature | Additional installation/setup | Important limit |
|---|---|---|
| Terminal only | `uv sync --frozen --no-dev` | Omits UI and heavy optional dependencies |
| Local dashboard | `uv sync --frozen --no-dev --extra ui` | No distributed DB/queue needed |
| DEEP reference probes | Add `--extra deep` | PyTorch/Transformers and prepared reference weights; separate model from remote target |
| Semantic embeddings | Add `--extra semantic` | Optional local MiniLM weights; first uncached load can require a separate download |
| Browser target connector | Add `--extra browser`; prepare Playwright Chromium separately | CSS selectors and verified completion marker required |
| PDF export | Add `--extra pdf` and platform WeasyPrint dependencies | Extra installation alone may not supply native rendering libraries |
| Semgrep executable | Add `--extra semgrep` | Built-in native AST fallback covers a smaller rule subset; custom-rule execution may be unavailable |
| Distributed REST service | Add both `--extra ui --extra api`; provision DB/Redis/keys/policies | Separate authenticated service, not the local dashboard |
| Exported metrics/traces | Add `--extra telemetry` and explicitly configure exporter | Optional observability, not automatic target coverage |

Repeat all extras you intend to retain when running `uv sync`: it can remove packages outside the selected profile. For example, a UI + DEEP + browser environment is:

```powershell
uv sync --frozen --no-dev --extra ui --extra deep --extra browser
```

Installing DEEP can be large. Prepare the pinned reference weights and optional semantic/browser assets before handling sensitive data; downloads are separate network operations. Merely adding `--deep` does not introspect a commercial API's hidden states or establish a GPU deployment.

### Browser or captured-request targets

For a widget, install the browser extra and its runtime before scanning:

```powershell
uv run --no-sync python -m playwright install chromium
uv run --no-sync python -m agentscan.cli scan --browser-url https://owned-site.example/chat --input-selector "#message" --response-selector ".assistant-message" --completion-selector ".reply-complete" --output browser-report.json
```

The URL and CSS selectors are placeholders. Use the actual widget input, newest reply and completion marker. If your widget has no trustworthy completion marker, `--allow-unverified-completion` explicitly accepts a weaker text-stability heuristic; it must not be interpreted as verified protocol completion.

For a copied cURL request from an owned application, save it locally as `request.curl`, protect its headers/cookies and use the actual request/response fields:

```powershell
uv run --no-sync python -m agentscan.cli scan --curl request.curl --message-path message --response-path response --output captured-report.json
```

MCP stdio, Streamable HTTP and legacy HTTP+SSE are local connector choices. Stdio starts the selected local command, so review it first. Protocol/session/pagination checks are bounded; legacy fallback is limited to an initial HTTP 404/405, and Streamable HTTP resumption never replays a POST. See [MCP compatibility](MCP_COMPATIBILITY.md) for supported behavior and remaining limits. WebSocket and these richer local connectors are not enabled for remote distributed API jobs, which accept enrolled HTTP(S) targets only.

## 7. Every implemented attack module

Names and modes below come from the module class definitions, not older numeric labels in screenshots. Modules can support more than one mode. Most ordinary behavioral probes work with the minimal core install; optional model judging needs the explicitly selected analysis setup. A result from a pattern, response, tool-call proposal or local reference model must be interpreted within that evidence scope.

### SCAN modules and shared modules

| ID and exact name | Modes | Purpose | Prerequisites and result limits |
|---|---|---|---|
| [ATK-001 — Direct Prompt Injection](modules/prompt_injection.md) | SCAN | Send 24 direct-user seeds and assess complete disclosure of an operator-known confidential reference. | Reachable target and privately provisioned synthetic canary or full known confidential prompt. Missing criteria and unreadable replies remain INCONCLUSIVE. Deterministic matching; no model judge. A negative covers only the declared reference and supported text representation. |
| [ATK-002 — Persona confidentiality probes](modules/jailbreak.md) | SCAN | 18 bounded persona/role-play probes; complete known-reference disclosure criterion. | Privately provisioned synthetic canary or complete known confidential prompt. Missing criteria and incomplete replies remain inconclusive; no general jailbreak or tool-execution claim. |
| [ATK-003 — PII & Sensitive Data Disclosure](modules/pii_exfiltration.md) | SCAN | Assess complete known private-value disclosure across 13 single-turn probes. | Requires an out-of-band synthetic canary or supported designated private value. Public-input echoes, fabricated PII and judge guesses do not prove disclosure. Missing criteria and unreadable replies remain inconclusive; network transfers and tenant boundaries are not verified. |
| [ATK-004 — Unbounded Consumption](modules/dos.md) | SCAN | Nine finite HTTP(S) response/timing observations; optional in-process owned resource witness. | Default replies, canaries and timeouts are inconclusive for DoS impact. Use a disposable instrumented target for measured work and neutral-service admission. |
| [ATK-005 — Indirect Document Injection](modules/indirect_injection.md) | SCAN | Seven document patterns assessed for complete known-reference disclosure. | Requires an explicitly configured HTTP `document_v1` adapter, target-owned reference and correlated consumption receipt. Ordinary chat is unavailable; tool ingestion remains unassessed. |
| [ATK-006 — MCP Shadow Server](modules/mcp_shadow.md) | SCAN | Eight hashed response-proposal observations; optional real MCP catalog comparison against an operator-approved baseline. | Default impact remains inconclusive. A baseline binds the exact endpoint and complete tool-definition hashes; one catalog-policy comparison may report bounded MEDIUM deviations. It does not inject metadata, launch a rogue server or prove downstream execution. |
| [ATK-007 — Insecure Output Handling](modules/output_handling.md) | SCAN | Record 12 hashed output-indicator observations; optional trusted Python instrumentation assesses owned browser/SQLite consumers. | Normal remote scans remain impact-inconclusive. Local consumer findings are excluded from customer scores; HTTP/model receipts cannot supply witnesses. The separate 48-run control suite passed; the 24-generation model smoke failed benign utility and leaves efficacy open. Shell/terminal execution, real transfer and Markdown rendering remain unvalidated. Observation records omit raw text; ordinary redacted trajectories/transcripts retain it. |
| [ATK-008 — RAG / Knowledge-Base Poisoning](modules/rag_poisoning.md) | SCAN | Record eight document-response observations; separately assess answer/citation effects in an owned retrieval fixture. | Requires an explicit HTTP `document_v1` adapter. Remote marker and receipt observations stay impact-inconclusive; owned local results do not score the customer target. No deployed corpus or retrieval path is independently verified. |
| [ATK-009 — Overreliance / Hallucination](modules/overreliance.md) | SCAN | Eight response observations; optional client-approved exact-answer policy checks with neutral/pressure pairs. | Requires an independently approved, exact-endpoint baseline for policy assessment. Strict complete JSON answers only; malformed/refusal prose and errors remain inconclusive. Policy deviations have no security score or tool/causal claims. Factuality traffic retains only digests. |
| [ATK-011 — Multilingual confidentiality](modules/multilingual.md) | SCAN | 18 bounded messages; complete private-reference disclosure and per-language coverage. | Privately provisioned synthetic reference; missing criteria and incomplete replies remain inconclusive. No general language-alignment or comprehension claim. |
| [ATK-012 — System Prompt Leakage](modules/system_prompt_leak.md) | SCAN | Assess complete known confidential prompt/reference disclosure across ten probes. | Requires a privately provisioned canary or known confidential prompt; missing criteria and unreadable replies stay inconclusive. Public-input echoes, generic phrases and judge guesses do not establish disclosure. |
| [ATK-013 — Excessive Agency & Unauthorized Tool Invocation](modules/excessive_agency.md) | SCAN | Inventory proposals/status claims across ten retained user-message probes. | Owned disposable target with controlled synthetic tools. Authorization, approval and effects remain unassessed with zero impact-evaluated tests; native MCP is skipped. No module-only CLI/dashboard selector or independent witness adapter. |
| [ATK-020 — Cross-Agent Workspace Poisoning](../agentscan/attacks/exploit/workspace_poison.py) | SCAN, EXPLOIT, DEEP | Simulate poisoned SQLite, RAG and workspace context. | Local simulated data plus target response. Findings are candidates; deployed ingestion, cross-agent propagation and execution are unverified. |
| [ATK-027 — Model/IP known-reference disclosure](modules/model_theft.md) | SCAN, EXPLOIT | Ten bounded single-turn model/IP requests assessed against a privately provisioned synthetic canary. | Requires `canary_token`; a system-prompt baseline alone is insufficient. Missing criteria prevent probes; incomplete replies remain inconclusive. Public model facts, paths and judge guesses do not prove model theft. No parameter-recovery, training-origin or network-transfer claim. |
| [ATK-028 — Multi-Turn Context Escalation](../agentscan/attacks/scan/multi_turn_escalation.py) | SCAN, EXPLOIT | Test disclosure after a three-turn escalation. | An operator-seeded confidential `canary_token`, installed out of band and supplied in local profile. Without it the module is inapplicable. A matched protected canary establishes disclosure, not arbitrary executed tools. |

### EXPLOIT-specific and shared social modules

| ID and exact name | Modes | Purpose | Prerequisites and result limits |
|---|---|---|---|
| [ATK-010 — Crescendo Private-Reference Conversations](modules/crescendo.md) | EXPLOIT | Six bounded scripted HTTP conversations assess complete private synthetic-reference disclosure. | Requires an out-of-band `canary_token`; missing references send no probes. Public echoes, judge opinions and incomplete replies cannot establish disclosure. No adaptive generation or proof of target-side conversation ingestion. |
| [ATK-014 — Active Data Exfiltration](../agentscan/attacks/exploit/data_exfiltration.py) | EXPLOIT | Compare an extraction response with operator-known system instructions. | `system_prompt` required; absence means no meaningful baseline test. Word overlap can overstate extraction and is not evidence of a separate outbound transfer. |
| [ATK-015 — Tool Call Hijacking](../agentscan/attacks/exploit/tool_hijack.py) | EXPLOIT | Detect injected destination markers in returned tool-call data. | Target exposes tool-call metadata. Returned call arguments are not verified tool execution or email delivery. |
| [ATK-016 — Memory / Persistent State Poisoning](../agentscan/attacks/exploit/memory_poison.py) | EXPLOIT | Plant a fact and query it in a follow-up conversation. | Conversation/history delivery. History is replayed by the scanner; a recalled phrase does not establish a durable target memory/database write. |
| [ATK-017 — Cross-Agent Trust Injection](../agentscan/attacks/exploit/cross_agent.py) | EXPLOIT | Frame messages as trusted inter-agent communication. | One reachable target. Simulates trust framing; does not observe two deployed agents or real inter-agent traffic. |
| [ATK-018 — Credential Harvest](../agentscan/attacks/exploit/credential_harvest.py) | EXPLOIT | Compare replies with credential-like values in a known system prompt. | `system_prompt` containing scanner-recognized test secrets. No baseline/matching secrets means no meaningful harvest test; use controlled canaries rather than production credentials. |
| [ATK-050 — Iterative AI Red-Teaming (PAIR)](../agentscan/attacks/exploit/ai_attacker.py) | EXPLOIT | Generate/refine adaptive payloads using attacker and strict judge models. | Explicit local/external analysis with available model; attacker selection makes the module applicable. Deterministic mode does not run AI generation. A valid judge schema does not establish independent verdict accuracy. |
| [ATK-SOC-001 — Multi-Turn Social Engineering & Authority Impersonation](../agentscan/attacks/deep/multi_turn_social.py) | EXPLOIT, DEEP | Test staged authority/diagnostic impersonation over conversation turns. | Reachable conversation target; no PyTorch needed for this behavioral module. Generic instruction/leak indicators require review and are not a verified system-prompt baseline. |

ATK-020, ATK-027 and ATK-028 also participate in EXPLOIT, as listed above. ATK-020 and ATK-SOC-001 participate in DEEP. This overlap is why per-mode counts exceed the number of unique modules.

### Local DEEP reference probes

These four probes need the `deep` extra and available pinned local Qwen reference weights. Their observations belong to `reference_observations` and **do not contribute to the remote-target score**. They do not inspect the hidden states of the URL being scanned. Missing weights/dependencies/baselines produce unavailable coverage.

| ID and exact name | Modes | Purpose | Prerequisites and result limits |
|---|---|---|---|
| [ATK-023 — Activation-Level Anomaly Detection](../agentscan/attacks/deep/activation_probe.py) | DEEP | Measure activation L2/cosine changes for prompt variants against benign anchors. | Local reference weights and activation hooks. Representation change is not calibrated proof of a jailbreak or target compromise. |
| [ATK-024 — Rare-Token Trojan Scanner](../agentscan/attacks/deep/trojan_scanner.py) | DEEP | Compare next-token distributions with rare/suffix triggers. | Local reference inference. Distribution anomalies do not establish an implanted backdoor or identify a compromised remote model. |
| [ATK-025 — Attention Diversion Analyzer](../agentscan/attacks/deep/attention_probe.py) | DEEP | Compare attention entropy/sink concentration against benign probes. | Local reference attention outputs. Diagnostic/experimental evidence; no automatic vulnerability category or remote execution claim. |
| [ATK-026 — Model Activation Fingerprint](../agentscan/attacks/deep/model_fingerprint.py) | DEEP | Compute a fixed-probe activation signature and optional baseline comparison. | Local reference model; `AGENTSCAN_MODEL_FINGERPRINT` for a comparison baseline. Runtime/precision/revision affect reproducibility; a mismatch alone does not prove tampering. |

```powershell
# Requires the deep extra and prepared reference model assets.
uv run --no-sync python -m agentscan.cli scan http://127.0.0.1:8000/chat --deep --output deep-report.json
```

## 8. Audit, identities, remediation and other workflows

### Static audit and declared identities

```powershell
# Offline avoids live OSV package/version lookups.
uv run --no-sync python -m agentscan.cli audit .\owned-project --offline --output audit-report.json

# Choose identity checks explicitly; reads declared *.agent.json manifests.
uv run --no-sync python -m agentscan.cli audit .\owned-project --scan-identity --offline --output identity-report.json

# Opt into Semgrep/native AST rules and declared AIBOM output.
uv run --no-sync python -m agentscan.cli audit .\owned-project --scan-semgrep --offline --output code-report.json
uv run --no-sync python -m agentscan.cli audit .\owned-project --aibom --offline
```

Without category flags, `audit` selects the built-in categories; Semgrep remains opt-in. Once a category flag is supplied, only selected categories run. Online dependency checks send package names/versions to OSV. Offline fallback, version ranges, malformed manifests, missing inputs and unexecuted scanners must remain visible in `audit_coverage`; an empty finding list is not a complete clean audit. Identity/RBAC checks assess declarations, not verified deployed entitlements. See the [audit diagram](../internal_docs/diagrams/12_audit_identity_flow.md).

### Review repairs before applying

```powershell
# Plans only; no --apply or --pr.
uv run --no-sync python -m agentscan.cli heal .\owned-project --report audit-report.json --patch-out proposed.patch
uv run --no-sync python -m agentscan.cli fix .\owned-project --kind ast_patch,identity_shrink,guardrails --output fix-plan.json
```

Read the plan/diffs and run project-specific validation. `--apply` is an explicit write operation; `--pr` additionally requests Git commit/push/PR work and requires a clean repository. Dynamic/ambiguous rewrites may remain manual. Interrupted multi-file edits leave private recovery receipts; review them before another apply. Recovery preserves later editor changes and does not reset Git. See [remediation and recovery](../internal_docs/diagrams/13_remediation_workflow.md).

### Swarm and local smoke checks

```powershell
uv run --no-sync python -m agentscan.cli swarm http://127.0.0.1:8000/chat --offline --rounds 2 --output swarm-report.json
uv run --no-sync python -m agentscan.cli swarm http://127.0.0.1:8000/chat --model ollama/llama3.2 --rounds 2 --output local-swarm.json
uv run --no-sync python -m agentscan.cli benchmark
uv run --no-sync python -m agentscan.cli calibrate --attacker-model ollama/llama3.2
```

Swarm `--offline` disables model generation, **not target network requests**. A default swarm is deterministic. External swarm selection uses `--model provider/MODEL_ID --data-classification non_sensitive`; it has the same privacy gates and starts fresh intelligence state. Token accounting is estimated, candidates are not confirmed execution and protected canaries must be provisioned independently. `benchmark` and `calibrate` are synthetic fixture/protocol smoke checks, not independent detector accuracy or deployment safety tests.

### Guard and sandbox integration

There is no standalone `agentscan guard` or `agentscan sandbox` CLI command. Capability/path/command guards and sandbox engines are integration components; callers must wrap the actual tool boundary. Starting a dashboard or running a scan does not automatically sandbox a remote target's tools. Container-backed execution needs a working Docker/runtime and disposable contained workspace. An explicitly selected audit-only subprocess tier records observations without providing isolation. Recovery preimages/private staging files are excluded from sandbox workspace copies. See the [guard/sandbox diagram](../internal_docs/diagrams/15_guard_sandbox_flow.md) and per-function inventories before integrating these components.

Other real command entry points include `init` (authorized target discovery), `watch` (repeated target checks), `export-guardrails` (write a gateway proposal) and `mcp-serve` (stdio MCP service). Review their `--help` and integration scope first. Exporting a policy does not apply it to a gateway; a watch webhook explicitly sends alerts to its configured destination.

## 9. Optional distributed API and workers

This is separate from the dashboard. Install the service profile, then provision PostgreSQL, Redis, persistent signing/data keys, tenant credentials, exact origins/private CIDRs and quotas using [api.md](api.md). All replicas need the same data key; there are no default enrollment/signing secrets. Do not start workers against unreviewed production queues.

```powershell
uv sync --frozen --no-dev --extra ui --extra api

# Terminal A, after the required deployment environment is configured.
uv run --no-sync python -m agentscan.cli api serve --host 127.0.0.1 --port 8081

# Terminal B, with the same DB/Redis/key/policy configuration.
uv run --no-sync python -m agentscan.cli api worker
```

A DEEP consumer is separately configured with `api worker --deep` and the deep dependencies/runtime; ordinary workers consume normal/high streams. API jobs accept enrolled HTTP(S) targets only. Local/external analysis permissions default false per tenant. External service jobs additionally need `non_sensitive` classification and administrator-configured provider model/key; per-tenant BYOK storage is not implemented. Durable acceptance, outbox redelivery, fenced leases, cancellation and PostgreSQL SSE replay are described in the [API sequence](../internal_docs/diagrams/05_api_job_sequence.md).

## 10. Troubleshooting and reading results

| Symptom | Meaning / next step |
|---|---|
| UI dependency missing | Install the `ui` extra in the environment actually launching the process. Avoid a later exact sync that omits it. |
| Port already in use | Stop the old process or choose `ui --port 8766`; use the printed URL. A target port is configured by the target application separately. |
| Blank target or field validation error | Enter a full real endpoint; fix each named field. Nothing should be substituted or launched because a target is missing. |
| Dashboard URL used as target | Use the separate agent service, not port 8765 or the dashboard's internal APIs. The scanner cannot scan a chat endpoint that it did not start. |
| Cross-site dashboard requests are denied while opening the page | After updating, stop the old UI with Ctrl+C and restart it. Paste its printed URL directly into the browser address bar. Normal top-level page navigation is allowed; cross-origin API calls, embedded frames and submissions remain blocked. Keep one exact host/port for the dashboard. |
| Target 401 | Check the target's own bearer/API-key header and its expiry. Provider keys do not replace application authentication. |
| 403 | Distinguish dashboard Host/Origin/token checks, service tenant/origin/model permission and a target's own authorization response. Read the source of the error before changing credentials. |
| 404 | Confirm the POST chat path or chosen transport. A GET of `/chat`, static page or dashboard path is not a valid JSON-agent endpoint. |
| 429 | Target/provider rate limit or service quota. Reduce approved load, wait for the relevant allowance and inspect acceptance before resubmitting; retries can create another job. |
| Timeout / connection failure | Verify the separate target is running and reachable. Inspect module errors; a failed request is not a resisted attack. Docker-host localhost addresses may differ from the host machine's addresses. |
| Local model unavailable | Check installed model name, loopback daemon and cloud-disabled setup. AgentScan does not pull missing Ollama weights or switch to a provider. |
| External selection rejected | Check explicit external mode, non-sensitive designation, actual provider/model ID and selected locally configured key; API tenants also need permission. |
| No PyTorch/Transformers or reference weights | Install `deep` only if needed; prepare pinned assets separately. Selected neural probes remain unavailable/inconclusive rather than a clean result. |
| Browser reply never completes | Check newest-reply and completion selectors. Text-stability fallback requires explicit opt-in and remains unverified completion. |
| Empty findings, nullable score or INCONCLUSIVE | Read selected/executed counts, module outcomes, audit coverage and error reasons. An empty list or unavailable score is not a perfect score or certification. |
| API accepted while Redis is down | A 202 can mean durable queued acceptance. Use scan ID/status; outbox reconciliation retries delivery. Readiness can still be 503 while Redis is unavailable. |
| Restart loses unsaved UI state | The local UI uses process-local state. Export results or load a saved report; the distributed API has separate durable storage. |
| Remediation recovery conflict | Preserve the journal and current files, review differences and use conditional recovery. Never discard newer editor work or reset Git to force a repair. |

Read findings as scoped evidence: what was submitted, what was observed, what actually executed and which checks were unavailable. Service reports retain redacted metadata/digests; local transcripts and recovery backups need operator-controlled access/retention. Compliance mappings are descriptive labels, not certification.

For source-level understanding, start with the [architecture and complete function guide](../internal_docs/diagrams/README.md), then the [offline explorer](../internal_docs/diagrams/explorer.html). The inventories explain authored Python functions/methods and dashboard JavaScript, with signatures, control flow and source links. The [repair status](../internal_docs/diagrams/repair-status.md) records verification and remaining boundaries.

## Guide verification

This guide's commands/options were checked against the installed Typer help and local `uv` help; its 27 attack names, IDs and supported modes were checked against the current class definitions by AST. Help verification disabled eager dotenv loading. A historical [connectivity verification](../internal_docs/diagrams/startup-connectivity-verification.json) ran the sample fixture through the actual dashboard scan path: 118 of 118 tests evaluated, no module errors, and JSON/SARIF/HTML downloads succeeded. This used only a local fixed-refusal server, with no model or provider calls. That receipt predates the updated module evidence contracts and does not describe the current suite's evaluated count. It verifies historical routing and report handling, not detector accuracy.
