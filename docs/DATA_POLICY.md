# Sensitive data and analysis modes

AgentScan offers three analysis modes. **Deterministic checks** and **sensitive data classification** are the defaults. Clients can choose an installed **offline local model**, or explicitly designate a scan **non-sensitive** and choose an **external provider**. Sensitive scans cannot use external analysis, even when a provider key is configured.

| Analysis mode | Allowed classification | Analysis destination | Required opt-in |
|---|---|---|---|
| `deterministic` | Sensitive or non-sensitive | No attacker/judge model calls | Default |
| `local` | Sensitive or non-sensitive | Installed Ollama model on literal loopback | Explicit mode and installed model; API tenant permission |
| `external` | `non_sensitive` only | Selected OpenAI, Anthropic or Gemini endpoint | Explicit mode, client designation, provider/model and local key; API tenant permission |

**External analysis sends relevant attack objectives and target responses to the chosen provider.** The client decides whether that scan is non-sensitive. Redaction of recognizable credentials cannot identify arbitrary confidential prose and does not make sensitive input safe to disclose. Keep sensitive scans deterministic or local. Missing keys, missing weights and errors never automatically switch a scan to an external provider.

## Local dashboard and CLI

The scan dialog exposes the three modes. Local mode accepts an installed model name, such as `ollama/llama3.2`. External mode requires provider/model selection and an explicit non-sensitive designation; the key is configured locally, rather than entered into the scan form. An unavailable model produces an unavailable/inconclusive outcome. Local selection does not download weights or switch to a cloud service.

```bash
agentscan scan http://127.0.0.1:8000/chat --analysis deterministic
agentscan scan http://127.0.0.1:8000/chat --analysis local --local-model ollama/llama3.2
agentscan audit ./owned-project --offline
agentscan swarm http://127.0.0.1:8000/chat --offline
```

## Optional external provider setup

On the client's own machine, set the selected provider's environment variable or add it to the `.env` file in the directory where AgentScan runs. An existing key remains inactive until external mode is explicitly selected. Keep `.env` outside version control and protect its file permissions. The local CLI/dashboard reads only the selected provider's named key when external analysis is chosen.

| Provider | Key variable | Model selector |
|---|---|---|
| OpenAI | `OPENAI_API_KEY` | `openai/<available-model-id>` |
| Anthropic | `ANTHROPIC_API_KEY` | `anthropic/<available-model-id>` |
| Gemini | `GEMINI_API_KEY` (`GOOGLE_API_KEY` accepted as an alias) | `gemini/<available-model-id>` |

For example, a local `.env` entry is `GEMINI_API_KEY=replace-with-your-key`. Do not paste a real key into chat, reports, a browser scan form or API request body. Choose an actual model available to that account, replacing the placeholder in this command:

```bash
agentscan scan http://127.0.0.1:8000/chat --analysis external --data-classification non_sensitive --external-model gemini/AVAILABLE_MODEL_ID
```

The external adapter uses the providers' fixed HTTPS origins, disables environment proxies, rejects arbitrary base URLs, bounds inputs/responses/timeouts and does not automatically retry provider calls. Keys authenticate requests to the selected provider and are excluded from analysis messages, scan configuration payloads and reports. Successful API response parsing does not establish model accuracy, and provider account access or billing remains the client's responsibility. The request formats are documented by [OpenAI](https://developers.openai.com/api/reference/resources/chat), [Anthropic](https://platform.claude.com/docs/en/api/messages/create) and [Gemini](https://ai.google.dev/gemini-api/docs/generate-content).

## Offline local model setup

Prepare model weights separately before handling sensitive data. Configure the Ollama daemon with `OLLAMA_NO_CLOUD=1` or `disable_ollama_cloud: true`, then restart it and confirm its cloud-disabled log. These settings are documented in the [Ollama FAQ](https://docs.ollama.com/faq). Restrict the daemon's outbound network access when the deployment requires independently enforced offline operation.

The analysis client accepts a literal loopback HTTP address only: `AGENTSCAN_LOCAL_MODEL_URL` defaults to `http://127.0.0.1:11434`. It bypasses proxy environment variables, pins loopback connections and refuses redirects outside that origin. It checks `/api/show` for installed local weights and rejects remote model metadata before sending analysis messages. Input, output, timeouts and retries are bounded. The administrator controls the local daemon; a replaced daemon or local proxy requires separate host integrity controls.

AgentScan's analysis policy applies to attacker/judge processing of findings and responses. A target scan communicates with the explicitly selected target endpoint. Choose a target and its data policy accordingly. Live OSV dependency lookups send package names and versions; use `audit --offline` to avoid those lookups. Browser/HTTP/MCP target traffic and separate downloads remain explicit capabilities rather than analysis-provider calls.

### HTTP redirect credentials and assessment scope

HTTP target requests check the configured host/origin enrollment before every
delivery, including redirects. Across different origins (scheme, host or port),
the shared HTTP path removes operator-supplied header names from both
`Target.extra_headers` and captured `RequestTemplate.headers`, alongside common
authentication headers. Same-origin requests retain their configured headers.
Destination Host and body-framing headers are regenerated after removal rather
than restored from the captured profile. Redirects consume the shared request budget.
Once a redirect chain crosses origins, subsequent hops also suppress cookies
that HTTPX might reattach from its jar. This conservative rule also suppresses
new destination cookies within that chain. Fresh requests and chains that stay
on the original origin keep their configured cookie behavior.

This protects headers; it does not sanitize request bodies or query parameters.
A 307/308 redirect can preserve a captured JSON body. For sensitive captured
context, restrict `Target.allowed_origins` to the exact authorized origin or set
`max_redirects=0` through the SDK. Local CLI defaults are trusted operator use;
they do not automatically enable the service's host enrollment or DNS/IP pinning.
Browser and native MCP transports have their own contracts. The
[T3MP3ST comparison and AI-boundary map](research/t3mp3st_comparison.md) explains
which boundaries AgentScan measures and which need independent effect evidence.

## API service

Every tenant needs an administrator-defined target policy. Local and external analysis are separately disabled unless `allow_local_model_analysis` or `allow_external_model_analysis` is set to `true`. API clients select `analysis_mode: "deterministic"`, `"local"` or `"external"` and `data_classification: "sensitive"` or `"non_sensitive"`. Submission and worker execution both enforce the permissions and sensitive-data restriction.

Administrators select the installed local model through `AGENTSCAN_LOCAL_MODEL`, or an external provider/model through `AGENTSCAN_EXTERNAL_MODEL`. External selection has no default model. API/worker keys come from deployment environment or a secret manager, with no `.env` fallback. Jobs cannot supply model endpoints or provider keys. The service currently uses administrator-configured provider credentials; a per-tenant BYOK secret store is not implemented. A client running its own CLI/dashboard can use its own local key.

Example external request after the administrator explicitly enables that tenant and configures a provider:

```json
{
  "target_url": "https://agent.example.com/chat",
  "scan_mode": "SCAN",
  "analysis_mode": "external",
  "data_classification": "non_sensitive"
}
```

A provider key alone does not authorize external analysis, and an enabled tenant still cannot submit sensitive external work. The queued classification is encrypted with the canonical request and rechecked before execution. An external swarm starts with a fresh blackboard to avoid carrying previous sensitive-run intelligence into provider prompts.

API and worker replicas require the same persistent Fernet key file via `AGENTSCAN_DATA_KEY_FILE`. Keep the key outside Git, protect its file permissions and back it up through the deployment's secret manager. To create it locally, after installing the API extra:

```bash
python -c "from cryptography.fernet import Fernet; from pathlib import Path; Path('agentscan-data.key').write_bytes(Fernet.generate_key())"
```

Pending requests, including target headers and system prompts, are encrypted in PostgreSQL. Redis entries carry scan and tenant identities. Terminal completion, failure or cancellation clears the encrypted request and outbox entry. Rotation requires draining pending work or migrating it with the old key; replacing the key without a migration can make pending requests unreadable.

Persisted service reports omit raw request/payload/response evidence, message and header fields, tool arguments and trajectories. Digests record evidence identity without retaining its contents. Known submitted secrets and recognizable credential patterns are redacted from remaining text, and target URL queries are omitted. Pattern matching cannot identify arbitrary confidential prose in every metadata field; minimize retained descriptions and restrict database, logs, backups and authenticated report access.

Terminal reports and replay events expire after `AGENTSCAN_RETENTION_DAYS`, default **7**, allowed **1–365**. Reconciliation removes up to 1000 expired terminal records per minute and cascades their events. Tenant deletion removes a terminal record and its events immediately. Active jobs remain recoverable until completed or cancelled. Backups and infrastructure logs need their own retention controls. Local CLI/dashboard evidence stays under the operator's filesystem policy and is not covered by service cleanup.

Interrupted local remediation can retain private `.agentscan-recovery` journals containing original file contents. Review and recover them under the operator's access/retention controls. Sandbox workspace copies exclude those journals, preimage backups and private replacement staging files; a local recovery receipt is not an ordinary scan artifact.

## Evidence limits

Text matches and synthetic workspace delivery are candidate observations. They do not establish executed tools, target retrieval or changed files/databases. A confidential canary must be provisioned in the target independently and kept out of attack prompts. Synthetic benchmark and local judge controls are smoke checks; they do not establish independent detector accuracy or target safety.

The current flow and function explanations are maintained in [internal diagrams](../internal_docs/diagrams/README.md), including [sensitive data and three analysis choices](../internal_docs/diagrams/17_sensitive_data_flow.md).
