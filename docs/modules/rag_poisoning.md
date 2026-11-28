# ATK-008: RAG and knowledge-base poisoning

ATK-008 examines whether untrusted document content could affect a retrieval-augmented agent's answers. Its ordinary SCAN path sends eight retained document probes to an explicitly configured HTTP adapter and records bounded response observations. A repeated fact, citation or marker is **not** a poisoning finding: the agent may have quoted, challenged or correctly summarized the document. Only a separate, operator-owned local RAG fixture can assess an answer or citation effect against independently supplied facts and policy.

## Run document observations against your agent

Use an authorized test endpoint that implements the [`document_v1` request contract](indirect_injection.md#native-request-and-receipt). It receives the legitimate task and document in separate fields. Route the document through your actual ingestion/retrieval path and report a consumption receipt only when your application can observe the exact text supplied to its model. A receipt is a statement from the target, not independent proof of corpus insertion, ranking or causation.

Save a local `rag-target.yaml` with your own endpoint:

```yaml
url: http://127.0.0.1:8000/document
framework: unknown
indirect_adapter: document_v1
analysis_mode: deterministic
data_classification: sensitive
output: rag-report.json
```

```powershell
agentscan scan --config rag-target.yaml
# Or, from the project environment:
python -m agentscan.cli scan --config rag-target.yaml
```

These commands run the normal SCAN suite; there is no ATK-008-only CLI flag. AgentScan needs no commercial model key for its deterministic assessment. Your target may use its own model. In the dashboard, start `agentscan ui`, open the printed localhost URL, enter the same endpoint and select **Target implements document adapter v1** under **Indirect document assessment**. If the adapter is absent or the connector cannot send documents, ATK-008 is skipped before opening a target request. Ordinary chat, browser, WebSocket and MCP connectors have no document fallback.

## Read the result

| Result | Meaning |
| --- | --- |
| `SKIPPED` | The declared document adapter or a supporting connector is missing. |
| Document observation, `INCONCLUSIVE` | The response was recorded, but a marker or target-reported receipt cannot establish a poisoned corpus, retrieval influence or a false endorsed answer. |
| Request error or incomplete response | Fix authentication, transport, output mapping or response limits; a failed request is not a successful defense. |
| `owned_rag_lab` finding | The separate owned fixture recorded an independently checked, narrow answer-integrity or citation-policy violation. This is local evidence, not a customer-agent finding. |

The per-probe report records a response digest, receipt status and indicator presence; the dashboard shows the bounded status and indicator fields. Neither observation copies the raw document or answer. Even a correlated receipt remains target-reported. The default eight probes produce no evaluated impact findings or clean security negatives, and their outcomes do not raise a target score. A mixed scan's score may reflect other modules. Protect local transcripts and reports according to your data policy; other diagnostic paths can contain redacted target text.

## Validate the owned retrieval pipeline

The [frozen local method, version 3](../../benchmarks/evaluation/atk008_METHOD_v3.md) runs the production ATK-008 path against a disposable SQLite FTS retrieval application. It compares permissive corpus admission with authenticated publisher and reviewed source/digest admission, followed by a narrow structured-answer check using only trusted, actually retrieved documents. The same nine attack/control and eight ordinary-update cases are submitted to both arms, including approved document bytes presented by an unapproved caller. The fixture independently inspects corpus changes, retrieved sources and ranks, generated answers and a fixed answer/citation policy before recording a local witness. These local findings stay outside customer scores.

From the repository root, with the project and test dependencies installed, use a **new** output directory for each run:

```powershell
python -m benchmarks.evaluation.atk008_run --output evaluation-output/atk008-extractive-run-1
```

Read `summary.json`, `journal.json` and `scanner-reports.json` together. The default generator is an intentionally vulnerable **extractive engineering control**, not an LLM or evidence of model resistance. If a compatible local Qwen snapshot and runtime are already installed, the optional phase runs actual offline generations:

```powershell
python -m benchmarks.evaluation.atk008_run --output evaluation-output/atk008-model-run-1 --snapshot C:/path/to/already/cached/Qwen2.5-0.5B-Instruct/snapshot
```

The optional phase does not download weights or call an external provider. Missing weights, invalid answer format or incomplete generation remain unavailable or inconclusive; they cannot become clean outcomes. Keep extractive and model results separate, including their denominators. The local fixture establishes behavior only for its frozen corpus, retrieval rule, generator and answer contract. It does not validate a production vector index, customer data, arbitrary citations, permissions, multimodal material or downstream actions.

On 19 October 2026, the cached Qwen2.5-0.5B-Instruct run assessed all 17 cases in each arm. The permissive baseline had five answer/citation violations, including one ordinary-update error. The defended application delivered zero violations and eight correct ordinary updates out of eight. Its raw model output still had one ordinary-update error, corrected from the two authenticated retrieved source parts. The journal retains the raw and delivered verdicts separately. This is an exposed synthetic fixture result; version 2's failed gate is preserved, and these results do not establish general model resistance.

## Defenses and research basis

At the application boundary, authenticate corpus publishers, review the full source before admission, preserve source/version integrity, enforce retrieval permissions and keep auditable source-to-answer traces. Use an independently trusted answer and citation policy when testing factual corruption. A digest confirms consistency with an approved document; it does not prove the document is true or safe. AgentScan demonstrates one owned admission control but does not install defenses on a remote target.

The module's OWASP label is [LLM08:2025, vector and embedding weaknesses](https://genai.owasp.org/llmrisk/llm082025-vector-and-embedding-weaknesses/); poisoned data and retrieved instructions can also overlap other OWASP categories. [OWASP's RAG Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/RAG_Security_Cheat_Sheet.html) informs source governance and retrieval controls. [Zou et al., *PoisonedRAG*, USENIX Security 2025](https://www.usenix.org/conference/usenixsecurity25/presentation/zou-poisonedrag) motivates measuring both corpus insertion and answer influence. [Tan et al., *PRA-RAG*, Findings of ACL 2026](https://aclanthology.org/2026.findings-acl.1794/) studies robust aggregation under its stated corruption model; AgentScan does not implement its guarantees. [Lu et al., *ToxicRAG*, September 2026 preprint](https://arxiv.org/abs/2609.11082) motivates the local knowledge-update narrative case. These papers' results are the authors' results, not AgentScan measurements.

An [original Slack AI researcher demonstration](https://www.promptarmor.com/resources/data-exfiltration-from-slack-ai-via-indirect-prompt-injection) illustrates how retrieved lower-trust text can alter a live application's answer and obscure source attribution. Its described exfiltration requires a user click, and the uploaded-file route was not tested in that disclosure. It is an adjacent indirect-injection example, not evidence that AgentScan has reproduced a production RAG corpus compromise.
