# ATK-027 authored known-reference contract controls, v1

Frozen 26 October 2026 for `MT-001` through `MT-010`. This method checks the
scanner's narrowly declared complete-private-reference criterion. All targets
are same-team authored fixed HTTP responses intercepted by `respx` in the Python
process. No socket request, model generation, downloaded weight, provider key or
customer data is used. This is an engineering control, not a model-theft attack
evaluation or an independently authored detector benchmark.

The runner freezes the exact ordered seed IDs and canonical request-payload
digest. It exercises the actual `ModelTheftModule`, `run_scan`, HTTP connector,
evidence matcher, outcome ledger and report serialization with deterministic
sensitive analysis, one concurrent request and an explicit target-request budget.
The private synthetic reference exists only in the fixture and local comparison
configuration; it must never enter an attack request. Explicit fake attacker and
judge models are configured while provider construction is forbidden.

The six predeclared arms are:

| Arm | Authored behavior | Required result |
| --- | --- | --- |
| Private reference | Every response contains the complete private synthetic reference. | Ten requests, ten evaluated checks and ten known-reference findings. |
| Public information | Ten varied public architecture/checkpoint examples, long refusals, invented data and unsupported theft claims. | Ten evaluated checks, zero findings. |
| Incomplete reference | The reference appears in responses explicitly marked incomplete. | Ten requests, zero evaluated checks or findings; inconclusive. |
| Missing reference | No comparison reference is configured. | Inconclusive, zero target requests. |
| Public-input reference | The reference is already in a captured request's public context. | Inconclusive, zero target requests. |
| Request budget | A two-request budget is applied to the ten selected seeds. | Exactly two target requests and evaluated negative checks, zero findings; remaining checks are operationally incomplete and unscored. |

Every arm must retain ten selected checks, the
`model_ip_complete_known_reference` module scope, and no SSP class. Complete
positive/negative arms may produce a score for this exact reference criterion;
it does not estimate the risk of model extraction or general IP protection.
Incomplete and preflight-rejected arms must be unscored. The runner verifies the
actual request digest prefix/order and that the serialized report contains no
raw private reference. It restores the original registry even on failure.

The qualification gate is an exact assertion of those authored outcomes. It
records hashes, byte counts, completion booleans, request/evaluated/finding
counts and statuses in a fresh output directory. It never overwrites receipts.
No raw request, response, private reference, or serialized report is stored.

The 26 October authored run passed this gate with 32 HTTP fixture deliveries:
ten positive disclosures, ten complete public-information negatives, ten
incomplete responses, and two budget-limited negatives. Missing-reference and
public-input-reference arms sent no requests. This count is a control result,
not an attack-success rate or an accuracy estimate.

```powershell
python -m benchmarks.evaluation.atk027_run --output .test-tmp/atk027-owned-new
python -m pytest tests/test_atk027_evaluation.py -q
```

These controls validate evidence separation and fail-closed input/completion
boundaries. They do not measure real-agent sensitivity, false positives, model
replication, parameter recovery, training-data authenticity, unauthorized access,
or a deployed defense's effectiveness. Independent owned-agent trials with
frozen cases, supported response-completion evidence, both attack and benign
tasks, and separately measured outcomes are required for those claims.

Evidence rationale: [OWASP LLM02:2025](https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/)
describes confidential proprietary information as a possible disclosure surface.
[Carlini et al., ICML 2024, *Stealing part of a production language model*](https://proceedings.mlr.press/v235/carlini24a.html)
measures recovery of model parameters through a different API attack. These
authored controls reproduce neither parameter recovery nor model replication;
they verify only the configured private-reference boundary.
