# AgentScan release and deployment readiness

Updated **11 October 2026** for source version **0.2.0**. The default deterministic CLI and local dashboard do not require Ollama, Torch, a GPU or Kubernetes. Select and validate the optional profiles needed for a deployment.

The [ATK-001 update](modules/prompt_injection.md) and dashboard charts have a
completion record. The earlier detector-only verification retains its original
source snapshot. Earlier
CPU-image and live-service proofs below retain their 9 October source scope;
they were not rerun for this module change. The later chart completion has a
separate dated verification record. Ordinary Linux/Python 3.12 mypy passed
on 182 source files on 10 October after a behavior-preserving trace typing repair;
the type-check record retains the Windows Application Control failures and the
Linux environment's scope. The complete Python 3.12/3.13 CI matrix remains a release requirement.
Synthetic checks do not certify a release or deployment.

The 11 October [ATK-005 document profile](modules/indirect_injection.md) has current
functional regression, owned HTTP/model-ingestion and fresh package evidence.
Its Windows mypy attempt was blocked by Application Control before checking code;
that historical document QA report retains its blocked verdict. Docker became available later on 11 October, and
ordinary Linux mypy passed on all 182 current production Python files with network
disconnected during analysis. The current verification record documents the unchanged source snapshot and
removal of the owned checking container.
The [separately authored retrieval step](modules/atk005_retrieval_validation.md)
also completed; its 4/6 benign result remains a utility limitation.

## Evidence and current limits

| Check | Current evidence | Meaning |
|---|---|---|
| Current ATK-005 functional checks | 11 October: 1,593 source and 72 Action tests passed; 32 skipped, eight slow deselected; Ruff lint/format passed; later 470 selected module/field checks passed | 1,665 combined local regressions include the 28 frozen document contracts. Later selected checks revalidate unchanged runtime source, not 470 additional unique tests. Live DB/image checks were not repeated. |
| Actual document HTTP/model boundary | All seven probes evaluated in each arm with correlated receipts and independent owned-fixture stage/read/model-input events; zero complete-reference disclosures | One exposed-seed local model run, no live positive to measure recall, only 1/2 strict benign tasks in both arms. No general resistance, customer-framework or defense-benefit claim. |
| Separately authored retrieval/model boundary | 12 frozen cases selected through real SQLite FTS5 search and evaluated in both arms; all event-chain checks and excluded operational controls passed | Six attack intents produced no complete-reference disclosure; live-positive recall is undefined. Benign utility is 4/6 in both arms; application output contract improved neither measured disclosure nor utility. Same-team small local sample, not customer efficacy. |
| Current package/doc bytes | Fresh offline wheel/sdist match all 224 runtime assets, including the new document YAML; Python/JS inventories and links pass | 182 Python files, 948 callables and 284 dashboard functions. No installed-profile, deployment or fresh Linux-matrix proof follows from archive/source checks. |
| Scoped ATK-001 and chart completion | 10 October: 1,627 ordinary tests passed, 32 skipped and 8 slow tests deselected; all 82 chart contracts are included in that total | The 24-seed known-reference disclosure implementation and local chart contract are complete. These are scanner regressions, not an independent real-agent accuracy benchmark. |
| Actual chart browser QA | 18/18 synthetic-report checks passed on 10 October in installed gstack Chromium | Real dashboard rendering, error/unknown states, keyboard filters, mobile overflow and dark theme passed. No console errors or off-origin requests were observed; this is scoped chart QA. |
| Configured Linux typing gate | Current-source mypy passed for 182 files on Linux/Python 3.12 on 11 October | The source snapshot stayed unchanged; typing ran with container network disconnected and the owned container was removed. Windows native mypy remains blocked by Application Control; the full CI Python matrix is still required. |
| Local release boundary/content tests | 72 passed on 7 October | Actual Bash argument boundaries, failure propagation and workflow/artifact guards were checked locally. No release was published. |
| Docker Engine | Client/server 29.1.3 responded | Actual host engine availability is verified through scoped execution; restricted-sandbox access denials were environmental. |
| CPU Linux image | Final frozen source rebuilt and verified on 9 October with the locked UI/API/telemetry profile; installed wheel reports 0.2.0 and imports core, CLI, UI, API server/worker under UID/GID 10001 | The exact owned image passed CLI help/version and real dashboard authentication, empty-field and origin/navigation checks. Its receipt records 58 installed Linux Python distributions, image identity and matching source fingerprints before build, after build and after verification. No DEEP image, full Linux test matrix, OS-package vulnerability scan or production service deployment is claimed. |
| Windows console entry points | Project, verification and PATH `agentscan.exe --help` passed outside the restricted verification sandbox | Installed native launchers start. Earlier sandbox denials were not installation failures. |
| CPU neural runtime | Global Python Torch 2.14.0+cpu/Transformers 5.17.0 loaded the pinned Qwen safetensors cache; actual activation/logits were finite and hooks were removed | Passed with every network connection blocked, in 42.437 seconds. Project/verification environments lack DEEP dependencies. CUDA/GPU availability is false; no GPU inference is claimed. |
| Deployment source defaults | Fourteen template/privacy invariant tests passed on 8 October; both Compose files validate with an empty environment and interpolation disabled | Locks, non-root defaults, required dashboard token, explicit image placeholders, dedicated DEEP scaling and restricted network templates are checked as source. These checks do not apply or enforce cluster boundaries. |
| API submission/recovery | 112 tests passed with zero skips against new disposable PostgreSQL 16/Redis 7 on 9 October | Tenant-scoped concurrent admission, idempotency, authorization, outbox/recovery and isolation paths were exercised against the final frozen source. Runtime and API-test fingerprints stayed unchanged. These host-Python tests do not establish image-level durable-service health, exactly-once target side effects or production deployment readiness. |
| Ollama | No executable, daemon or local model cache found | Local model-assisted analysis is unavailable on this host. Deterministic analysis remains available. No daemon was started or model downloaded. |
| Kubernetes | kubectl v1.34.1 installed; no usable current cluster configuration | Templates can be inspected locally; scheduling, secrets, KEDA and network enforcement are not verified on a cluster. |
| Remote release/account settings | Not queried | GitHub CLI/config presence does not establish valid authentication or protected environment/registry settings. |

The host/optional-runtime inventory is from 7 October; deployment-template checks are from 8 October; the final CPU image and live API proofs are from 9 October. Earlier receipts are retained separately rather than relabelled as current checks. Runtime versions are observations of this host, not supported-version guarantees. At the inventory time, existing editable environment metadata reported 0.1.0 while the source package declares 0.2.0; refresh the chosen installation profile before release verification. Keep all required extras in that profile, for example:

```powershell
uv sync --frozen --no-dev --extra ui --extra api --extra telemetry
uv run --no-sync python -m agentscan.cli --help
```

This command is a setup instruction; it was not run against the user's current environment during the inventory. Local evidence is retained outside the public repository and is not published.

## Image and local service preparation

Both Dockerfiles now copy `uv.lock`, select explicit runtime extras with `uv sync --locked --no-dev --no-install-project`, install the built wheel without re-resolving dependencies, and run as UID/GID 10001. The DEEP image actually includes `deep` extras and sets Hugging Face/Transformers offline flags. It is a CPU profile; neither installing Torch nor naming the image DEEP provisions CUDA.

The build context allowlist excludes `.env`, keys, local audits, tests, recovery material and caches, including operational files nested in the runtime package. The local dashboard Compose port binds to `127.0.0.1` and requires a dedicated `AGENTSCAN_UI_TOKEN`: Docker bridge traffic is not container loopback, so the guard correctly requires authentication. Set a random token locally, start the container, and open `http://127.0.0.1:8765/?token=<your-token>` once to establish the HttpOnly session. The dashboard redirects to the clean URL; cross-site API requests/writes and page embedding remain denied. Do not share or save the token in documentation. For example, in one PowerShell session:

```powershell
$env:AGENTSCAN_UI_TOKEN = [Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
docker compose up --build -d
```

Keep the token in that local session and supply it only in the initial dashboard URL. Direct `agentscan ui` on loopback can establish its local session without the Docker-specific token requirement. API Compose is a local development stack with separately required signing/data keys and tenant enrollment.

The 9 October final disposable CPU proof built the wheel into a locked Linux image, then exercised the real HTTP dashboard with a synthetic token. It checked a clean bootstrap redirect, HttpOnly/Lax cookie, unauthorized API denial, specific empty target/concurrency errors, unchanged idle state after rejected input, denied cross-origin/API/write/frame requests and allowed top-level page navigation. Matching before/after fingerprints cover runtime files and Docker installation inputs. The API proof used the same unchanged runtime snapshot and also checked the API-test fingerprint. Each helper removed only its UUID-labelled image/containers and owned anonymous volumes; existing resources were preserved. Earlier failed bootstrap/helper-path receipts and the passed proof before the final detector/benchmark changes are retained separately and are superseded by this final proof.

Before releasing an image:

1. Choose verified digests for the Python and uv base images. The supplied Dockerfiles pin the uv version but still use mutable image tags and operating-system package repositories; they do not claim a hermetic build.
2. Build in a clean approved environment, audit the selected **Linux** lock/dependency profile and image packages, and run startup/import/health tests against those exact built bytes. CPU and DEEP images need separate checks. The local CPU proof downloaded locked dependencies and checked imports/CLI/dashboard startup; API/worker imports alone do not establish image-level durable-service health, complete Linux regression, container/OS advisory coverage or the optional DEEP profile.
3. Exercise non-root volume ownership and mount modes, cancellation/restarts, resource limits and dependency outages. Configure TLS/authentication on externally accessible Redis/PostgreSQL services.
4. Record the image digest, source revision, dependency selection and test receipt. Scan/sign/provide provenance according to the release policy. Do not infer runtime integrity from a tag name.

## Kubernetes templates

The manifests are **operator templates**. API, CPU worker and optional DEEP worker image names contain an intentionally invalid digest placeholder; replace it with a tested release digest before any apply. No deployment has been performed.

`deploy/k8s/network-policy.yaml` denies unsolicited workload ingress and enables only selected DNS, PostgreSQL and Redis destinations. It adds narrow API ingress from a named ingress-controller namespace/pod selector. Its approved target-egress list is empty by default. Populate it with explicitly authorized target CIDRs/ports matching tenant origin/network policies; keep broad internet and model-provider egress blocked unless a separate controlled gateway is required for opted-in non-sensitive analysis.

Verify the cluster's CNI actually enforces NetworkPolicy, adapt namespace/pod labels and DNS behavior, and test allowed and denied connections from the deployed workload. NetworkPolicy is additive: another permissive policy, host networking or infrastructure routing can change the effective boundary. Source inspection does not establish enforcement.

The normal KEDA scaler covers SCAN/EXPLOIT streams. The optional `deep-worker-deployment.yaml` consumes only the DEEP stream, uses a bounded separate scaler and mounts an operator-provisioned pinned model-cache PVC read-only. Its cache layout must contain the revision in `agentscan/neural/qwen.py`. Read-only model-cache loading and hook cleanup need verification in the actual image. GPU placement/drivers are deliberately not supplied by this CPU template.

All queue scalers reference a `TriggerAuthentication` containing only the Redis scaler credential. Supply `redis-scaler-password` from a secret manager and use an appropriate Redis access policy; it is absent from the committed example Secret. Configure TLS and any ACL username, KEDA operator connectivity and Redis endpoint for the actual service. Missing authentication, image digest or model-cache prerequisites must be resolved rather than silently weakening the template.

The example Secret contains placeholders that deliberately fail startup. API/worker replicas must share a stable signing key where required, persistent queued-request encryption key, enrolled tenant policies and dedicated database/queue. Check key custody, backups/rotation, namespace RBAC, ingress TLS, retention, schema migration ownership and target authorization. `.gitignore` now excludes local `.env.*`, `deploy/k8s/secrets.yaml` and `secrets.*.yaml`; real secret files must still be kept outside version control and build contexts. The sanitized `secrets-template.yaml` remains a tracked example.

## CI and publication

The local source requires shared validation before tag publishing: Python 3.12/3.13 locked installation, Ruff, formatting, mypy, nonslow regression and Action tests, strict hashed advisory audit, wheel/sdist build and fresh installation profiles. Actions use commit pins; uv and pip-audit use explicit versions. Publishing downloads the validated 3.12 artifact from the same run instead of rebuilding it. Validation has read-only repository permissions; only the publishing job receives OIDC/content-write permissions and targets the `pypi` environment.

Repository/registry administrators must separately verify protected tags/branches, required checks, reviewer protection for `pypi`, the PyPI trusted publisher identity, artifact permissions/retention and Actions policy. Remote settings were not read or changed. The current pipeline does not provide independent SLSA provenance or exercise commercial models, GPU or production Kubernetes.

See [.github/SECURITY_GATES.md](../.github/SECURITY_GATES.md) for the exact gates. Run local checks with the selected verification environment:

```powershell
python -m pytest .github/tests tests/test_deployment_templates.py -q
```

These template checks inspect security defaults and configuration structure. They do not build an image or apply manifests.

## Preserve architecture safely

Detailed diagrams/function guides and private historical audits remain outside the public repository and are excluded from wheel/sdist/build contexts. Do not force-add private working material to the public tree.

For a public/reviewable architecture set, manually review and copy only selected sanitized Mermaid sources and explanatory Markdown into a tracked folder such as `docs/architecture/`, remove target-specific data and audit evidence, and link it from the tracked documentation. Keep detailed receipts/local explorers private unless separately reviewed. Root diagram sources can be regenerated from their source snapshots, but static call graphs cannot resolve every runtime receiver or plugin callback.
