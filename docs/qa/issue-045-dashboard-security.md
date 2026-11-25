# Issue #45 — P3: dashboard headers and secret handling

Status: in progress (docs-first commit; implementation follows on the same branch)
Issue: [#45](https://github.com/PrathaMesh3056/AgentScan/issues/45) — QA-189, QA-190, QA-191, QA-192, QA-193
Base: `origin/main` @ `7c17743` (`refactor(ui): modularize dashboard scripts and dedupe page routes`)
Branch: `fix/qa-045-dashboard-security`
Related, but separate: #35 / #37 / #40 (secret and status work) — left intact, not reverted.

## Why

The dashboard is a local operator surface, but its responses and its form handling
still leak information a browser tab should not keep:

| ID | Finding | Current behaviour |
| --- | --- | --- |
| QA-189 | Absolute paths in 4xx bodies | `HTTPException(403, detail=str(error))` forwards `PathSecurityError` / `FixConflictError` text, which embeds absolute target and containment-root paths. |
| QA-190 | Missing headers on early returns | `nosniff` is set only by the report-download route; the middleware's Host/origin/fetch-metadata/auth denials return `JSONResponse` before the header block, so those responses carry no security headers at all. |
| QA-191 | Shallow CSP | Only `frame-ancestors 'none'` is set; there is no `default-src`, no `object-src`, no `base-uri`/`form-action` restriction. |
| QA-192 | Secrets retained in the DOM | `#scan-canary-token` and `#cert-secret-key` keep their values after submission; no code path scrubs dashboard storage for secret-shaped keys. |
| QA-193 | `secret_key` accepted on GET | `GET /api/certificate?secret_key=…` still signs and logs a deprecation warning, putting a signing key in URL history, referrers and proxy logs. |

## Scope (the six exit conditions)

### 1. Strip absolute paths from 4xx bodies (QA-189)

- Add `redact_absolute_paths()` to `agentscan/ui/security.py`. It replaces
  Windows drive paths, UNC paths and POSIX absolute paths with a stable
  `[redacted path]` token and never echoes the original segment.
- Apply it once in the `HTTPException` handler in `agentscan/ui/app.py`
  (`public_error_detail()`), so every 4xx detail that reaches a response body is
  redacted at one boundary. The handler is the single place where
  `HTTPException.detail` becomes an `error` / `field_errors.request` value.
- Replace the two leaky raise sites with actionable, path-free copy:
  - `agentscan/ui/security.py::project_path` → "Choose a path inside the dashboard's configured project directory."
  - `agentscan/ui/routers/heal.py` (`/api/heal`, `/api/heal/apply`, webhook
    simulation) → path-free messages per failure class
    (`PathSecurityError` → 403 containment message,
    `FixConflictError` → 409 "file changed / not a regular file" message).
- `agentscan/guard/path.py` and `agentscan/remediation/` exception text is
  **not** changed: those messages are still useful to CLI callers and tests.

### 2. `nosniff` and standard security headers on early returns (QA-190)

- Add `security_headers()` / `apply_security_headers(response, *, secure)` to
  `agentscan/ui/security.py` and route every middleware response through it,
  including the direct denials. The middleware gains a local `deny()` wrapper so
  each early return keeps its current status code and JSON body.
- Headers on every response (success, denial, and handler-produced errors):
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`
  - `Referrer-Policy: no-referrer`
  - `Cache-Control: no-store`
  - `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()`
  - `Cross-Origin-Opener-Policy: same-origin`
  - `Cross-Origin-Resource-Policy: same-origin`
  - `X-Permitted-Cross-Domain-Policies: none`
  - `Content-Security-Policy` (see below)
  - `Strict-Transport-Security: max-age=31536000` only when the request arrived
    over HTTPS; a loopback `http` dashboard must not emit HSTS.
- Existing `set_cookie` behaviour, status codes and bodies are unchanged.

### 3. Deepen the CSP (QA-191)

Dashboard baseline, used whenever a route did not set its own policy:

```
default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';
img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none';
frame-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'
```

- `'unsafe-inline'` remains required for `script-src` and `style-src`: the
  dashboard markup uses inline `onclick` handlers, inline `style=` attributes and
  one small theme-bootstrap `<script>`. Removing those is a separate structural
  refactor, explicitly out of scope for this issue.
- No external origin is allowed: the UI loads no CDN assets, and all fetches and the
  `EventSource` are same-origin (verified against `agentscan/ui/static/`).
- A route-provided policy wins: the HTML report download keeps
  `sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'`
  and only gains `frame-ancestors 'none'` when that directive is absent.

### 4. Clear secret fields from the DOM and browser storage (QA-192)

- Add to `DashboardSemantics` (`agentscan/ui/static/dashboard.js`):
  - `clearSecretFields(scope)` — empties `input[type="password"]`,
    `[data-secret-field]` inputs and textareas, and removes any `value` attribute
    so the secret is not re-serialised into the DOM.
  - `scrubStoredSecrets(scope)` — removes dashboard `localStorage` /
    `sessionStorage` keys that look secret-shaped
    (`secret|token|key|password|credential|canary|certificate`), while preserving
    the allowlisted UI preferences `agentscan_theme` and `agentscan_font`.
- Call sites:
  - `triggerScanAction()` (`dashboard-app-actions.js`) — clear the canary
    reference once the dispatch request settles, success or failure.
  - `closeScanModal()` — clear on close.
  - `verifyCertAction()` (`dashboard-app-renderers.js`) — clear the signing key
    after verification settles, success or failure.
- Mark the signing-key input with `data-secret-field="true"` so the selector does
  not depend on `type="password"` alone.

### 5. Reject `secret_key` on GET (QA-193)

- `GET /api/certificate` keeps the `secret_key` query parameter declared (so the
  server can reject it explicitly instead of silently ignoring it) and returns a
  `400` validation body pointing at `POST /api/certificate` with a JSON body.
  The submitted value is never echoed back.
- `POST /api/certificate` and `POST /api/verify-certificate` keep their current
  behaviour, including the existing minimum-length checks.

### 6. Regression tests

New `tests/test_ui_security_hardening.py`, split by exit condition:

- 4xx bodies: containment violation, healing conflict, and a project-root
  override attempt contain no absolute path, drive letter, UNC prefix, project
  root string or username segment.
- Headers: untrusted Host, untrusted origin, cross-site fetch metadata,
  missing bearer token, dashboard-origin target guard and unexpected 500 all
  carry the full header set; `nosniff` and CSP are present on a normal page.
- CSP: dashboard baseline directives present; HTML report download keeps
  `sandbox`/`default-src 'none'` and gains `frame-ancestors 'none'`.
- Secrets: node-backed test (same `shutil.which("node")` harness style as
  `tests/test_ui_factuality.py`) that stubs `document` / `localStorage` and
  asserts values and secret-shaped keys are removed while UI preferences
  survive; plus assertions that the scan and certificate flows call the scrubber.
- GET rejection: `GET /api/certificate?secret_key=…` → 400 without the key in the
  body; `POST /api/certificate` with the same synthetic key still signs.

## Files expected to change

| File | Change |
| --- | --- |
| `agentscan/ui/security.py` | redactor, CSP baseline, header application helpers |
| `agentscan/ui/app.py` | single secured-response path for middleware, redacted HTTPException detail |
| `agentscan/ui/routers/heal.py` | path-free 403/409 detail messages |
| `agentscan/ui/routers/identity.py` | reject `secret_key` on GET |
| `agentscan/ui/static/dashboard.js` | `clearSecretFields` / `scrubStoredSecrets` |
| `agentscan/ui/static/dashboard-app-actions.js` | clear canary after dispatch / on modal close |
| `agentscan/ui/static/dashboard-app-renderers.js` | mark + clear signing key after verification |
| `tests/test_ui_security_hardening.py` | new regression tests |
| `docs/qa/issue-045-dashboard-security.md` | this plan |

No other file is intended to change.

## Verification plan

```
$env:PYTHONDONTWRITEBYTECODE='1'
python -c "… pytest.main([…])"   # wrapper from the issue workflow
```

- Targeted: `tests/test_ui_security_hardening.py`
- Related existing UI/security suites: `test_ui_structure.py`,
  `test_ui_features.py`, `test_ui_target_selection.py`,
  `test_ui_form_validation.py`, `test_identity/`, `test_ui.py`,
  `test_ui_lifecycle.py`, `test_ui_gateway_status.py`
- `ruff check` and `ruff format --check` on the changed Python files
- `mypy` on the changed Python modules (result reported verbatim, including any
  environment-level blocker)

## Risks and rollback

- The header set is additive; the only behaviour change for existing clients is
  that `Cache-Control: no-store` now also covers denials (already the intent).
- CSP remains permissive for inline script/style so the current UI keeps working;
  the stricter policy would need a separate inline-handler refactor.
- Redaction is applied to error text only; status codes, field names and
  `field_errors` keys are unchanged.
- Rollback is a revert of the implementation commit; the docs commit is inert.

## Result

Implemented on `fix/qa-045-dashboard-security` (base `origin/main` @ `7c17743`):

- `ed3d8e5` — this plan (docs-first commit).
- `a037930` — security helpers, secured-response path, path-free healing/identity
  details, GET `secret_key` rejection, DOM/storage scrubbers and the new
  regression suite. `tests/test_ui.py` also moved its custom-key signature check
  from GET to POST, because a key in the URL is now rejected by design.

Verification (venv Python from the issue workflow, `--basetemp` under the session
workspace, `-p no:cacheprovider`):

| Check | Result |
| --- | --- |
| `tests/test_ui_security_hardening.py` on the fixed tree | 40 passed |
| Same file on a `7c17743` worktree (before the fix) | 36 failed, 4 passed |
| Related suites (`test_ui*`, `guard/test_path.py`, identity, identity-shrink) | 647 passed, 1 skipped |
| `ruff check` on changed Python | all checks passed |
| `ruff format --check` on changed Python | 5 files already formatted |
| `mypy` on changed modules | blocked by the host Application Control policy: `ImportError: DLL load failed while importing subtypes` |

The before/after run is the regression proof: every new test that exercises a
header path, a redacted 4xx body, the GET rejection or the DOM scrubber fails on
the base commit and passes here.

## Out of scope

`agentscan/core/`, `agentscan/action/`, `agentscan/reporting/audit_verifier.py`,
`docs/RUNTIME_GATEWAY.md`, issues #20–#34, #46 (CLI/UI polish), #47 (docs
consistency), #48 (CI hygiene), #49 (state/webhook). No refactor, no formatting
churn, no real credentials or external providers in fixtures.
