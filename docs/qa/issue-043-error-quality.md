# Issue #43 — Error quality and raw tracebacks

## Context

- Base: `origin/main` at `7c17743`.
- Working branch: `fix/qa-043-error-quality`.
- Scope owner: #43. This plan deliberately does **not** take #44 output-validation work,
  #45 security headers, #46 CLI/UI polish, or #47 documentation consistency.
- Frozen modules: no edits under `agentscan/core/`, `agentscan/action/`, or to
  `agentscan/reporting/audit_verifier.py`.

## Problem

Several expected operator mistakes currently escape the CLI as raw exception
tracebacks or as generic messages that do not say which path or field failed:

1. An unreadable/malformed target profile says only “review its fields”.
2. A bad `framework` value or non-integer `attacker_turns`/`escalation_turns`
   raises `ValueError`/`KeyError` after the profile is loaded.
3. An invalid nested `request_template` raises a Pydantic validation traceback.
4. A missing `--curl` file raises `FileNotFoundError`; a malformed capture can
   raise a JSON parser traceback.
5. UTF-8 BOM-prefixed JSON reports fail in `verify`, `compliance`, `heal`, and
   `fix` even though the BOM is valid for operator-edited files.
6. `verify-claims --receipt` lets `JSONDecodeError` escape.
7. `--output report.pdf` without the `pdf` extra raises a `RuntimeError`
   traceback instead of a usage error.
8. Missing `audit`/`fix` paths and missing `--rules` files are not consistently
   rejected before scanner work starts.

## Bounded subset (this PR)

| ID | Failure class | Intended behavior |
|---|---|---|
| QA-043 | Profile path/YAML | Name the profile path; distinguish missing, unreadable, invalid YAML, duplicate keys, and non-mapping documents. |
| QA-044 | Profile fields | Name the offending field; keep `framework` choices explicit; report integer/request-template validation without a traceback. |
| QA-051 | cURL capture | Name the capture path; report parse failures and point at `--message-path`/JSON body. |
| QA-067 | JSON report BOM/parser | Read UTF-8 with BOM; report malformed input with path and line/column. |
| QA-076 | Verify-claims receipt | Bounded receipt-file error with path and JSON location. |
| QA-091 | Optional `pdf` extra | Bounded usage error naming the output path and the install extra. |
| QA-136 | Missing paths | Reject missing `audit`/`fix` targets and `--rules` files with the path in the message. |

Deferred IDs: `QA-102`, `QA-109`, `QA-127`, `QA-137`, `QA-140`, `QA-141`.
Several overlap #44’s output destination/format ownership; the remainder have no
reproducible evidence in the #43 body. They are not silently claimed.

## Implementation

1. Add a small CLI error helper (`agentscan/_cli/_errors.py`) for:
   - UTF-8-with-BOM text reads;
   - JSON object/array parsing with path, line, and column;
   - Pydantic validation field extraction;
   - integer field coercion with the field name.
2. Use the helper from `scan` (profile and cURL), `misc` (`verify`,
   `compliance`, `verify-claims`, `fix`), and `heal`.
3. In `scan`, catch profile field errors before Pydantic target construction,
   and format target/request-template validation errors by field.
4. In `_shared.write_report`, convert the optional-PDF `RuntimeError` into a
   `typer.BadParameter` naming the output path.
5. In `audit` and `fix`, validate path existence before scanner/engine work.
6. Keep messages actionable, single-line where practical, and free of raw
   tracebacks. Do not catch exceptions that indicate programming defects.

## Regression tests

New file `tests/test_cli_error_quality.py` with one test per failure class:

- missing/malformed/non-mapping profile names the path;
- bad `framework`, bad integer turn field, and bad nested template name fields;
- missing and malformed `--curl` captures name the capture path;
- BOM-prefixed report succeeds in `compliance` (and `fix`/`heal` smoke);
- malformed JSON reports report path and parser location;
- `verify-claims` malformed receipt is bounded;
- PDF write without `weasyprint` is a usage error naming the output path;
- missing audit/fix targets and `--rules` file are bounded.

Each test must fail against `7c17743` and pass after the change. No network,
external providers, real credentials, or loopback target traffic is required.

## Verification

```powershell
$env:PYTHONDONTWRITEBYTECODE='1'
& 'D:\prathamesh\AgentScan-gw-impl\.venv\Scripts\python.exe' -c "import os,sys; _m=os.mkdir; os.mkdir=lambda p,m=0o777,*a,**k:_m(p,0o777,*a,**k); import pytest; sys.exit(pytest.main(['tests/test_cli_error_quality.py','-q','-p','no:cacheprovider','--basetemp',r'C:\Users\prath\.deepai-code\scratch\2026-11-24-so-dont-touch-this-issue-c82a4f9a\qa43-bt']))"
& 'D:\prathamesh\AgentScan-gw-impl\.venv\Scripts\python.exe' -m ruff check agentscan/_cli tests/test_cli_error_quality.py
& 'D:\prathamesh\AgentScan-gw-impl\.venv\Scripts\python.exe' -m ruff format --check agentscan/_cli tests/test_cli_error_quality.py
```

Also run the existing CLI/test slices that exercise the touched commands, plus
the related remediation tests. Report any environment-only failure exactly.

## Result

Implemented and covered by `tests/test_cli_error_quality.py` (18 tests). Against
the base commit `7c17743` all 18 tests fail; after the fix all 18 pass. The
related existing slice (`test_cli`, `test_analysis_options`, `test_cli_fix`,
`test_audit_verifier`, `test_pdf_report`, `test_audit_coverage`) reports
**103 passed, 2 skipped**. Ruff check and format check pass.

## Acceptance criteria

- [x] At least five of the 13 IDs are covered by code and tests; this plan
      claims seven.
- [x] Every expected operator error names the field or path.
- [x] No raw traceback for the covered expected errors.
- [x] BOM-prefixed valid JSON is accepted.
- [x] No frozen files or unrelated refactors.
- [x] Targeted, related, Ruff, and format checks pass.
- [x] Draft PR opened after the docs commit; marked ready only after checks.

## Rollback

Revert the implementation commit; the docs commit is standalone and harmless.
