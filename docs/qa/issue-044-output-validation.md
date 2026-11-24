# QA-044 ? Output path and format validation

**Issue:** [#44 ? [P3] Output path and format validation](https://github.com/PrathaMesh3056/AgentScan/issues/44)
**Status:** Implementation complete; awaiting owner review.
**Base:** main at 7c17743

## Summary

AgentScan decides the report format from the output file extension and writes the file only after a scan or audit has already run. A bad destination (missing directory, an existing directory, an unsupported extension) therefore wastes the whole run and can surface as a raw Python traceback. Writes are also direct, so a serialization or PDF failure can leave a partial artifact.

This PR validates the output destination and format before work starts, writes reports atomically, and makes the extension/format contract explicit.

## Problem and impact

- agentscan/_cli/_shared.py write_report inspects output_path.suffix only when the report is ready.
- A missing parent produces FileNotFoundError; a directory path produces IsADirectoryError.
- An unsupported extension raises typer.BadParameter after the scan, when findings may already have been produced.
- .JSON works only because the suffix is lowercased; extension and format are otherwise implicit.
- Direct Path.write_text calls can leave a truncated file if serialization or PDF rendering fails.

Operator impact: wasted long-running scans, confusing tracebacks, and possible data loss or partial artifacts.

## Reproduction (to be recorded with exact output)

1. Run a scan with --output missing-dir/report.json and observe a traceback instead of a bounded usage error.
2. Run a scan with --output report.txt and observe the failure only after the scan completes.
3. Point --output at an existing directory and observe IsADirectoryError.
4. Simulate a serialization failure during a write and observe the destination left partially written.

## Scope

- Add one preflight validator for report output paths used by scan and audit.
- Accept exactly .json, .html, .pdf, .sarif (case-insensitive).
- Reject unsupported extensions, missing parents, non-directory parents, and existing directories before work begins.
- Write through a temporary file in the destination directory and os.replace on success; clean up the temp file on failure.
- Keep the existing CLI flags and report content unchanged.
- Document the supported extensions and the --output semantics.

## Non-goals

- Changing report schemas or adding new output formats.
- Touching the PDF dependency stack (that is issue #21 in the P1 table).
- Refactoring unrelated writers (gateway_exporter, profile export) in this PR.
- Editing agentscan/core/ or agentscan/action/.

## Proposed change

1. Add validate_report_output(path) beside write_report in agentscan/_cli/_shared.py.
2. Call it in scan and audit immediately after CLI options are resolved and before scanners run.
3. Refactor write_report to serialize to a temporary sibling file, flush and close it, then os.replace.
4. Raise typer.BadParameter with the path, the offending suffix, and the supported list.
5. Add tests that fail before the fix and pass after it.

## Test plan

- Unit: validator accepts .json, .JSON, .html, .pdf, .sarif; rejects .txt, no suffix, missing parent, file-as-parent, and existing directory.
- Unit: write_report leaves no destination and no temp file when serialization fails.
- CLI: scan --output missing/report.json fails before the scanner is invoked with a bounded message, no traceback.
- CLI: uppercase extension still writes the expected format.
- Targeted run: pytest tests/test_cli.py tests/test_reporting -q.
- Ruff on changed Python files.

## Implementation evidence

Recorded on the clean clone with the synthetic loopback fixture (`http://127.0.0.1:9/chat`) and a patched runner:

- Before: `--output missing-dir/report.json` ran the scanner, exited 1, and raised `FileNotFoundError`.
- Before: an existing directory destination ran the scanner, exited 1, and raised `PermissionError` on Windows (`IsADirectoryError` on POSIX).
- Before: `--output report.txt` ran the scanner, exited 2, and reported `Unsupported output format: .txt` only after the scan.
- Before: a simulated PDF render failure left a 12-byte `report.pdf` destination behind.
- After: all three scan cases exit 2 with a bounded `BadParameter` message and the scanner is not invoked.
- After: the simulated PDF failure leaves no destination and no temporary file.
- `pytest tests/test_cli.py tests/test_reporting -q`: 120 passed, 2 skipped.
- `ruff check` on the changed Python files: All checks passed.

## Risks and rollback

- Risk: preflight rejection of paths that previously worked (for example, a parent created by another process during the scan). Mitigation: only require the parent to exist at validation time; allow an existing directory only as the parent, never as the destination.
- Risk: atomic replace changes permissions on some platforms. Mitigation: preserve the temp file mode where practical and test on Windows and Linux.
- Rollback: revert the validator call sites and the write_report implementation; report content is unchanged.

## Review checklist

- [x] Reproduction recorded before the fix.
- [x] Failing test added first.
- [x] Validator called before scanners in scan and audit.
- [x] Atomic write leaves no partial destination on failure.
- [x] Uppercase and mismatched extensions covered.
- [x] Targeted tests and Ruff pass.
- [x] No changes under agentscan/core/, agentscan/action/, or the P1 workstreams.
- [x] Commit message references #44.
