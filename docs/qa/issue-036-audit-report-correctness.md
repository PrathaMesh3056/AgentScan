# QA-036 ? Audit and report correctness

**Issue:** [#36 ? [P2] Audit and report correctness](https://github.com/PrathaMesh3056/AgentScan/issues/36)
**Status:** Documentation-first draft. Implementation commits follow.
**Base:** main at `7c17743`

## Summary

Mixed scan modes are mislabeled, audit/config checks overclaim, reports lose coverage and module errors, and the MCP/dashboard views can disagree with the CLI. Operators cannot tell what was actually assessed from the report alone.

This PR makes the coverage/status model explicit, preserves module errors, labels mixed modes correctly, qualifies overclaims, and adds parity tests for the same fixture across CLI, MCP, and dashboard output.

## Problem and impact

- CLI, MCP, and dashboard assemble orchestration/coverage independently, so the same run can produce different status and coverage claims.
- Report schema does not explicitly preserve which modules ran, which were skipped, and which errored.
- Audit/config findings can be presented as complete even when only a subset of checks ran.
- Mixed modes (for example, scan plus audit) are labeled as a single mode.
- Overclaims such as a clean result without evidence undermine the trust model.

## Reproduction (to be recorded with exact output)

1. Run the same synthetic fixture through CLI, MCP, and dashboard and compare status/coverage fields.
2. Force one module to error or be unavailable and confirm the report records it.
3. Run a mixed scan/audit and inspect the mode label.
4. Run an audit with only a subset of checks enabled and inspect the claim text.

## Scope

- Define one coverage/status model shared by the report schema and the three surfaces.
- Preserve module run/skip/error state in the report and JSON output.
- Correct mixed-mode labels.
- Remove or qualify overclaims; add `Not assessed` where evidence is absent.
- Add parity tests over one synthetic fixture for CLI, MCP, and dashboard.

## Non-goals

- New scanners or remediation behavior.
- Editing `agentscan/core/` or `agentscan/action/`.
- Broad dashboard redesign or unrelated formatting.
- The P1 workstreams #20-#34.

## Proposed change

1. Add an explicit coverage/status section to the report model and serializers.
2. Make CLI, MCP, and dashboard consume the same orchestration result rather than re-deriving labels.
3. Record module errors and skipped modules instead of dropping them.
4. Replace unsupported claims with qualified/unknown states.
5. Add parity and regression tests that fail before the fix.

## Test plan

- Unit: report schema preserves module run/skip/error state.
- Unit: mixed mode is labeled correctly.
- Regression: a clean claim is not emitted when a module did not run.
- Parity: CLI, MCP, and dashboard output agree for one synthetic fixture.
- Targeted pytest slice and Ruff on changed files; full suite in CI.

## Risks and rollback

- Risk: schema additions break consumers. Mitigation: additive fields only; keep existing keys and document defaults.
- Risk: parity tests expose unrelated drift. Mitigation: fix only the fields in scope and record the rest as follow-ups.
- Rollback: revert the model/serializer and surface changes; no scanner behavior changes.

## Review checklist

- [ ] Reproduction recorded before the fix.
- [ ] Failing-before tests added.
- [ ] One coverage model shared by CLI/MCP/dashboard.
- [ ] Module errors preserved.
- [ ] Mixed modes labeled correctly.
- [ ] Overclaims qualified.
- [ ] Targeted tests and Ruff pass.
- [ ] No changes under `agentscan/core/`, `agentscan/action/`, or P1 files.
