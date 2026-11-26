# Issue #47 — Documentation consistency (P3)

**Working branch:** `fix/qa-047-docs-consistency`
**Base:** `origin/main` at `7c17743`
**Issue:** [#47](https://github.com/PrathaMesh3056/AgentScan/issues/47)
**QA IDs:** QA-100, QA-123, QA-124, QA-125, QA-128, QA-129, QA-130, QA-131, QA-132
**Constraint source:** issue body and `QA_REVIEW_PROGRESS.md` review at `7c17743`.

> No `QA_REVIEW_PROGRESS.md` is present in the checked-out repository or the public
> remote. The item list below was reconstructed from the issue theme and from
> differences found by comparing live Typer help, the manual/README/START_HERE
> guides, and the implementation at the base commit. Each finding names the
> exact file and observed behavior so it can be reviewed independently.

## Goal

Make help text, the manual, and runtime behavior agree for targets, report
formats, profile keys, exit codes, attack counts, and `verify-claims`; replace
the live third-party example with a synthetic loopback one; and make the counts
come from the attack registry instead of literals.

## Findings and planned changes

| ID | Finding at `7c17743` | Planned change |
| :--- | :--- | :--- |
| QA-100 | `agentscan scan --help` calls the target an "HTTP endpoint", while `Target` accepts `http(s)`, `ws(s)`, `mcp://stdio`, `mcp+sse://`, and `mcp+sses://`; README/manual advertise more schemes than the target table/manual reference lists. | Update `scan` target help, README supported-target rows, and the manual `Target` reference to the exact scheme set. |
| QA-123 | `scan --output` and `audit --output` both say "JSON only", but `write_report` dispatches `.json`, `.html`, `.pdf`, and `.sarif`. | Update both option helps and keep the manual extension table; add a help regression assertion. |
| QA-124 | `scan --config` help says profiles contain a `connector (browser/curl)` key, which the loader never reads. The real blocks are `request_template` and `browser`. | Correct the help string and assert the documented blocks match the loader. |
| QA-125 | `scan` exits `3` for an incomplete assessment and `2` for usage errors; the manual only mentions exit `1` for `--fail-on`. | Add an exit-status section to the manual, mention `3` in `scan` help, and add a behavior-aligned test. |
| QA-128 | `agentscan_list_attacks` metadata says "all 23 registered" modules; the runtime registry currently reports 24 modules without the optional DEEP extra (27 authored). | Remove the hardcoded count from MCP metadata; the handler already computes the count. |
| QA-129 | Manual says the trajectory log records "`ATK-001` through `ATK-013`", but the registry contains non-contiguous IDs including ATK-027, ATK-028, ATK-050, and ATK-SOC-001. | Replace the stale range with a registry-driven reference. |
| QA-130 | START_HERE hardcodes 27/15/11/6 module counts while `list-attacks` shows only currently loadable modules (verified here: 24 modules — 15 SCAN, 11 EXPLOIT, 3 DEEP — without the `deep` extra, 27 authored); the manual also says "registry of 23". | Have `list-attacks` print counts derived from the registry, remove hardcoded totals from the guides, and explain optional-DEEP availability. |
| QA-131 | `verify-claims` exists in top-level help but is absent from the manual; its default receipt path and exit-1 failure behavior are undocumented. | Add a manual subsection with `--receipt`/default path and exit behavior; assert the documented options against live help. |
| QA-132 | The manual's auto-discovery example uses the live third-party endpoint `https://bitinfusiontechnology.com/backend/chatbot/chat.php`. | Replace it with a synthetic loopback profile (`http://127.0.0.1:8000/chat`). |
| Extra | `compliance --help` lists only `eu-ai-act` and `nist-ai-rmf`, while the command implements `mitre-atlas` and `iso-42001` (and the manual already uses them). | Include all four framework values in help/docstring. |

## Implementation steps

1. **Docs first (this commit).** Add this plan, push the branch, and open a draft PR.
2. **Help/behavior alignment.** Touch only CLI command modules and the MCP
   metadata description:
   - `agentscan/_cli/commands/scan.py`: target schemes, `--config` blocks,
     `--output` formats, and an incomplete-assessment exit note.
   - `agentscan/_cli/commands/audit.py`: `--output` formats.
   - `agentscan/_cli/commands/misc.py`: `verify-claims` help/exit note,
     `list-attacks` registry-derived count footer, and all four compliance
     frameworks.
   - `agentscan/mcp/server.py`: remove the hardcoded attack count from the
     metadata description (the handler already derives it).
3. **Manual/guide alignment.** Update
   `docs/AgentScan_Manual.md`, `README.md`, and `docs/START_HERE.md` for the
   same facts, the exit-status table, the `verify-claims` section, and the
   synthetic discovery example. Historical evidence in `ROADMAP.md`,
   `docs/EVALUATION.md`, and module docs is not rewritten.
4. **Tests.** Add `tests/test_docs_consistency.py`:
   - derive attack counts/IDs from the registry and assert the `list-attacks`
     output and MCP metadata track them;
   - parse one-line `agentscan <command> ...` examples from the guides and
     assert each command exists and each `--long-option` is present in live
     Typer help (copy-paste check);
   - assert scan/audit output help lists all four formats;
   - assert compliance help lists all four frameworks;
   - assert scan target/config help names the supported schemes and real
     profile blocks;
   - assert the manual exit-status table is present and the documented
     `verify-claims` options match live help;
   - assert no live third-party host is used in executable examples.
5. **Verification.** Targeted docs/consistency tests, related CLI/docs tests,
   full-suite smoke where practical, and `ruff check` / `ruff format --check`
   on changed Python.

## Non-goals / boundaries

- No edits to `agentscan/core/`, `agentscan/action/`,
  `agentscan/reporting/audit_verifier.py`, or `docs/RUNTIME_GATEWAY.md`.
- No #41 API quickstart/claims work, #36 audit-report docs, #43 error handling,
  #45 security headers, #46 CLI/UI polish, #48 CI hygiene, or #49 state/webhook
  work.
- No broad refactor, formatting churn, behavior renames, or network calls.
- Examples use loopback/synthetic fixtures only; no credentials or external
  providers.

## Acceptance criteria

- [ ] Help, manual, and behavior agree for every item above.
- [ ] Counts shown by `list-attacks` come from the registry; no stale hardcoded
      total remains in help/manual/MCP metadata.
- [ ] The live third-party example is replaced with a loopback example.
- [ ] Copy-paste and registry-driven regression checks fail before the fixes
      and pass after them.
- [ ] Targeted tests, related CLI/docs tests, and Ruff pass; commit messages
      reference #47.

## Resume status (2026-11-26)

- The interrupted run's clone and this untracked plan were inspected and kept.
- Issue #47 already has the owner's pickup comment dated 2026-11-25; no duplicate
  comment is needed.
- No PR existed for `fix/qa-047-docs-consistency` when work resumed.
- Registry check on the verification interpreter: 24 loadable modules without
  the `deep` extra (15 SCAN, 11 EXPLOIT, 3 DEEP); ATK-024/025/026 are the three
  optional DEEP modules that need `torch`. The 27 authored figure in START_HERE
  is therefore source-level, not the default `list-attacks` output.
- Implementation follows in a second commit: CLI help, MCP metadata, manual,
  README, START_HERE, and `tests/test_docs_consistency.py`.

## Rollback

Revert the implementation commit; the docs-first commit is independent and can
be reverted separately. No data migrations or runtime state are involved.
