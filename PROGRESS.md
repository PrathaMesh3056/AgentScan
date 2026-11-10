# AgentScan Runtime Gateway v1 — Implementation Progress

**Last updated:** 2026-11-10
**Phase 0 head:** `2721a15` (skeleton `8654034`; test/evidence `2721a15`)
**Worktree:** `D:\prathamesh\AgentScan-gw-impl`
**Branch:** `feat/runtime-gateway-v1`
**Base:** `origin/main` @ `1ed8942` (`docs: mark runtime gateway spec approved`)

This file tracks phase gates, evidence, and decisions. It is not a security
approval, and it does not replace `docs/RUNTIME_GATEWAY.md`.

---

## Phase status

| Phase | Scope | Status | Evidence |
|---|---|---|---|
| 0 | Dependency gate, config/skeleton, import boundary | Verified and committed | Dependency/API gate and import-boundary test below |
| 1 | Policy bundle, signing/verification, evaluation | Not started | — |
| 2 | Receipts, chain, WAL, writer lease/epoch | Not started | — |
| 3 | Idempotency, recovery, reconciliation | Not started | — |
| 4 | Identity, sessions, MCP server, protocol pin | Not started | — |
| 5 | Upstream client, mock upstream, end-to-end | Not started | — |
| 6 | CI, docs/runbook, benchmark/soak, draft PR | Not started | — |

Implementation stops at each user-requested checkpoint. Phase 1 remains not
started pending the user's review of this checkpoint.

---

## Phase 0 summary

Handoff §4's clean-worktree snapshot was stale at takeover: Luna's uncommitted
Phase 0 files (`pyproject.toml`, `uv.lock`, the gateway package, and the
import-boundary test) were already present. They were preserved, then committed
as the Phase 0 checkpoint.

The Phase 0 checkpoint contains:

- `pyproject.toml`: `agentscan-gateway` script, `gateway` extra, and `gateway`
  added to `full`.
- `uv.lock`: gateway extra metadata only; `mcp` remains `1.30.0`; 203 packages.
- `agentscan/gateway/`: eight Python modules — `__init__`, `__main__`, `cli`,
  `config`, `canonical`, `models`, `errors`, `logging`.
- `tests/test_gateway/test_import_boundary.py`.


---

## Phase 0 checkpoint

Committed as the Phase 0 checkpoint after the user confirmed Phase 0 and
requested a stronger import test and exact gate evidence. Contents:

- `pyproject.toml` — gateway extra/script, `full` union.
- `uv.lock` — gateway metadata only.
- `agentscan/gateway/` — Phase 0 skeleton; no security-critical logic.
- `tests/test_gateway/test_import_boundary.py` — imports every discovered
  gateway submodule in a subprocess and verifies the forbidden modules stay
  unloaded.
- `PROGRESS.md` — this file.

The checkpoint is **not** a claim that the v1 security gates are met.

Checkpoint commits:

- `8654034` — skeleton: script/extra, gateway package, import-boundary test,
  initial `PROGRESS.md`.
- `2721a15` — strengthened import-boundary test and captured gate evidence.

---

## Phase 0 verification

The dependency/API gate commands and their captured outputs:

```powershell
uv sync --locked --extra gateway --dev
Resolved 203 packages in 1ms
Checked 118 packages in 14ms

uv run --no-sync python -c "import mcp; from mcp.types import LATEST_PROTOCOL_VERSION; from mcp.server.streamable_http_manager import StreamableHTTPSessionManager; from mcp.server.auth.provider import AccessToken, TokenVerifier; from mcp.server.auth.middleware.bearer_auth import BearerAuthBackend, AuthenticatedUser; from mcp.client.streamable_http import streamable_http_client; from mcp.client.session import ClientSession; assert LATEST_PROTOCOL_VERSION == '2025-11-25'; print('mcp gate ok')"
mcp gate ok

uv run --no-sync python -m pytest -q tests/test_gateway/test_import_boundary.py
.                                                                        [100%]
1 passed in 0.37s

uv run --no-sync python -m agentscan.gateway --help
usage: agentscan-gateway [-h] [{serve,verify,policy,reconcile}]

positional arguments:
  {serve,verify,policy,reconcile}
                        gateway operation (implemented in subsequent phases)

options:
  -h, --help            show this help message and exit

git diff --check
(no output; exit code 0)

gh pr view 12 --json state,isDraft,mergedAt
{"isDraft":false,"mergedAt":null,"state":"OPEN"}
```

`mcp` was `1.30.0`; `uv.lock` added gateway extra metadata without changing
locked package versions. Windows Application Control blocked direct execution
of the generated `pytest` and `agentscan-gateway` executables, so the Python
module commands above were used and passed.

### Coordinator rerun (2026-11-10)

The coordinator independently re-ran the gate after commit `2721a15`:

```text
uv sync --locked --extra gateway --dev
Resolved 203 packages in 1ms
Checked 118 packages in 8ms

MCP API gate
mcp gate ok

uv run --no-sync python -m pytest -q tests/test_gateway/test_import_boundary.py
.                                                                        [100%]
1 passed in 0.46s

gh pr view 12 --json state,isDraft,mergedAt
{"isDraft":false,"mergedAt":null,"state":"OPEN"}
```

The direct `pytest` launcher remains blocked by Windows Application Control;
the Python module invocation was used instead. No policy, identity, receipt,
session, or upstream code was written.


PR #12 is open and unmerged. Its `isDraft` value is `false`; the query was
read-only and did not modify the PR.
