# AgentScan security boundaries

AgentScan audits security through active testing, filesystem inspection, and optional remediation. Claims must be tied to installed versions, deployment configuration, and tested paths. Earlier snapshots are recorded in `Codex audit/` and `AUDIT_PHASE2.md`. The current fixes do not establish a zero-CVE dependency closure or production certification.

## Local dashboard

The dashboard checks Host against operator-configured hosts, requires matching browser Origins, and rejects cross-site Fetch Metadata before mutations. Default hosts are `127.0.0.1`, `localhost`, and `::1`. Remote access requires `AGENTSCAN_UI_TOKEN` (or `create_app(token=...)`) and an admitted host.

A page bootstrap token is exchanged for a HttpOnly, SameSite=Strict session and a redirect to a URL without the token. API fetches/EventSource use the cookie. Mutating requests require an established session or valid Bearer credential; without a configured token, opening the local dashboard establishes a session. HTTPS sessions set Secure. Configure TLS and appropriate proxy Host handling for remote access.

`create_app(project_root=...)` selects the server-owned directory. Requests cannot change the remediation root. Static audits, AIBOM/dependency queries, explicit identity/RBAC path queries, and dashboard MCP audit calls are confined to it. An operator-supplied identity directory remains readable as the default identity source. Profiles create new JSON/YAML files under `.agentscan/profiles`; traversal, links, and overwrites are rejected. Dashboard and MCP scan routes reject URLs that launch local stdio commands.

One active scan is held in memory; overlaps return 409. Completed, inconclusive, and failed results preserve evaluated/selected counts and module outcomes. This is a local, single-process application, without durable multi-tenant state.

## Self-healing webhook and fix application

The webhook requires `AGENTSCAN_HEAL_TOKEN` and `AGENTSCAN_HEAL_ROOT`. Missing configuration returns 503; invalid Bearer authentication returns 401. Alerts cannot select another repository. Planning is the default; writing also requires `AGENTSCAN_HEAL_ALLOW_APPLY=1`. Patch output is contained and cannot overwrite an existing file.

The engine validates finding metadata paths before reading. FixPlan is bound to an operator-selected root in private, nonserialized state. Application preflights all preimages, stages replacements, preserves mode bits, and atomically replaces each file. Conflicts reject the plan before writes; replacement failures attempt rollback. Multiple actions on one file must form an exact before/after chain.

These checks address stale-file clobbering and tested path escapes. Multi-file application is not a database transaction: power loss, rollback errors, and hostile concurrent directory replacement remain limitations. Review generated diffs and validate behavior; syntactic validity is insufficient proof of correct remediation.

## Service API

The service API uses configured Ed25519 JWT keys, tenant-scoped authentication, admitted target hosts, dependency-aware readiness, and durable records. See [the API guide](api.md). Hostname admission is an application policy; enforce service egress independently, especially for private networks and DNS changes.

## Guard and sandbox layers

[Capability guards](GUARD.md) inspect normalized arguments and pin executables. Explicit scopes are required; they do not replace OS/network boundaries. [Sandbox selection](SANDBOX.md) fails closed when isolation is unavailable. Host subprocess execution requires opt-in and cannot promise network isolation.

## Cryptographic helpers

`agentscan.guard.crypto` implements AES-256-GCM-SIV encryption with a random 12-byte nonce, Argon2id derivation (64 MiB, three iterations, four lanes, 32-byte output), OS-backed tokens, and constant-time byte comparison. Helpers require compatible cryptography support. A primitive does not establish regulatory certification, deployment key custody, or protocol security.

Report signing requires an explicit or configured `AGENTSCAN_HMAC_KEY` of at least 32 bytes. The previous public default cannot provide authentic provenance. Keep report-signing credentials outside target-controlled data.

## Verification and reporting

Boundary regressions are in `tests/test_containment_security.py`, `tests/test_ui_lifecycle.py`, `tests/guard/`, `tests/sandbox/`, and `tests/test_remediation/`. Record actual deployment/browser/provider checks separately with the versions and fixtures exercised. Use the repository's configured private security channel for issues; never publish real credentials or confidential target data in reproductions.
