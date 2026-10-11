# MCP compatibility

AgentScan supports MCP stdio, Streamable HTTP, and the older HTTP+SSE transport. Live connectors contact the explicitly selected server; the separate static audit reads configuration declarations without starting servers.

## Select a live endpoint

Use a target profile to keep sensitive baselines and credentials out of command history:

```yaml
url: mcp+sses://your-owned-server.example/mcp
analysis_mode: deterministic
data_classification: sensitive
exploit: false
deep: false
```

```powershell
uv run --no-sync python -m agentscan.cli scan --config target.yaml
```

Replace the example hostname with your authorized server. `mcp+sses://` selects HTTPS; `mcp+sse://` selects HTTP. Keep local HTTP endpoints on loopback. User information in the URL, fragments, control characters, backslashes, and invalid ports are rejected. Target authentication comes from the profile's `auth_header` or `extra_headers`; do not commit credential-bearing profiles.

For stdio, a URL such as `mcp://stdio?command=python&arg=-u&arg=owned_server.py` starts that command as a subprocess. Stdio selection is an operator action that executes the configured command with the scanner's environment. Static configuration auditing never takes this action.

## Supported transport behavior

| Transport | Implemented behavior | Boundaries |
|---|---|---|
| Stdio | Newline-delimited UTF-8 JSON-RPC, initialization, correlated replies, subprocess cleanup | Response/request sizes and RPC deadlines are bounded; stderr is drained without retaining target logs |
| Streamable HTTP | POST requests, JSON or SSE replies, initialized notification, negotiated protocol header, optional session header | Redirects and compressed responses are rejected; authentication stays on the selected endpoint |
| Interrupted HTTP SSE reply | Up to two GET resumptions using the last fully observed, safe event ID | GET uses the exact original endpoint, the original RPC deadline, and a shared response-byte budget; the original POST is never repeated |
| Legacy HTTP+SSE | Initial discovery, persistent GET reader, endpoint announcement, POST messages, correlated SSE `message` responses | Fallback occurs only when the first initialization POST returns 404 or 405; a single fixed POST endpoint must share the selected scheme, hostname, and effective port |
| Catalogs | Tool and advertised resource pagination | Repeated/invalid cursors, malformed responses, oversized catalogs, and more than 100 pages fail explicitly |
| Expired modern session | A session-bearing 404 triggers initialization of a fresh session | The failed tool request returns an error and is never replayed automatically |

The modern transport and resumable-event behavior follow the [MCP Streamable HTTP specification](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports). The old transport uses a GET event stream and an advertised POST endpoint, as described in the [2024-11-05 transport specification](https://modelcontextprotocol.io/specification/2024-11-05/basic/transports).

Legacy endpoint validation checks the raw path before URL resolution, then its decoded path and resolved origin. Traversal, ambiguous repeated escaping, encoded separators, credential-bearing URLs, and fragments fail before any authenticated POST to the advertised endpoint. The first completed event must announce the endpoint, and it cannot change during a session. Reader failure, cancellation, timeout, and context exit clear pending requests and close connections.

## Limits that affect a scan

The supported negotiated versions are `2024-11-05`, `2025-03-26`, and `2025-06-18`. This is a scanning client, with no sampling or elicitation capability advertised. It does not provide a general server-request handler, OAuth discovery/login, standalone notification subscription, or legacy stream reconnection. An unsupported server requirement produces an unavailable/error result rather than a successful assessment.

Each RPC uses the target timeout. The initial handshake also has a total timeout. Modern SSE event IDs must be visible ASCII and at most 256 characters; an empty ID clears the resumption cursor. LF, CRLF, and lone-CR framing work across chunks. Request/reply sizes use `max_response_bytes`; legacy persistent-stream bytes, including keepalives, share a session-wide limit. A long-running legacy scan can exhaust that limit and must report the failure.

Active probing selects the first available tool unless the caller supplies a tool name. Resource reads require an explicit resource request. Selecting a connector does not verify tool authorization, sandbox remote tools, or establish that a refusal proves security. Authentication failures, unusable catalogs, malformed replies, and exhausted bounds remain operational assessment failures.

## Static MCP configuration audit

```powershell
uv run --no-sync python -m agentscan.cli audit .\owned-project --scan-mcp --offline --output mcp-audit.json
```

The auditor accepts flat declarations and nested `mcpServers` objects in `*.mcp.json`, `mcp.json`, `mcp_config.json`, and `claude_desktop_config.json`. Nested entries must declare exactly one command or HTTP(S) URL. Supported fields include `args`, `env`, `headers`, `auth`, `tools`, and `scopes`, with structural validation. Files are limited to 1 MiB.

A local nested stdio declaration does not need HTTP authentication. For remote declarations, a nonempty authentication declaration or supported authentication header suppresses the missing-authentication declaration finding. This records declared intent only. It does not validate a credential, connect to the URL, inspect a launched server, or prove deployed enforcement. Dangerous tool/scope keywords describe declared capability risk.

Coverage counts **server declarations**, with a flat file counting as one. Valid siblings are retained when another declaration is malformed; missing, unsupported, or unparsable inputs make coverage incomplete. Findings include provenance with `runtime_permissions_verified: false`. Command arguments, environment values, and authentication-header values are not executed or included in findings.

## Verification evidence

The focused transport suite covers modern JSON/SSE correlation, bounded resumption and deadlines, invalid cursors, session expiry, legacy origin/traversal rejection, authentication preservation, cancellation, reader cleanup, and a real disposable loopback legacy server. These are local protocol fixtures, not proof of compatibility with every deployed MCP server. Run it with:

```powershell
uv run --no-sync python -m pytest tests/test_mcp_protocol.py tests/test_mcp_http_transports.py -q
```

Static declaration tests live under `tests/test_supply_chain/test_mcp_nested.py`, `test_mcp_auditor.py`, and `test_audit_coverage.py`.
