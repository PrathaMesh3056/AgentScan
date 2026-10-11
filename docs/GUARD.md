# AgentScan capability guards

The guard package validates arguments passed to a protected Python function. It is an in-process policy layer. The tool and its downstream filesystem/network clients must enforce the same policy where they perform operations.

## Protect a tool with an explicit scope

```python
from pathlib import Path
from pydantic import BaseModel
from agentscan.guard.firewall import CapabilityGuard

workspace = Path("./workspace").resolve()  # must already exist
guard = CapabilityGuard(allowed_root=workspace, allowed_domains=[])

class ReadArgs(BaseModel):
    file_path: str

@guard.protect_tool(schema_model=ReadArgs)
def read_document(file_path: str) -> str:
    return Path(file_path).read_text(encoding="utf-8")

document = read_document("notes.txt")
blocked = read_document("../private.txt")  # structured JSON policy error
```

Pydantic normalization is applied before invocation. Nested dictionaries, lists, tuples, and Pydantic models are inspected; cycles, more than 32 nesting levels, and more than 10,000 argument nodes are rejected. Recognized path arguments become contained absolute paths before execution.

`allowed_domains=None` means no domain policy. An explicit empty list denies recognized network endpoints. Nonempty lists permit exact hostnames, with case and terminal dots normalized. A configured domain policy rejects URLs with user information or unsupported schemes.

Path and network detection uses argument names and string prefixes. Opaque objects, unrecognized fields, URLs assembled inside the tool, redirects, DNS changes, and child-process network calls require additional enforcement. A decorator does not intercept arbitrary sockets or guarantee containment against a concurrently hostile local process.

The module-level `@protect_tool` has no configured root or domain scope. Use a `CapabilityGuard` instance for those policies. Its decorator accepts `schema_model`; it does not accept `allowed_root`, `path_param_name`, `allowed_binaries`, or `url_param_name`.

## Execute a permitted command

```python
from agentscan.guard.command import PosixCommandGuard

commands = PosixCommandGuard(["git"])
result = commands.sanitize_and_execute("git status", cwd=workspace, timeout=10)
```

Configured executables are resolved when the guard is constructed. String parsing and direct `execute(argv)` calls both revalidate identity; `/attacker/bin/git` cannot pass by matching the basename. Execution uses the trusted absolute executable and `shell=False`. Shell metacharacters in the command or arguments are rejected.

Allowlisting does not make every operation of an executable safe. Define tool-specific argument contracts and working-directory permissions. General-purpose interpreters and dangerous options need their own policy. Administrator configuration and the initially resolved executable must remain trusted.

## Validate an MCP request

```python
import json
from agentscan.guard.mcp_proxy import MCPCapabilityProxy

proxy = MCPCapabilityProxy(
    workspace_root=workspace,
    allowed_binaries=["git"],
    allowed_domains=["api.example.com"],
)
request = json.dumps({
    "jsonrpc": "2.0", "id": 1, "method": "tools/call",
    "params": {"name": "fetch", "arguments": {"url": "https://api.example.com/data"}},
})
error = proxy.process_request(request)
if error is not None:
    print(error)  # MCP result with isError=True
```

This is a request-validation helper. The caller supplies transport forwarding and must execute approved arguments under the same policy. There is no `start()` method or `server_command` constructor argument. Non-tool methods and malformed JSON are left to transport protocol validation. Nested domain policy is enforced for tool calls; command-like fields require a configured binary policy.

Focused regressions live in `tests/guard/` and `tests/test_containment_security.py`. [Sandbox execution](SANDBOX.md) supplies a separate execution boundary.
