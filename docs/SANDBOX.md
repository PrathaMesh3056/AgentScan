# AgentScan execution sandbox

`select_sandbox()` chooses an available isolation backend in the order gVisor, Docker, then Bubblewrap. When none is available, it raises `SandboxUnavailableError`. Explicitly requesting an unavailable or misspelled tier also raises; execution does not silently move to the host.

| Backend | Implemented controls | Limits |
|---|---|---|
| `gvisor` | Linux and detected runsc; Docker controls below plus `--runtime runsc` | Requires a working daemon/runtime configuration; detection alone is not proof of execution |
| `docker` | UID/GID 65534, 64-process limit, dropped capabilities, read-only root, no-new-privileges, 512 MiB memory, one CPU, tmpfs, optional network none | Daemon and image are trusted; default image tag is mutable |
| `bwrap` | Linux namespaces, cleared environment, selected runtime directories read-only, disposable workspace | User namespaces may be disabled; equivalent Docker CPU/memory/process ceilings are not implemented |
| `subprocess` | Explicit operator opt-in to host execution | Telemetry only; cannot enforce filesystem or network isolation |

Docker/gVisor and Bubblewrap copy the supplied workspace before execution. The original is not mounted writable. Copying rejects links and nonregular files, skips `.git`, `.venv`, `node_modules`, `__pycache__`, `.aws`, `.ssh`, `.env*`, `.pem`, and `.key` inputs, and is limited to 10,000 files / 128 MiB. Filename rules cannot discover every secret: prepare minimal inputs.

Mutation telemetry compares content hashes in the disposable copy and reports added (A), changed (C), or deleted (D) paths under `/workspace`. Docker layer changes are included. Copies are cleaned after execution; container removal has a deadline and reports failure. Execution and Docker lifecycle operations have timeouts. Stdout/stderr are currently buffered and are not a bounded output channel.

## Run an isolated verification

```python
from pathlib import Path
from agentscan.sandbox import select_sandbox

sandbox = select_sandbox("docker")
result = sandbox.execute_in_sandbox(
    command=["python", "-c", "from pathlib import Path; Path('receipt.txt').write_text('verified')"],
    host_workspace=Path("./verification-inputs").resolve(),
    network_disabled=True,
    timeout=10,
)
print(result.sandbox_tier, result.exit_code, result.filesystem_diff)
```

The directory must already exist. Start Docker Desktop on Windows/macOS or use an operator-managed daemon on Linux. Install/configure the desired backend outside AgentScan. Backend execution errors return an error result without executing the command on a weaker tier.

## Explicit host execution

```python
host_audit = select_sandbox("subprocess", allow_host_execution=True)
result = host_audit.execute_in_sandbox(
    ["trusted-program", "--inspect"],
    host_workspace=Path("./trusted-workspace").resolve(),
    network_disabled=False,
)
```

Use this only for trusted commands and inputs. Host mode rejects `network_disabled=True`: proxy environment variables cannot enforce network isolation. The host process receives a minimal environment and can access resources permitted to the current OS account. Its filesystem telemetry covers only the supplied workspace.

Regressions in `tests/sandbox/` and `tests/test_containment_security.py` verify fail-closed selection, command construction, disposable copies, and mutations. They do not establish backend equivalence, kernel escape resistance, or enforcement on hosts where a backend was not executed.
