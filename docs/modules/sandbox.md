# Execution sandbox

AgentScan's sandbox integration runs supported local verification tasks and
records execution observations. It does not sandbox a remote agent simply
because you scan its endpoint.

## Choose an available execution tier

The selector checks supported isolated engines in this order: gVisor, Docker and
Bubblewrap. The chosen tier is reported. An explicitly requested unavailable
tier fails instead of silently substituting another mode.

Docker needs a running engine and CLI; gVisor needs the configured `runsc`
runtime; Bubblewrap needs a supported Linux environment. The
[sandbox guide](../SANDBOX.md) documents configuration and integration. There is
no standalone `agentscan sandbox` CLI command.

Host subprocess audit execution requires explicit opt-in. It provides observation
without kernel isolation, and is not an equivalent fallback for running untrusted
code. Host mode rejects `network_disabled=True`: proxy environment settings cannot
enforce network isolation.

## Read the execution evidence

Results report the selected tier, exit code, stdout/stderr, elapsed time,
out-of-memory status and observed filesystem differences. Container settings can
include a read-only root filesystem, dropped capabilities, resource limits and
disabled networking. Verify that the chosen engine enforces the intended settings
on the actual host.

These observations support claims about the bounded execution that occurred.
They do not establish universal containment or an agent's overall security.
Use disposable workspaces and review outputs before reusing them.
