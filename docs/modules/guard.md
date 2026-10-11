# Tool capability guard

The guard checks arguments at an integrated tool boundary before a protected
tool executes. Python decorators cover developer-owned tools; an MCP stdio proxy
can inspect tool-call arguments across language boundaries.

## Integrate the actual boundary

Configure the permitted filesystem root, binaries, domains and optional argument
schema for the intended tool. Wrap its real invocation path rather than only a
scan request. The [guard integration guide](../GUARD.md) provides setup and usage.
There is no standalone `agentscan guard` CLI command; starting a scan or dashboard
does not automatically protect remote agent tools.
The MCP helper validates requests; its caller must supply transport forwarding
and execute approved arguments under the same policy.

## Interpret policy decisions

Path checks resolve a requested path against its allowed root. Command checks
enforce an executable allowlist and avoid shell execution. Argument inspection
can validate schemas, nested values, paths and domains. A rejected call returns
a structured policy error so the caller can handle the denied action.

Treat a rejection as a denied tool operation, not proof that every surrounding
action was contained. Calls outside the integrated wrapper or proxy need their
own enforcement. Policies must match the tool's real semantics.

## Limits

Conservative command checks can reject valid literal shell characters. Filesystem
permissions and symlink behavior depend on the deployment host. Argument checks
do not replace operating-system isolation, authorization or protection against
filesystem changes between validation and use. Measure overhead on your workload
rather than assuming a universal latency or bypass guarantee.

See [sandbox boundaries](sandbox.md) for execution isolation.
