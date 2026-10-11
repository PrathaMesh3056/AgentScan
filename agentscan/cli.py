# agentscan/cli.py
#
# CLI entry point for AgentScan.
#
# This file is the public entry point referenced in pyproject.toml:
#   agentscan = "agentscan.cli:app"
#
# It delegates all command logic to the agentscan._cli package (agentscan/_cli/).
# Do NOT add command logic here — add it to the appropriate submodule under
# agentscan/_cli/commands/.
#
# Commands (grouped by module):
#   scan.py      — agentscan scan
#   audit.py     — agentscan audit
#   heal.py      — agentscan heal, agentscan heal-server
#   swarm.py     — agentscan swarm
#   misc.py      — agentscan calibrate, init, benchmark, verify-claims, ui,
#                  fix, list-attacks, watch, export-guardrails, mcp-serve,
#                  compliance, verify, api serve, api worker
#
# The import of agentscan._cli (the package) triggers all @app.command()
# decorators to fire, registering every command onto the shared `app` object.

from __future__ import annotations

# Provider keys are read lazily by the selected external analysis adapter.
# Importing this entry point must not promote .env secrets into the environment
# of deterministic/local commands or API/worker deployments.
# Re-export the Typer app from the internal CLI package.
# Importing the package causes all command modules to register themselves.
from agentscan._cli import api_app, app, console  # noqa: F401, E402

# ── Backwards-compatible re-exports ──────────────────────────────────────────
# Tests and other code import these directly from agentscan.cli, so we keep
# them available here.
from agentscan._cli._shared import (  # noqa: E402, F401
    _SEVERITY_COLOURS,
    _SEVERITY_ORDER,
    _confirm_exploit_mode,
    _fail_on_should_exit,
    _format_ssp_class,
    write_report,
)

# Tests patch "agentscan.cli.run_scan_multi" — must stay importable from here.
from agentscan.core.runner import run_scan_multi  # noqa: E402, F401

if __name__ == "__main__":
    app()
