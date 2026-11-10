from __future__ import annotations

import subprocess
import sys


def test_gateway_import_does_not_load_scanner_or_spike_modules() -> None:
    forbidden = (
        "agentscan.core",
        "agentscan.cli",
        "agentscan.action",
        "agentscan.reporting",
        "agentscan.mcp",
        "agentscan.guard",
    )
    script = (
        "import importlib, sys; importlib.import_module('agentscan.gateway'); "
        f"forbidden = {forbidden!r}; "
        "loaded = [name for name in forbidden if name in sys.modules]; "
        "assert not loaded, f'forbidden imports loaded: {loaded}'"
    )
    subprocess.run([sys.executable, "-c", script], check=True)
