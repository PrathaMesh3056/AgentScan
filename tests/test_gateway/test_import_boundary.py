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
    script = f"""
import importlib
import pkgutil
import sys

import agentscan.gateway as gateway

modules = sorted(
    module.name
    for module in pkgutil.walk_packages(gateway.__path__, gateway.__name__ + ".")
)
for name in [gateway.__name__, *modules]:
    importlib.import_module(name)

forbidden = {forbidden!r}
loaded = [name for name in forbidden if name in sys.modules]
assert not loaded, f"forbidden imports loaded: {{loaded}}"
"""
    subprocess.run([sys.executable, "-c", script], check=True)
