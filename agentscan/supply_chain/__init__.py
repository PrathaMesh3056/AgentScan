# agentscan/supply_chain/__init__.py
#
# AI Supply Chain Scanner (AICS) — Module 2A & Framework-Native Security.
#
# dep_scanner makes live OSV.dev (api.osv.dev) HTTP calls for CVE lookups,
# with automatic fallback to the bundled known_vulnerabilities.yaml on failure.
# All other scanners (config, secrets, typosquat, MCP, identity, frameworks) are static-only,
# driven from AST and YAML files bundled with the package. Semgrep is an optional extra
# (`audit --scan-semgrep`) and is skipped when the binary is missing.

from agentscan.supply_chain.framework_auditor import scan_frameworks
from agentscan.supply_chain.native_semgrep import scan_native_rules
from agentscan.supply_chain.semgrep_auditor import scan_semgrep

__all__ = ["scan_frameworks", "scan_semgrep", "scan_native_rules"]
