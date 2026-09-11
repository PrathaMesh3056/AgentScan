# agentscan/supply_chain/__init__.py
#
# AI Supply Chain Scanner (AICS) — Module 2A.
#
# dep_scanner makes live OSV.dev (api.osv.dev) HTTP calls for CVE lookups,
# with automatic fallback to the bundled known_vulnerabilities.yaml on failure.
# All other scanners (config, secrets, typosquat, MCP, identity) are static-only,
# driven from YAML files bundled with the package. Semgrep is an optional extra
# (`audit --scan-semgrep`) and is skipped when the binary is missing.
