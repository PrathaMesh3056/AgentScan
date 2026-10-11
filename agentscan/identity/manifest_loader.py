# agentscan/identity/manifest_loader.py
#
# Parses agent manifest files on disk into AgentIdentity objects.
#
# IDE context rule #11: this module is SYNC, not async, and does not
# inherit AttackModule. It reads local files — same pattern as
# supply_chain/dep_scanner.py, not the live-target attack pattern.
#
# ── Supported format (v0.1): AgentScan manifest JSON ────────────────────────
# Any file matching *.agent.json anywhere under the audited path is parsed.
# Shape:
#
#   {
#     "agent_id": "support_agent",
#     "declared_role": "customer_support_agent",
#     "credential_ref": "OPENAI_KEY_PROD",
#     "tools": [
#       {"tool_name": "send_email",
#        "capability_scopes": ["send_email"],
#        "source": "mcp_config"}
#     ]
#   }
#
# "declared_role" and "credential_ref" are optional keys. If absent, they
# stay None on the resulting AgentIdentity — see rule #12, never guessed.
#
# LangChain agent-definition parsing (reading a live AgentExecutor's tool
# list instead of a static manifest) is a planned follow-up, not built yet.
# This loader only understands the AgentScan manifest JSON format above.

from __future__ import annotations

import json
from pathlib import Path

from loguru import logger

from agentscan.identity.models import AgentIdentity, ToolPermission
from agentscan.supply_chain.coverage import collect_inputs, record_coverage

MANIFEST_SUFFIX = ".agent.json"


def load_manifests(path: str | Path, *, coverage: list[dict] | None = None) -> list[AgentIdentity]:
    """
    Walk `path` recursively, parse every *.agent.json file found into an
    AgentIdentity. Files that fail to parse are logged and skipped —
    one broken manifest never aborts the whole audit.

    Returns an empty list if the path has no manifest files. Raises
    FileNotFoundError only if `path` itself does not exist.
    """
    root = Path(path)
    if not root.exists():
        raise FileNotFoundError(f"Audit path does not exist: {root}")

    identities: list[AgentIdentity] = []
    issues: list[str] = []
    manifest_files = collect_inputs(
        root,
        f"*{MANIFEST_SUFFIX}",
        issues,
        ignored_dirs={".git", ".venv", "venv", "node_modules", "__pycache__"},
    )
    seen_ids: set[str] = set()

    if not manifest_files:
        logger.warning(f"No *{MANIFEST_SUFFIX} manifest files found under {root}")

    for manifest_file in manifest_files:
        try:
            identity = _parse_manifest_file(manifest_file)
            if identity.agent_id in seen_ids:
                raise ValueError("Duplicate agent identifier")
            identities.append(identity)
            seen_ids.add(identity.agent_id)
        except Exception as e:
            issues.append(f"{manifest_file.name}: {type(e).__name__}; manifest was not assessed.")
            logger.error(f"Failed to parse manifest {manifest_file}: {type(e).__name__}")

    record_coverage(
        coverage,
        "identity",
        len(identities),
        source="agent_manifest_declarations",
        issues=issues,
        selected=len(manifest_files),
    )
    if coverage is not None:
        coverage[-1]["runtime_permissions_verified"] = False
        coverage[-1]["scope"] = (
            "AgentScan .agent.json declarations only; deployed entitlements are not verified."
        )
    return identities


def _parse_manifest_file(manifest_file: Path) -> AgentIdentity:
    """Parse a single *.agent.json file into an AgentIdentity."""
    raw = manifest_file.read_text(encoding="utf-8")
    data = json.loads(raw)

    if not isinstance(data, dict) or not isinstance(data.get("tools", []), list):
        raise ValueError("Unsupported agent manifest structure")
    if any(not isinstance(tool, dict) for tool in data.get("tools", [])):
        raise ValueError("Manifest tools must be objects")
    agent_id = data.get("agent_id")
    if not isinstance(agent_id, str) or not agent_id.strip():
        raise ValueError(f"Manifest missing required 'agent_id': {manifest_file}")

    tools = [
        ToolPermission(
            tool_name=t["tool_name"],
            capability_scopes=t.get("capability_scopes", []),
            source=t.get("source", "custom_manifest"),
        )
        for t in data.get("tools", [])
    ]

    return AgentIdentity(
        agent_id=agent_id,
        declared_role=data.get("declared_role"),  # None if absent — never guessed
        tools=tools,
        credential_ref=data.get("credential_ref"),  # None if absent — never guessed
        calls_agents=data.get("calls_agents") or [],
        manifest_path=str(manifest_file),
    )
