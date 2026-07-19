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

MANIFEST_SUFFIX = ".agent.json"


def load_manifests(path: str | Path) -> list[AgentIdentity]:
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
    manifest_files = sorted(root.rglob(f"*{MANIFEST_SUFFIX}"))

    if not manifest_files:
        logger.warning(f"No *{MANIFEST_SUFFIX} manifest files found under {root}")

    for manifest_file in manifest_files:
        try:
            identity = _parse_manifest_file(manifest_file)
            identities.append(identity)
        except Exception as e:
            logger.error(f"Failed to parse manifest {manifest_file}: {e}")

    return identities


def _parse_manifest_file(manifest_file: Path) -> AgentIdentity:
    """Parse a single *.agent.json file into an AgentIdentity."""
    raw = manifest_file.read_text(encoding="utf-8")
    data = json.loads(raw)

    agent_id = data.get("agent_id")
    if not agent_id:
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
        manifest_path=str(manifest_file),
    )
