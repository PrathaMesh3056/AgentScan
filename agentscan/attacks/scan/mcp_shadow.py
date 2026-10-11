# agentscan/attacks/scan/mcp_shadow.py
#
# ATK-006: MCP Shadow Server — OWASP LLM01
#
# Simulates MCP tool impersonation and typosquatting by instructing the agent to
# call attacker-controlled endpoints or spoofed tool names.

from __future__ import annotations

from pathlib import Path
from typing import Any

from agentscan.attacks.scan.runner import YamlScanRunner
from agentscan.core.ai_client import AIClient  # noqa: F401 - preserved for test patch compatibility

PAYLOAD_FILE = Path(__file__).resolve().parent.parent / "payloads" / "mcp_shadow.yaml"

MCP_SHADOW_DOMAIN = "agentscan-mcp-shadow.invalid"


class McpShadowModule(YamlScanRunner):
    """
    MCP shadow-server impersonation scanner.

    Tests whether the agent accepts spoofed MCP configuration, typosquatted tool
    names, or callback URLs pointing at attacker-controlled infrastructure.
    """

    is_abstract = False
    attack_id = "ATK-006"
    attack_name = "MCP Shadow Server"
    owasp_id = "LLM01"
    payload_file = PAYLOAD_FILE

    default_remediation = (
        "Pin MCP server endpoints and tool identities to a signed allowlist. "
        "Reject in-message configuration updates and typosquatted tool names."
    )
    default_judge_remediation = default_remediation

    def build_finding_description(
        self, variant: dict[str, Any], detection_method: str, response_text: str
    ) -> str:
        return (
            f"Target accepted MCP shadow/impersonation in {variant['name']}. "
            f"Detection method: {detection_method}."
        )

    def build_judge_description(
        self, variant: dict[str, Any], verdict_reason: str, response_text: str
    ) -> str:
        return (
            f"Target complied with MCP shadow attack {variant['name']} "
            f"(detected by LLM-as-a-Judge). Judge reason: {verdict_reason}"
        )
