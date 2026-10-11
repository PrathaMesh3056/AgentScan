# agentscan/attacks/scan/dos.py
#
# ATK-004: Denial of Service / Resource Exhaustion — OWASP LLM10
#
# Probes the target for loop-inducing prompts, repetition bombs, and context-flood
# patterns that can exhaust compute, memory, or context windows.

from __future__ import annotations

from pathlib import Path
from typing import Any

from agentscan.attacks.scan.runner import YamlScanRunner
from agentscan.core.ai_client import AIClient  # noqa: F401 - preserved for test patch compatibility

PAYLOAD_FILE = Path(__file__).resolve().parent.parent / "payloads" / "dos.yaml"


class DosModule(YamlScanRunner):
    """
    Denial-of-service and resource exhaustion scanner.

    Sends loop-inducing, repetition-bomb, and context-flood payloads to detect
    agents that spin indefinitely, emit huge outputs, or stall on oversized input.
    """

    is_abstract = False
    attack_id = "ATK-004"
    attack_name = "Denial of Service / Resource Exhaustion"
    owasp_id = "LLM10"
    payload_file = PAYLOAD_FILE

    default_remediation = (
        "Enforce output token limits, request timeouts, repetition detection, "
        "and context-window guards on agent responses."
    )
    default_judge_remediation = default_remediation

    def build_finding_description(
        self, variant: dict[str, Any], detection_method: str, response_text: str
    ) -> str:
        return (
            f"Target exhibited resource-exhaustion behavior for {variant['name']}. "
            f"Detection method: {detection_method}."
        )

    def build_judge_description(
        self, variant: dict[str, Any], verdict_reason: str, response_text: str
    ) -> str:
        return (
            f"Target showed DoS/resource exhaustion for {variant['name']} "
            f"(detected by LLM-as-a-Judge). Judge reason: {verdict_reason}"
        )
