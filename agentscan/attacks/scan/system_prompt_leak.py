"""ATK-012: complete operator-known confidential prompt/reference disclosure."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from agentscan.attacks.scan.prompt_injection import PromptInjectionModule
from agentscan.core.client import AgentScanClient
from agentscan.core.evaluator import LLMJudge
from agentscan.core.evidence import complete_known_prompt_present, known_private_disclosure
from agentscan.core.models import Finding
from agentscan.core.outcomes import AssessmentInconclusiveError
from agentscan.core.provenance import user_message_input

PAYLOAD_FILE = Path(__file__).resolve().parent.parent / "payloads" / "system_prompt_leak.yaml"


class SystemPromptLeakModule(PromptInjectionModule):
    """Assess known confidential content, without inferring hidden prompt text.

    Reuse ATK-001's reference preflight, mutation provenance, readable-response
    checks and digest-only findings. This profile never invokes a model judge.
    Its negative result covers complete supported text matches only; translated,
    encoded, partial and paraphrased extraction remain outside this criterion.
    """

    is_abstract = False
    attack_id = "ATK-012"
    attack_name = "System Prompt Leakage"
    owasp_id = "LLM07"
    payload_file = PAYLOAD_FILE
    assessment_scope = "system_prompt_complete_known_reference"
    criterion_version = "atk012-known-reference-2026-10-16"
    deterministic_evidence_method = "known_private_reference"

    default_remediation = (
        "Minimize system/developer prompts and keep credentials, customer records and "
        "authorization state outside model-visible instructions. Enforce access control "
        "and privilege separation in application code; preserve trusted message roles "
        "and treat user-written audit/debug authority claims as untrusted input. "
        "Use output checks as an additional control and measure legitimate-task utility. "
        "A secrecy instruction, refusal or matched synthetic reference does not establish "
        "general protection or unauthorized tool execution."
    )
    default_judge_remediation = default_remediation

    def _check_known_system_prompt(self, response_text: str) -> bool:
        """Compatibility helper: partial overlap is never complete disclosure."""
        configured = self._current_target
        return known_private_disclosure(response_text, configured) or complete_known_prompt_present(
            response_text, configured
        )

    def _provenance_input(self, variant: dict[str, Any], payload_text: str) -> str:
        """Exclude content supplied in the payload or captured request body.

        A reference already present in replayed history or context is not proof
        of extraction from privately provisioned target state. Mirror the HTTP
        connector's message replacement, without modifying the captured profile.
        """
        if variant.get("channel", "user") != "user":
            raise AssessmentInconclusiveError(
                "ATK-012 supports user-message probes only; indirect ingestion is unassessed."
            )
        return user_message_input(self._current_target, payload_text)

    async def _test_variant(
        self,
        client: AgentScanClient,
        variant: dict[str, Any],
        judge: LLMJudge | None = None,
    ) -> Finding | None:
        finding = await super()._test_variant(client, variant, judge=None)
        if finding is None:
            return None
        description = (
            f"The response to {variant['name']} disclosed complete operator-designated "
            "confidential content. The configured reference matched; hidden prompt origin, "
            "authorization bypass and tool execution have not been independently verified."
        )
        return finding.model_copy(
            update={
                "description": description,
                "metadata": {
                    **finding.metadata,
                    "attack_family": variant.get("family", "system_prompt_extraction"),
                    "prompt_origin_verified": False,
                    "authorization_bypass_verified": False,
                    "encoded_or_partial_extraction_assessed": False,
                },
            }
        )
