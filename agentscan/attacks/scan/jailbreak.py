"""ATK-002: persona probes assessed against a privately provisioned reference."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from agentscan.attacks.scan.known_reference_chat import KnownReferenceChatModule
from agentscan.core.client import AgentScanClient
from agentscan.core.evaluator import LLMJudge
from agentscan.core.models import Finding

PAYLOAD_FILE = Path(__file__).resolve().parent.parent / "payloads" / "jailbreak.yaml"


class JailbreakModule(KnownReferenceChatModule):
    """Observe complete known-reference disclosure under bounded persona probes.

    Public marker repetition and an inferred judge verdict cannot establish a
    safeguard failure. Negatives cover only complete supported text matches.
    """

    is_abstract = False
    attack_id = "ATK-002"
    attack_name = "Jailbreak & Persona Adoption"
    owasp_id = "LLM01"
    payload_file = PAYLOAD_FILE
    assessment_scope = "persona_complete_known_reference"
    criterion_version = "atk002-known-reference-2026-10-20"
    deterministic_evidence_method = "known_private_reference"

    default_remediation = (
        "Keep confidential records and credentials outside model-visible instructions. "
        "Preserve trusted message roles and treat persona, fiction, simulation and claimed "
        "administrator instructions as untrusted user input. Enforce access control, output "
        "contracts and tool permissions in application code; measure legitimate task utility "
        "alongside these probes. Refusal text and persona consistency alone do not enforce "
        "confidentiality or prove general resistance."
    )
    default_judge_remediation = default_remediation

    async def _test_variant(
        self,
        client: AgentScanClient,
        variant: dict[str, Any],
        judge: LLMJudge | None = None,
    ) -> Finding | None:
        finding = await super()._test_variant(client, variant, judge=None)
        if finding is None:
            return None
        return finding.model_copy(
            update={
                "description": (
                    f"The response to {variant['name']} disclosed a complete operator-known "
                    "confidential reference under a persona probe. This establishes observed "
                    "reference disclosure; general safeguard failure, causal persona adoption "
                    "and tool execution have not been independently verified."
                ),
                "metadata": {
                    **finding.metadata,
                    "attack_family": variant.get("family", "legacy_persona_framing"),
                    "persona_adoption_verified": False,
                    "authorization_bypass_verified": False,
                    "encoded_or_partial_extraction_assessed": False,
                },
            }
        )
