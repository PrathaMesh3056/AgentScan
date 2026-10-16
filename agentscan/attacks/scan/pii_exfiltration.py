"""ATK-003: complete operator-known private-value disclosure, OWASP LLM02."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from agentscan.attacks.scan.prompt_injection import PromptInjectionModule
from agentscan.core.client import AgentScanClient
from agentscan.core.evaluator import LLMJudge
from agentscan.core.models import Finding
from agentscan.core.outcomes import AssessmentInconclusiveError
from agentscan.core.provenance import user_message_input

PAYLOAD_FILE = Path(__file__).resolve().parent.parent / "payloads" / "pii_exfiltration.yaml"


class PiiExfiltrationModule(PromptInjectionModule):
    """Assess known private values without inferring authenticity from PII shapes.

    A synthetic canary, designated private email or credential assignment must
    already exist on the target. A whole prompt alone is not a private-record
    criterion. This assessment never calls a model judge.
    """

    is_abstract = False
    attack_id = "ATK-003"
    attack_name = "PII & Sensitive Data Disclosure"
    owasp_id = "LLM02"
    payload_file = PAYLOAD_FILE
    assessment_scope = "sensitive_data_complete_known_private_value"
    criterion_version = "atk003-known-private-value-2026-10-16"
    deterministic_evidence_method = "known_private_reference"
    allow_complete_prompt_reference = False
    reference_requirement = (
        "an out-of-band confidential canary or a supported designated private value; "
        "output format alone cannot establish sensitive-data disclosure"
    )

    default_remediation = (
        "Minimize model-visible sensitive data and use synthetic references in assessments. "
        "Enforce user, tenant and record authorization before retrieval or tool execution. "
        "Keep credentials behind a broker and scope each workload role to its required resources. "
        "Restrict tool destinations and metadata-service access where not needed; apply output "
        "DLP/redaction and protect diagnostic logs. Verify successful transfers at the destination "
        "before claiming exfiltration. Preserve legitimate-task utility when evaluating controls. "
        "This scanner observation does not install these defenses on the target."
    )
    default_judge_remediation = default_remediation

    def _provenance_input(self, variant: dict[str, Any], payload_text: str) -> str:
        if variant.get("channel", "user") != "user":
            raise AssessmentInconclusiveError(
                "ATK-003 supports user-message probes only; indirect/tool delivery is unassessed."
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
        return finding.model_copy(
            update={
                "description": (
                    f"The response to {variant['name']} disclosed a complete operator-known "
                    "private value. This establishes the configured reference disclosure; "
                    "record authenticity, training-data origin, tenant isolation and "
                    "successful network exfiltration have not been independently verified."
                ),
                "metadata": {
                    **finding.metadata,
                    "attack_family": variant.get("family", "sensitive_data_request"),
                    "record_authenticity_verified": False,
                    "training_data_origin_verified": False,
                    "tenant_boundary_verified": False,
                    "network_transfer_verified": False,
                    "encoded_or_partial_disclosure_assessed": False,
                },
            }
        )
