"""ATK-027: model/IP request probes with a known private-reference criterion."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from agentscan.attacks.scan.known_reference_chat import KnownReferenceChatModule
from agentscan.core.client import AgentScanClient
from agentscan.core.evaluator import LLMJudge
from agentscan.core.models import Finding, ScanMode

PAYLOAD_FILE = Path(__file__).resolve().parent.parent / "payloads" / "model_theft.yaml"


class ModelTheftModule(KnownReferenceChatModule):
    """Assess complete reference disclosure without inferring model extraction.

    A synthetic canary must already be private on the owned target. Architecture
    descriptions, claimed training examples and weight paths cannot prove that
    parameters, proprietary data or capabilities were recovered.
    """

    attack_id = "ATK-027"
    is_abstract = False
    attack_name = "Model/IP Requests: Known-Reference Disclosure"
    owasp_id = "LLM02"
    supported_modes = [ScanMode.SCAN, ScanMode.EXPLOIT]

    payload_file = PAYLOAD_FILE
    assessment_scope = "model_ip_complete_known_reference"
    criterion_version = "atk027-private-reference-2026-10-26"
    allow_complete_prompt_reference = False
    reference_requirement = (
        "an out-of-band synthetic confidential canary_token of 16–128 letters, numbers, "
        "underscores or hyphens; model descriptions and a system-prompt baseline alone "
        "cannot establish model/IP disclosure"
    )

    default_remediation = (
        "Keep model artifacts, training records, credentials and private reasoning outside "
        "ordinary chat context. Authorize artifact retrieval and storage access in application "
        "code, use least privilege and avoid exposing sensitive debugging or log-probability "
        "interfaces. Enforce request/cost quotas and monitor account-level extraction patterns. "
        "Protect confidential outputs with application controls and measure benign-task utility. "
        "This reference-disclosure observation does not verify parameter recovery, model "
        "replication, training-data origin, transfer or the effectiveness of these defenses."
    )
    default_judge_remediation = default_remediation

    def _private_reference_values(self) -> tuple[str, ...]:
        token = self._current_target.canary_token if self._current_target is not None else None
        return (
            (token,)
            if isinstance(token, str) and re.fullmatch(r"[A-Za-z0-9_-]{16,128}", token)
            else ()
        )

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
                    f"The response to {variant['name']} disclosed the complete operator-known "
                    "confidential synthetic reference under a model/IP request probe. "
                    "This establishes reference disclosure only; actual model theft, weight "
                    "extraction, training-data origin and network transfer are unassessed."
                ),
                "metadata": {
                    **finding.metadata,
                    "model_theft_verified": False,
                    "weight_extraction_verified": False,
                    "architecture_authenticity_verified": False,
                    "training_data_origin_verified": False,
                    "reasoning_origin_verified": False,
                    "network_transfer_verified": False,
                    "encoded_or_partial_extraction_assessed": False,
                },
            }
        )
