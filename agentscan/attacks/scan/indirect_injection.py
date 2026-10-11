"""ATK-005: known-reference disclosure with target-reported document ingestion."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any
from uuid import uuid4

from agentscan.attacks.scan.prompt_injection import PromptInjectionModule
from agentscan.core.client import AgentScanClient
from agentscan.core.connectors import select_connector
from agentscan.core.evaluator import LLMJudge
from agentscan.core.models import Finding, Target
from agentscan.core.outcomes import AssessmentInconclusiveError, ModuleUnavailableError

PAYLOAD_FILE = Path(__file__).resolve().parent.parent / "payloads" / "indirect_document.yaml"
PROTOCOL = "agentscan.document.v1"


class IndirectInjectionModule(PromptInjectionModule):
    """Document-only, opt-in capability; receipts never come from model assertions."""

    is_abstract = False
    attack_id = "ATK-005"
    attack_name = "Indirect Document Injection: Known-Reference Disclosure"
    owasp_id = "LLM01"
    payload_file = PAYLOAD_FILE
    assessment_scope = "indirect_document_target_receipt"
    criterion_version = "atk005-document-reference-2026-10-11"
    default_remediation = (
        "Keep retrieved data below trusted instructions and keep real secrets outside prompts. "
        "Instrument the actual document ingestion/model-input boundary. Validate authorization, "
        "output contracts, tool arguments and destinations in application code. Use least privilege "
        "and compare benign retrieval utility with adversarial tests. A receipt or refusal alone "
        "does not prove general safety or independently verified causal attribution."
    )
    default_judge_remediation = default_remediation

    async def run(self, target: Target) -> list[Finding]:
        if target.indirect_adapter != "document_v1":
            raise ModuleUnavailableError(
                "ATK-005 needs an explicitly configured target-owned document_v1 adapter. "
                "Ordinary chat cannot establish document ingestion; see docs/modules/indirect_injection.md."
            )
        if not select_connector(target).supports_indirect_document:
            raise ModuleUnavailableError(
                "ATK-005 document_v1 is unsupported by this connector; no chat fallback is used."
            )
        self._receipts: dict[str, dict[str, Any]] = {}
        return await super().run(target)

    async def _deliver_variant(
        self, client: AgentScanClient, variant: dict[str, Any], payload_text: str | None = None
    ) -> dict[str, Any]:
        if variant.get("channel") != "document":
            raise AssessmentInconclusiveError(
                "ATK-005 currently supports document ingestion only; tool/unknown channels are unassessed."
            )
        document = payload_text if payload_text is not None else self._build_payload(variant)
        task = str(variant.get("user_task") or "Answer using the retrieved document.")
        self._reference_match("", task + "\n" + document)
        probe_id = uuid4().hex
        source_id = str(variant["id"])
        source_hash = hashlib.sha256(document.encode("utf-8")).hexdigest()
        response = await client.send_indirect_document(task, document, probe_id, source_id)
        receipt = response.get("indirect_receipt")
        expected = {
            "protocol": PROTOCOL,
            "probe_id": probe_id,
            "source_id": source_id,
            "source_sha256": source_hash,
            "model_visible_sha256": source_hash,
            "boundary": "retrieved_document",
        }
        if (
            not isinstance(receipt, dict)
            or receipt.get("consumed") is not True
            or any(receipt.get(key) != value for key, value in expected.items())
        ):
            raise AssessmentInconclusiveError(
                "ATK-005 lacks a correlated document consumption receipt with the exact "
                "model-visible content digest. Upload acknowledgement, altered/removed content "
                "and model-generated assertions do not establish this ingestion criterion."
            )
        self._receipts[source_id] = expected
        return response

    async def _test_variant(
        self, client: AgentScanClient, variant: dict[str, Any], judge: LLMJudge | None = None
    ) -> Finding | None:
        finding = await super()._test_variant(client, variant, judge=None)
        if finding is not None:
            description = (
                f"A complete operator-known confidential reference was observed during "
                f"{variant['name']}. Document ingestion is target-reported and correlated "
                "to this probe; this does not independently establish causality or tool execution."
            )
            finding = finding.model_copy(
                update={
                    "description": description,
                    "metadata": {
                        **finding.metadata,
                        **self._receipts[str(variant["id"])],
                        "ingestion_evidence": "target_reported_correlated",
                        "causal_attribution_verified": False,
                        "tool_execution_verified": False,
                    },
                }
            )
        return finding
