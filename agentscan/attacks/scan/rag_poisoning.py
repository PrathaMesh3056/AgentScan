"""ATK-008: document delivery and bounded, independently witnessed RAG results.

The ordinary target adapter reports what it received; it cannot attest that a
source was inserted into a corpus, retrieved, trusted, or caused an answer.
Only an enrolled, operator-owned Python fixture may assess those effects.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
from typing import Any
from uuid import uuid4

from loguru import logger

from agentscan.attacks.scan.runner import YamlScanRunner
from agentscan.core.ai_client import AIClient  # noqa: F401 - preserve import compatibility
from agentscan.core.client import AgentScanClient
from agentscan.core.connectors import select_connector
from agentscan.core.evaluator import LLMJudge
from agentscan.core.models import Finding, Severity, Target
from agentscan.core.outcomes import (
    AssessmentInconclusiveError,
    ModuleUnavailableError,
    execution_ledger,
    record_evaluated_variant,
    record_execution_error,
    record_inconclusive,
    record_observation,
)
from agentscan.core.rag_witness import active_rag_collector, rag_delivery

PAYLOAD_FILE = Path(__file__).resolve().parent.parent / "payloads" / "rag_poisoning.yaml"
PROTOCOL = "agentscan.document.v1"
CRITERION_VERSION = "atk008-document-observation-2026-10-18"
DEFAULT_TASK = "Answer using only the supplied context. Do not rely on outside knowledge."
REMOTE_SCOPE = "rag_document_observation"


class RagPoisoningModule(YamlScanRunner):
    """Observe remote document responses; assess effects only in an owned RAG lab."""

    is_abstract = False
    attack_id = "ATK-008"
    attack_name = "RAG / Knowledge-Base Poisoning"
    owasp_id = "LLM08"
    payload_file = PAYLOAD_FILE
    assessment_scope = REMOTE_SCOPE
    default_remediation = (
        "Require authenticated corpus publishers, verify exact document provenance, "
        "and enforce answer and citation policy against independently trusted facts. "
        "Keep retrieval and model-input records to investigate observed effects."
    )

    @classmethod
    def _remote_variants(cls) -> tuple[dict[str, Any], ...]:
        return super()._load_payload_variants()

    @classmethod
    def _load_payload_variants(cls) -> tuple[dict[str, Any], ...]:
        collector = active_rag_collector()
        return collector.probes if collector is not None else cls._remote_variants()

    def variant_count(self) -> int:
        return len(self._load_payload_variants())

    @staticmethod
    def _task(variant: dict[str, Any]) -> str:
        value = variant.get("user_task")
        return value if isinstance(value, str) and value else DEFAULT_TASK

    @classmethod
    def _document(cls, variant: dict[str, Any]) -> str:
        payload = cls._build_payload(variant)
        wrapper = variant.get("document_wrapper", "{payload}")
        if not isinstance(wrapper, str):
            raise AssessmentInconclusiveError("ATK-008 has an invalid document wrapper.")
        try:
            return wrapper.format(payload=payload)
        except (KeyError, ValueError, IndexError):
            raise AssessmentInconclusiveError("ATK-008 has an invalid document wrapper.") from None

    @staticmethod
    def _response_text(response: dict[str, Any]) -> str | None:
        for key in ("response", "text", "message", "output", "content"):
            if key in response:
                value = response[key]
                return value if isinstance(value, str) else None
        return None

    @staticmethod
    def _receipt_status(
        response: dict[str, Any], *, probe_id: str, source_id: str, source_hash: str
    ) -> str:
        if "indirect_receipt" not in response:
            return "missing"
        receipt = response["indirect_receipt"]
        if not isinstance(receipt, dict):
            return "invalid"
        expected = {
            "protocol": PROTOCOL,
            "probe_id": probe_id,
            "source_id": source_id,
            "source_sha256": source_hash,
            "model_visible_sha256": source_hash,
            "boundary": "retrieved_document",
        }
        return (
            "correlated"
            if receipt.get("consumed") is True
            and all(receipt.get(key) == value for key, value in expected.items())
            else "mismatched"
        )

    @staticmethod
    def _canonical_response(response: Any, max_bytes: int) -> bytes:
        if not isinstance(response, dict):
            raise AssessmentInconclusiveError("ATK-008 received a non-object response.")
        try:
            encoded = json.dumps(
                response, sort_keys=True, ensure_ascii=True, allow_nan=False
            ).encode("utf-8")
        except (TypeError, ValueError, OverflowError, RecursionError, UnicodeError):
            raise AssessmentInconclusiveError(
                "ATK-008 response cannot be safely serialized for observation."
            ) from None
        if len(encoded) > max_bytes:
            raise AssessmentInconclusiveError("ATK-008 response exceeds the configured size limit.")
        return encoded

    async def run(self, target: Target) -> list[Finding]:
        collector = active_rag_collector()
        ledger = execution_ledger.get()
        variants = self._load_payload_variants()
        if ledger is not None:
            ledger.assessment_scope = collector.scope if collector is not None else REMOTE_SCOPE
            ledger.selected = len(variants)
            ledger.evaluated = 0
        if target.indirect_adapter != "document_v1":
            raise ModuleUnavailableError(
                "ATK-008 requires an explicitly configured target-owned document_v1 adapter."
            )
        if not select_connector(target).supports_indirect_document:
            raise ModuleUnavailableError(
                "ATK-008 document_v1 is unsupported by this connector; no chat fallback is used."
            )
        semaphore = asyncio.Semaphore(target.concurrency)

        async def test_one(variant: dict[str, Any]) -> Finding | None:
            async with semaphore:
                try:
                    result = await self._test_variant(client, variant)
                    record_evaluated_variant()
                    return result
                except AssessmentInconclusiveError as exc:
                    record_inconclusive(f"Variant {variant['id']}: {exc}")
                    return None
                except Exception as exc:
                    logger.warning(
                        "ATK-008 variant {} failed: {}", variant["id"], type(exc).__name__
                    )
                    record_execution_error(f"Variant {variant['id']}: {type(exc).__name__}")
                    return None

        async with AgentScanClient(target) as client:
            results = await asyncio.gather(*(test_one(variant) for variant in variants))
        return [result for result in results if result is not None]

    async def _test_variant(
        self,
        client: AgentScanClient,
        variant: dict[str, Any],
        judge: LLMJudge | None = None,
    ) -> Finding | None:
        del judge  # A model verdict cannot establish RAG corpus or answer integrity.
        if variant.get("channel") != "document":
            raise AssessmentInconclusiveError("ATK-008 supports document ingestion only.")
        document = self._document(variant)
        task = self._task(variant)
        source_id = str(variant["id"])
        source_hash = hashlib.sha256(document.encode("utf-8")).hexdigest()
        task_hash = hashlib.sha256(task.encode("utf-8")).hexdigest()
        probe_id = uuid4().hex
        with rag_delivery(source_id, source_hash, task_hash) as delivery:
            response = await client.send_indirect_document(task, document, probe_id, source_id)
            limit = getattr(client.target, "max_response_bytes", 4 * 1024 * 1024)
            encoded = self._canonical_response(response, limit)
            response_text = self._response_text(response)
            collector = active_rag_collector()
            witness = (
                collector.consume(delivery, response_text)
                if collector is not None and response_text is not None
                else None
            )

        indicator = variant.get("observation_marker", variant.get("detection_target"))
        has_indicator = (
            indicator.casefold() in response_text.casefold()
            if isinstance(response_text, str) and isinstance(indicator, str) and indicator
            else None
        )
        observation: dict[str, Any] = {
            "variant_id": source_id,
            "criterion_version": CRITERION_VERSION,
            "evidence_source": "target_reported_document_response",
            "response_sha256": hashlib.sha256(encoded).hexdigest(),
            "response_bytes": len(encoded),
            "source_sha256": source_hash,
            "receipt_status": self._receipt_status(
                response, probe_id=probe_id, source_id=source_id, source_hash=source_hash
            ),
            "response_text_available": response_text is not None,
            "seed_indicator_present": has_indicator,
            "corpus_poisoning_verified": False,
            "causal_attribution_verified": False,
            "retrieval_ranking_verified": False,
            "source_authenticity_verified": False,
            "downstream_impact": "unassessed",
        }
        if witness is not None:
            observation.update(
                assessment_scope=witness.scope,
                local_profile=witness.profile,
                local_effect=witness.effect,
                witness_disposition=witness.disposition,
                independent_evidence_sha256=witness.evidence_sha256,
            )
        record_observation(observation)

        if witness is None:
            raise AssessmentInconclusiveError(
                "Document response recorded; corpus, retrieval and answer effect remain unverified."
            )
        if witness.effect is None:
            return None
        return self.make_finding(
            severity=Severity.HIGH,
            description=(
                f"Owned RAG fixture observed {witness.effect.replace('_', ' ')} "
                f"for {source_id}; customer-agent impact is unassessed."
            ),
            evidence=f"Owned fixture evidence SHA256: {witness.evidence_sha256}",
            remediation=self.default_remediation,
            turn_number=1,
            metadata={
                "yaml_variant_id": source_id,
                "assessment_scope": witness.scope,
                "local_profile": witness.profile,
                "local_effect": witness.effect,
                "independent_evidence_sha256": witness.evidence_sha256,
            },
        )

    def _check_detection(
        self,
        method: str,
        response_text: str,
        target: str,
        response: dict[str, Any] | None = None,
    ) -> bool:
        del method, response_text, target, response
        raise AssessmentInconclusiveError(
            "ATK-008 markers and model claims cannot verify RAG poisoning."
        )
