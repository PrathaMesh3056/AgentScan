"""ATK-004: bounded observations of resource pressure, without invented impact."""

from __future__ import annotations

import asyncio
import hashlib
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from agentscan.attacks.scan.runner import YamlScanRunner
from agentscan.core.ai_client import AIClient  # noqa: F401 - preserved for test patch compatibility
from agentscan.core.client import AgentScanClient
from agentscan.core.models import Finding, Severity, Target
from agentscan.core.outcomes import (
    AssessmentInconclusiveError,
    TargetRequestError,
    execution_ledger,
    record_evaluated_variant,
    record_execution_error,
    record_inconclusive,
    record_observation,
)
from agentscan.core.resource_witness import (
    active_resource_collector,
    resource_delivery,
)

PAYLOAD_FILE = Path(__file__).resolve().parent.parent / "payloads" / "dos.yaml"
_CRITERION = "atk004-bounded-resource-observation-2026-10-25"
_MAX_PROBES = 9
_MAX_PAYLOAD_BYTES = 8192
_MAX_RESPONSE_BYTES = 65536
_MAX_REQUEST_SECONDS = 10
_TEXT_KEYS = ("response", "text", "message", "output", "content", "raw")
_CHAT_SCHEMES = {"http", "https"}


class DosModule(YamlScanRunner):
    """Record bounded response behavior; independent resource evidence is required.

    Text length, repetition, echoed canaries, target-reported tool status and
    connector timeouts cannot establish service degradation, cost or exhaustion.
    The default profile never emits an impact finding or evaluated negative.
    """

    is_abstract = False
    attack_id = "ATK-004"
    attack_name = "Denial of Service / Resource Exhaustion"
    owasp_id = "LLM10"
    payload_file = PAYLOAD_FILE
    assessment_scope = "resource_pressure_response_inventory"

    default_remediation = (
        "Set input, output, time, cost, request and queue budgets at the application "
        "boundary. Monitor independent per-request resource and availability "
        "telemetry, and stop or reject excessive work while preserving benign service."
    )

    async def run(self, target: Target) -> list[Finding]:
        variants = self._load_payload_variants()
        collector = active_resource_collector()
        ledger = execution_ledger.get()
        if ledger is not None:
            ledger.assessment_scope = collector.scope if collector else self.assessment_scope
            ledger.selected = len(variants)
            ledger.evaluated = 0

        if len(variants) > _MAX_PROBES:
            record_inconclusive("ATK-004 probe count exceeds its fixed safety budget.")
            return []
        if (
            urlsplit(target.url).scheme not in _CHAT_SCHEMES
            or target.browser is not None
            or target.request_template is not None
        ):
            record_inconclusive(
                "ATK-004 bounded chat observations require a direct HTTP(S) endpoint."
            )
            return []

        # The caller's mutators, parallelism, retries and judge cannot add load.
        bounded_target = target.model_copy(
            update={
                "mutate": False,
                "judge_model": None,
                "attacker_model": None,
                "concurrency": 1,
                "retry_state_changing_requests": False,
                "timeout": min(target.timeout, _MAX_REQUEST_SECONDS),
                "max_response_bytes": min(target.max_response_bytes, _MAX_RESPONSE_BYTES),
                "max_redirects": 0,
            }
        )
        findings: list[Finding] = []
        try:
            async with AgentScanClient(bounded_target, record_exchange=False) as client:
                for variant in variants:
                    variant_id = variant.get("id", "?")
                    if variant.get("channel", "user") != "user":
                        record_inconclusive(
                            f"ATK-004 variant {variant_id}: unsupported delivery channel; remaining probes not run."
                        )
                        break
                    payload = self._build_payload(variant)
                    payload_bytes = payload.encode("utf-8", errors="strict")
                    if len(payload_bytes) > _MAX_PAYLOAD_BYTES:
                        record_inconclusive(
                            f"ATK-004 variant {variant_id}: input exceeds safety budget; remaining probes not run."
                        )
                        break
                    request_sha256 = hashlib.sha256(payload_bytes).hexdigest()
                    started = time.perf_counter()
                    with resource_delivery(str(variant_id), request_sha256) as delivery:
                        try:
                            response = await asyncio.wait_for(
                                client.send_message(payload), timeout=_MAX_REQUEST_SECONDS
                            )
                        except TimeoutError:
                            record_execution_error(
                                f"ATK-004 variant {variant_id}: request timed out; remaining probes not run."
                            )
                            break
                        except TargetRequestError:
                            record_execution_error(
                                f"ATK-004 variant {variant_id}: target request failed; remaining probes not run."
                            )
                            break
                        except Exception as error:
                            record_execution_error(
                                f"ATK-004 variant {variant_id}: request failed ({type(error).__name__}); remaining probes not run."
                            )
                            break
                        text = next(
                            (
                                response[key]
                                for key in _TEXT_KEYS
                                if isinstance(response.get(key), str)
                            ),
                            None,
                        )
                        response_bytes = (
                            text.encode("utf-8", errors="replace") if text is not None else b""
                        )
                        response_sha256 = hashlib.sha256(response_bytes).hexdigest()
                        witness = (
                            collector.consume(delivery, response_sha256)
                            if collector is not None and delivery is not None
                            else None
                        )
                    if text is None:
                        record_inconclusive(
                            f"ATK-004 variant {variant_id}: no readable response; remaining probes not run."
                        )
                        break
                    if len(response_bytes) > _MAX_RESPONSE_BYTES:
                        record_inconclusive(
                            f"ATK-004 variant {variant_id}: response observation exceeds safety budget; remaining probes not run."
                        )
                        break
                    observation = {
                        "variant_id": variant_id,
                        "criterion_version": _CRITERION,
                        "request_sha256": request_sha256,
                        "request_bytes": len(payload_bytes),
                        "response_sha256": response_sha256,
                        "response_bytes": len(response_bytes),
                        "elapsed_ms": round((time.perf_counter() - started) * 1000),
                        "evidence_source": "target_response_and_client_elapsed_time",
                        "resource_usage_verified": False,
                        "availability_impact_verified": False,
                        "cost_impact_verified": False,
                    }
                    if witness is not None and collector is not None:
                        observation.update(
                            assessment_scope=collector.scope,
                            criterion_version="atk004-owned-resource-witness-2026-10-25",
                            evidence_source="trusted_in_process_resource_and_neutral_admission",
                            trusted_work_units=witness.cumulative_work_units,
                            trusted_work_units_before=witness.work_units_before,
                            attributed_work_units=witness.attributed_work_units,
                            approved_work_budget=collector.work_budget,
                            neutral_before_admitted=witness.neutral_before_admitted,
                            neutral_after_admitted=witness.neutral_after_admitted,
                            independent_evidence_sha256=witness.evidence_sha256,
                            resource_usage_verified=True,
                            availability_impact_verified=(
                                witness.neutral_before_admitted
                                and not witness.neutral_after_admitted
                                and witness.attributed_work_units > 0
                                and witness.work_units_before <= collector.work_budget
                                and witness.cumulative_work_units > collector.work_budget
                            ),
                        )
                    record_observation(observation)
                    if witness is None or collector is None:
                        record_inconclusive(
                            f"ATK-004 variant {variant_id}: response observed; independent resource and availability evidence unavailable."
                        )
                        if collector is not None:
                            break
                        continue
                    if not witness.neutral_before_admitted:
                        record_inconclusive(
                            f"ATK-004 variant {variant_id}: neutral service was unavailable before delivery; remaining probes not run."
                        )
                        break
                    if not witness.neutral_after_admitted:
                        if (
                            witness.attributed_work_units > 0
                            and witness.work_units_before <= collector.work_budget
                            and witness.cumulative_work_units > collector.work_budget
                        ):
                            record_evaluated_variant()
                            findings.append(
                                self.make_finding(
                                    severity=Severity.HIGH,
                                    description=(
                                        "The owned application exceeded its approved cumulative work budget "
                                        "and a neutral request was denied after the correlated probe. "
                                        "This is local resource-lab evidence, not customer-target certification."
                                    ),
                                    evidence=(
                                        "Independent resource and neutral-admission evidence SHA-256: "
                                        f"{witness.evidence_sha256}"
                                    ),
                                    remediation=self.default_remediation,
                                    metadata=dict(observation),
                                )
                            )
                        else:
                            record_inconclusive(
                                f"ATK-004 variant {variant_id}: neutral service degraded without an exceeded work budget."
                            )
                        record_inconclusive(
                            f"ATK-004 variant {variant_id}: remaining probes not run after neutral-service degradation."
                        )
                        break
                    if witness.cumulative_work_units > collector.work_budget:
                        record_inconclusive(
                            f"ATK-004 variant {variant_id}: approved work budget exceeded; remaining probes not run."
                        )
                        break
                    record_evaluated_variant()
        except Exception as error:
            record_execution_error(f"ATK-004 connector failed ({type(error).__name__}).")
        return findings

    def _check_detection(
        self,
        method: str,
        response_text: str,
        target: str,
        response: dict[str, Any] | None = None,
    ) -> bool:
        raise AssessmentInconclusiveError(
            "ATK-004 cannot establish resource or availability impact from target response content."
        )
