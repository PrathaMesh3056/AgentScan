"""ATK-009: bounded response inventory and approved exact-answer policy checks."""

from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from pydantic import ValidationError

from agentscan.attacks.scan.runner import YamlScanRunner
from agentscan.core.ai_client import AIClient  # noqa: F401 - import compatibility
from agentscan.core.client import AgentScanClient
from agentscan.core.evaluator import LLMJudge
from agentscan.core.factuality import (
    FACTUALITY_CRITERION,
    FactualityCase,
    evaluate_factuality_response,
    factuality_baseline_digest,
    factuality_requests,
    response_fingerprint,
    response_text,
)
from agentscan.core.models import Finding, Severity, Target
from agentscan.core.outcomes import (
    AssessmentInconclusiveError,
    ModuleUnavailableError,
    TargetRequestError,
    execution_ledger,
    record_evaluated_variant,
    record_execution_error,
    record_inconclusive,
    record_observation,
)

PAYLOAD_FILE = Path(__file__).resolve().parent.parent / "payloads" / "overreliance.yaml"
INVENTORY_SCOPE = "overreliance_response_inventory"
POLICY_SCOPE = "factuality_policy"
INVENTORY_CRITERION = "atk009-response-inventory-v1"


class OverrelianceModule(YamlScanRunner):
    """Never infer verified facts, tool execution or causation from target claims."""

    is_abstract = False
    attack_id = "ATK-009"
    attack_name = "Overreliance / Hallucination"
    owasp_id = "LLM09"
    payload_file = PAYLOAD_FILE
    assessment_scope = INVENTORY_SCOPE
    default_remediation = (
        "Authenticate authoritative facts independently of user assertions. Verify answers "
        "against approved sources, support explicit abstention, and test ordinary answer utility. "
        "Require separate authorization and execution evidence for consequential actions."
    )

    async def run(self, target: Target) -> list[Finding]:
        # Revalidate direct callers and mutated Target instances before connection.
        try:
            target = Target.model_validate(target.model_dump(warnings=False))
        except (ValidationError, ValueError, TypeError):
            raise ModuleUnavailableError("ATK-009 target configuration is invalid.") from None
        if urlsplit(target.url).scheme not in {"http", "https"}:
            raise ModuleUnavailableError("ATK-009 supports direct HTTP(S) user messages only.")
        baseline = target.factuality_baseline
        ledger = execution_ledger.get()
        if ledger is not None:
            ledger.assessment_scope = POLICY_SCOPE if baseline else INVENTORY_SCOPE
            ledger.selected = 2 * len(baseline.cases) if baseline else self.variant_count()
            ledger.evaluated = 0
        tasks: list[tuple[str, Any, str, str]] = []
        if baseline is not None:
            baseline_digest = factuality_baseline_digest(baseline)
            for case in baseline.cases:
                for arm, message in factuality_requests(case):
                    tasks.append((case.id, case, arm, message))
        else:
            baseline_digest = ""
            for variant in self._load_payload_variants():
                tasks.append(
                    (str(variant["id"]), variant, "inventory", self._build_payload(variant))
                )
        semaphore = asyncio.Semaphore(target.concurrency)
        attempts = 0

        async def test_one(item: tuple[str, Any, str, str]) -> Finding | None:
            nonlocal attempts
            probe_id, specification, arm, message = item
            async with semaphore:
                try:
                    # Direct module callers may not have the core ScanContext.
                    # Preserve a target-owned cap as well as the shared client budget.
                    if target.request_budget is not None and attempts >= target.request_budget:
                        raise TargetRequestError("Target request budget exhausted.")
                    attempts += 1
                    response = await client.send_message(message)
                    if baseline is not None:
                        result = self._assess_policy(
                            specification,
                            arm,
                            message,
                            response,
                            baseline_digest,
                            target.max_response_bytes,
                        )
                        record_evaluated_variant()
                        return result
                    self._observe_inventory(
                        specification, message, response, target.max_response_bytes
                    )
                    raise AssessmentInconclusiveError(
                        "Response recorded; factual correctness and tool execution remain unverified."
                    )
                except AssessmentInconclusiveError as exc:
                    record_inconclusive(f"Probe {probe_id}/{arm}: {exc}")
                except Exception as exc:
                    # Exceptions may embed credentials, prompts or responses.
                    record_execution_error(f"Probe {probe_id}/{arm}: {type(exc).__name__}")
                return None

        results: list[Finding | None] | None = None
        try:
            async with AgentScanClient(target) as client:
                results = await asyncio.gather(*(test_one(item) for item in tasks))
        except Exception as exc:
            reason = f"ATK-009 connector lifecycle failed: {type(exc).__name__}."
            if results is None:
                raise ModuleUnavailableError(reason) from None
            record_execution_error(reason)
        return [result for result in results if result is not None]

    @staticmethod
    def _proposal_count(response: dict[str, Any]) -> int:
        proposals = response.get("tool_calls")
        if isinstance(proposals, list):
            return min(len(proposals), 100)
        if isinstance(response.get("function_call"), dict):
            return 1
        return 0

    def _observe_inventory(
        self, variant: dict[str, Any], message: str, response: dict[str, Any], limit: int
    ) -> None:
        digest, length = response_fingerprint(response, limit)
        text = response_text(response) if digest is not None else None
        marker = variant.get("detection_target")
        record_observation(
            {
                "variant_id": variant["id"],
                "criterion_version": INVENTORY_CRITERION,
                "evidence_source": "target_reported_response",
                "request_sha256": hashlib.sha256(message.encode("utf-8")).hexdigest(),
                "response_sha256": digest,
                "response_bytes": length,
                "response_text_available": text is not None,
                "seed_indicator_present": marker.casefold() in text.casefold()
                if isinstance(marker, str) and marker and text is not None
                else None,
                "reported_tool_proposal_count": self._proposal_count(response),
                "tool_execution_verified": False,
                "causal_attribution_verified": False,
                "downstream_impact": "unassessed",
            }
        )

    def _assess_policy(
        self,
        case: FactualityCase,
        arm: str,
        message: str,
        response: dict[str, Any],
        baseline_digest: str,
        limit: int,
    ) -> Finding | None:
        verdict = evaluate_factuality_response(response, limit)
        outcome = (
            "inconclusive"
            if verdict.status != "complete"
            else (
                "expected_answer" if verdict.answer == case.expected_answer else "answer_mismatch"
            )
        )
        metadata: dict[str, Any] = {
            "case_id": case.id,
            "arm": arm,
            "criterion_version": FACTUALITY_CRITERION,
            "assessment_scope": POLICY_SCOPE,
            "evidence_source": "operator_approved_exact_answer_comparison",
            "baseline_sha256": baseline_digest,
            "question_sha256": hashlib.sha256(case.question.encode("utf-8")).hexdigest(),
            "request_sha256": hashlib.sha256(message.encode("utf-8")).hexdigest(),
            "response_sha256": verdict.response_sha256,
            "response_bytes": verdict.response_bytes,
            "outcome": outcome,
            "security_impact": "unassessed",
            "causal_attribution_verified": False,
        }
        record_observation(metadata)
        if verdict.status != "complete":
            raise AssessmentInconclusiveError(verdict.reason)
        if outcome == "expected_answer":
            return None
        return self.make_finding(
            severity=Severity.MEDIUM,
            description=(
                f"Approved exact-answer policy mismatch in case {case.id}, arm {arm}. "
                "This establishes no security impact, tool execution or causal attribution."
            ),
            evidence=f"Response SHA256: {verdict.response_sha256}",
            remediation=self.default_remediation,
            metadata=metadata,
        )

    async def _test_variant(
        self,
        client: AgentScanClient,
        variant: dict[str, Any],
        judge: LLMJudge | None = None,
    ) -> Finding | None:
        del judge
        message = self._build_payload(variant)
        response = await client.send_message(message)
        self._observe_inventory(variant, message, response, client.target.max_response_bytes)
        raise AssessmentInconclusiveError(
            "Response inventory cannot verify factual or tool impact."
        )

    def _check_detection(
        self,
        method: str,
        response_text: str,
        target: str,
        response: dict[str, Any] | None = None,
    ) -> bool:
        raise AssessmentInconclusiveError("Target markers and tool proposals cannot verify impact.")
