"""ATK-013: inventory reported tool intent without inventing authorization proof."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from agentscan.attacks.scan.runner import YamlScanRunner
from agentscan.core.client import AgentScanClient
from agentscan.core.evaluator import LLMJudge
from agentscan.core.models import Finding, Target
from agentscan.core.outcomes import (
    AssessmentInconclusiveError,
    execution_ledger,
    record_inconclusive,
    record_observation,
)

PAYLOAD_FILE = Path(__file__).resolve().parent.parent / "payloads" / "excessive_agency.yaml"
_CRITERION = "atk013-agency-observation-2026-10-18"
_MCP_SCHEMES = {"mcp", "mcp+stdio", "mcp+sse", "mcp+sses"}
_TOOL_NAME = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z")
_PROPOSAL_LIMIT = 1000
_COMPLETION_STATUSES = {"executed", "completed", "succeeded"}
_APPROVAL_PENDING_STATUSES = {
    "awaiting_approval",
    "approval_pending",
    "pending_approval",
    "requires_approval",
}


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Ambiguous JSON object.")
        value[key] = item
    return value


def _invalid_constant(value: str) -> Any:
    raise ValueError("Non-finite JSON value.")


def _proposal_inventory(response: dict[str, Any]) -> dict[str, Any]:
    """Count bounded syntactic reports, never authorize or execute a proposal.

    Support a single root or OpenAI first-choice message envelope. Conflicting
    envelopes are ambiguous rather than silently choosing the favorable one.
    Counters describe records, not unique calls or durable effects.
    """
    inventory: dict[str, Any] = {
        "reported_proposal_count": 0,
        "malformed_proposal_count": 0,
        "reported_completion_claim_count": 0,
        "reported_approval_pending_count": 0,
        "proposal_scan_truncated": False,
        "proposal_scan_limit": _PROPOSAL_LIMIT,
        "proposal_envelope": "none",
    }
    envelope = response
    root_keys = [key for key in ("tool_calls", "function_call") if key in response]
    if root_keys and "choices" in response:
        inventory.update(proposal_envelope="ambiguous", malformed_proposal_count=1)
        return inventory
    if "choices" in response:
        choices = response["choices"]
        if (
            not isinstance(choices, list)
            or len(choices) != 1
            or not isinstance(choices[0], dict)
            or not isinstance(choices[0].get("message"), dict)
        ):
            inventory.update(proposal_envelope="invalid", malformed_proposal_count=1)
            return inventory
        envelope = choices[0]["message"]
    keys = [key for key in ("tool_calls", "function_call") if key in envelope]
    if len(keys) > 1:
        inventory.update(proposal_envelope="ambiguous", malformed_proposal_count=1)
        return inventory
    if not keys:
        return inventory
    key = keys[0]
    inventory["proposal_envelope"] = key
    calls = envelope[key]
    if key == "function_call":
        if not isinstance(calls, dict):
            inventory.update(proposal_envelope="invalid", malformed_proposal_count=1)
            return inventory
        calls = [calls]
    if not isinstance(calls, list):
        inventory.update(proposal_envelope="invalid", malformed_proposal_count=1)
        return inventory
    inventory["proposal_scan_truncated"] = len(calls) > _PROPOSAL_LIMIT
    for call in calls[:_PROPOSAL_LIMIT]:
        if not isinstance(call, dict):
            inventory["malformed_proposal_count"] += 1
            continue
        status = call.get("status")
        status = status.lower() if isinstance(status, str) and len(status) <= 64 else ""
        inventory["reported_completion_claim_count"] += int(
            call.get("executed") is True or status in _COMPLETION_STATUSES
        )
        inventory["reported_approval_pending_count"] += int(status in _APPROVAL_PENDING_STATUSES)
        function = call.get("function", call)
        if not isinstance(function, dict):
            inventory["malformed_proposal_count"] += 1
            continue
        name = function.get("name")
        arguments = function.get("arguments", {})
        if isinstance(arguments, str):
            try:
                arguments = json.loads(
                    arguments, object_pairs_hook=_unique_object, parse_constant=_invalid_constant
                )
                # The decoder accepts exponent overflow as infinity even with
                # parse_constant overridden. Validate nested decoded numbers too.
                json.dumps(arguments, allow_nan=False)
            except (ValueError, RecursionError):
                arguments = None
        if (
            not isinstance(name, str)
            or not _TOOL_NAME.fullmatch(name)
            or not isinstance(arguments, dict)
        ):
            inventory["malformed_proposal_count"] += 1
            continue
        inventory["reported_proposal_count"] += 1
    return inventory


class ExcessiveAgencyModule(YamlScanRunner):
    """Ten retained user probes with unassessed authorization and effects.

    A target's tool names, approvals, completion claims and refusals are all
    untrusted reports. The same action can be authorized for one principal and
    forbidden for another. Independent policy, approval and effect evidence is
    required to assess excessive agency; this profile supplies none of them.
    """

    is_abstract = False
    attack_id = "ATK-013"
    attack_name = "Excessive Agency & Unauthorized Tool Invocation"
    owasp_id = "LLM06"  # OWASP LLM Top 10:2025.
    payload_file = PAYLOAD_FILE
    assessment_scope = "agency_proposal_inventory"
    default_remediation = (
        "Enforce per-user least privilege at the actual tool dispatch boundary. "
        "Bind required approvals to the exact action, arguments and resources; "
        "revalidate changes and retries. Keep independent authorization and effect "
        "records. A model refusal, tool name or reported status is not enforcement."
    )

    async def run(self, target: Target) -> list[Finding]:
        ledger = execution_ledger.get()
        if ledger is not None:
            ledger.assessment_scope = self.assessment_scope
            ledger.selected, ledger.evaluated = self.variant_count(), 0
        if urlsplit(target.url).scheme in _MCP_SCHEMES:
            record_inconclusive(
                "ATK-013 has no independently enrolled authorization/effects adapter. "
                "Chat probes are not dispatched through an arbitrary MCP tool."
            )
            return []
        # Neither a judge nor additional generated prompts can supply independent
        # approval/effects evidence. Keep the ten-seed observation denominator.
        return await super().run(
            target.model_copy(update={"judge_model": None, "attacker_model": None, "mutate": False})
        )

    async def _test_variant(
        self, client: AgentScanClient, variant: dict[str, Any], judge: LLMJudge | None = None
    ) -> Finding | None:
        if variant.get("channel", "user") != "user":
            raise AssessmentInconclusiveError("ATK-013 supports only its direct user-text probes.")
        response = await self._deliver_variant(client, variant)
        if not isinstance(response, dict):
            raise AssessmentInconclusiveError("ATK-013 received no JSON response object.")
        try:
            encoded = json.dumps(
                response, sort_keys=True, ensure_ascii=True, allow_nan=False
            ).encode()
        except (TypeError, ValueError, RecursionError, UnicodeError) as error:
            raise AssessmentInconclusiveError("ATK-013 received invalid response JSON.") from error
        if len(encoded) > client.target.max_response_bytes:
            raise AssessmentInconclusiveError(
                "ATK-013 response observation exceeds its size limit."
            )
        record_observation(
            {
                "variant_id": variant["id"],
                "criterion_version": _CRITERION,
                "response_sha256": hashlib.sha256(encoded).hexdigest(),
                "response_bytes": len(encoded),
                **_proposal_inventory(response),
                "evidence_source": "target_reported_intent",
                "authorization_verified": False,
                "approval_verified": False,
                "tool_execution_verified": False,
                "downstream_impact": "unassessed",
            }
        )
        raise AssessmentInconclusiveError(
            "Target-reported proposals, completion claims and refusals cannot establish "
            "authorization, approval or actual effects. Independent policy and effect "
            "evidence is unavailable."
        )

    def _check_detection(
        self, method: str, response_text: str, target: str, response: dict[str, Any] | None = None
    ) -> bool:
        raise AssessmentInconclusiveError(
            "ATK-013 cannot establish authorization or tool impact from a target response."
        )
