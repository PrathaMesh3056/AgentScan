"""ATK-009 effect, transport, privacy and independent-baseline controls."""

from __future__ import annotations

import hashlib
import json
from unittest.mock import AsyncMock, patch

import pytest
import respx

from agentscan.attacks.scan.overreliance import OverrelianceModule
from agentscan.core.context import ScanContext, active_context
from agentscan.core.factuality import FactualityBaseline
from agentscan.core.models import Target
from agentscan.core.outcomes import (
    AssessmentInconclusiveError,
    ExecutionLedger,
    ModuleUnavailableError,
    execution_ledger,
)

URL = "https://agent.example/chat"
PRIVATE_QUESTION = "SENSITIVE_QUESTION_8e2c1"
PRIVATE_EXPECTED = "SENSITIVE_APPROVED_d102a"
PRIVATE_FALSE = "SENSITIVE_FALSE_75c8a"


def baseline():
    return FactualityBaseline(
        schema_version="agentscan.factuality.v1",
        target_url=URL,
        cases=[
            {
                "id": "CASE-1",
                "question": PRIVATE_QUESTION,
                "expected_answer": PRIVATE_EXPECTED,
                "false_answer": PRIVATE_FALSE,
            }
        ],
    )


def test_legacy_payload_bytes_are_preserved():
    new = OverrelianceModule()._load_payload_variants()
    encoded = json.dumps(
        [(row["id"], row["payload"]) for row in new], ensure_ascii=True, separators=(",", ":")
    ).encode("ascii")
    assert len(new) == 8
    assert (
        hashlib.sha256(encoded).hexdigest()
        == "0dbb652966a58f8153551a7132ea9bd1ee8916c3518fb67e560393246840f83c"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "scheme",
    ["mcp://stdio?command=python", "mcp+sse://agent.example/mcp", "wss://agent.example/chat"],
)
async def test_no_native_mcp_or_unsupported_connector_dispatch(scheme):
    with (
        patch(
            "agentscan.attacks.scan.overreliance.AgentScanClient",
            side_effect=AssertionError("opened"),
        ),
        pytest.raises(ModuleUnavailableError, match="HTTP"),
    ):
        await OverrelianceModule().run(Target(url=scheme))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change",
    [
        {"url": "https://other.example/chat"},
        {"mutate": True},
        {"judge_model": "fake"},
        {"analysis_mode": "local"},
        {"indirect_adapter": "document_v1"},
    ],
)
async def test_model_copy_cannot_bypass_profile_before_connection(change):
    target = Target(url=URL, factuality_baseline=baseline()).model_copy(update=change)
    with (
        patch(
            "agentscan.attacks.scan.overreliance.AgentScanClient",
            side_effect=AssertionError("opened"),
        ),
        pytest.raises(ModuleUnavailableError, match="configuration is invalid"),
    ):
        await OverrelianceModule().run(target)


@pytest.mark.asyncio
async def test_request_budget_does_not_count_unexecuted_arm_as_safe():
    ledger = ExecutionLedger()
    ledger_token = execution_ledger.set(ledger)
    context_token = active_context.set(ScanContext(request_budget=1))
    try:
        with respx.mock(assert_all_called=False) as mock:
            route = mock.post(URL).respond(
                200, json={"response": json.dumps({"answer": PRIVATE_EXPECTED})}
            )
            findings = await OverrelianceModule().run(
                Target(url=URL, factuality_baseline=baseline())
            )
        assert findings == []
        assert route.call_count == 1
        assert ledger.selected == 2 and ledger.evaluated == 1
        assert ledger.errors
        assert len(ledger.observations) == 1
    finally:
        active_context.reset(context_token)
        execution_ledger.reset(ledger_token)


@pytest.mark.asyncio
async def test_direct_module_budget_without_scan_context():
    ledger = ExecutionLedger()
    ledger_token = execution_ledger.set(ledger)
    context_token = active_context.set(None)
    try:
        with respx.mock(assert_all_called=False) as mock:
            route = mock.post(URL).respond(
                200, json={"response": json.dumps({"answer": PRIVATE_EXPECTED})}
            )
            assert (
                await OverrelianceModule().run(
                    Target(url=URL, factuality_baseline=baseline(), request_budget=1)
                )
                == []
            )
        assert route.call_count == 1
        assert ledger.selected == 2 and ledger.evaluated == 1
        assert any("TargetRequestError" in error for error in ledger.errors)
    finally:
        active_context.reset(context_token)
        execution_ledger.reset(ledger_token)


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [401, 429, 503])
async def test_http_errors_preserve_unassessed_coverage_without_error_body(failure):
    ledger = ExecutionLedger()
    token = execution_ledger.set(ledger)
    try:
        with respx.mock(assert_all_called=False) as mock:
            mock.post(URL).respond(failure, text=PRIVATE_EXPECTED)
            assert (
                await OverrelianceModule().run(Target(url=URL, factuality_baseline=baseline()))
                == []
            )
        assert ledger.evaluated == 0 and ledger.selected == 2 and ledger.errors
        assert PRIVATE_EXPECTED not in json.dumps(ledger.errors)
    finally:
        execution_ledger.reset(token)


@pytest.mark.asyncio
async def test_private_baseline_and_unknown_reply_never_enter_finding_or_reasons():
    ledger = ExecutionLedger()
    token = execution_ledger.set(ledger)
    try:
        with respx.mock(assert_all_called=False) as mock:
            mock.post(URL).respond(
                200, json={"response": json.dumps({"answer": "UNEXPECTED_SECRET_412df"})}
            )
            findings = await OverrelianceModule().run(
                Target(url=URL, factuality_baseline=baseline())
            )
        encoded = json.dumps(
            {
                "findings": [finding.model_dump(mode="json") for finding in findings],
                "observations": ledger.observations,
                "errors": ledger.errors,
                "inconclusive": ledger.inconclusive_reasons,
            }
        )
        for secret in (
            PRIVATE_QUESTION,
            PRIVATE_EXPECTED,
            PRIVATE_FALSE,
            "UNEXPECTED_SECRET_412df",
        ):
            assert secret not in encoded
        assert len(findings) == 2
        assert (
            ledger.observations[0]["question_sha256"]
            == hashlib.sha256(PRIVATE_QUESTION.encode()).hexdigest()
        )
    finally:
        execution_ledger.reset(token)


def test_detection_marker_api_cannot_claim_success():
    with pytest.raises(AssessmentInconclusiveError):
        OverrelianceModule()._check_detection(
            "contains", "AGENTSCAN-FALSE-FACT-OK", "AGENTSCAN-FALSE-FACT-OK"
        )


@pytest.mark.asyncio
async def test_connector_setup_exception_does_not_echo_private_input():
    with patch("agentscan.attacks.scan.overreliance.AgentScanClient") as client_type:
        client_type.return_value.__aenter__ = AsyncMock(side_effect=RuntimeError(PRIVATE_EXPECTED))
        with pytest.raises(ModuleUnavailableError) as error:
            await OverrelianceModule().run(Target(url=URL, factuality_baseline=baseline()))
    assert PRIVATE_EXPECTED not in str(error.value)
    assert "RuntimeError" in str(error.value)
