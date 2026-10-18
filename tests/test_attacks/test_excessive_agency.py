# tests/test_attacks/test_excessive_agency.py
#
# Tests for ATK-013: Excessive Agency & Unauthorized Tool Invocation (OWASP LLM06).

from __future__ import annotations

import httpx
import pytest
import respx

from agentscan.attacks.scan.excessive_agency import ExcessiveAgencyModule
from agentscan.core.models import Target
from agentscan.core.outcomes import AssessmentInconclusiveError


class TestExcessiveAgencyModule:
    def test_module_metadata(self) -> None:
        module = ExcessiveAgencyModule()
        assert module.attack_id == "ATK-013"
        assert module.attack_name == "Excessive Agency & Unauthorized Tool Invocation"
        assert module.owasp_id == "LLM06"
        assert module.variant_count() == 10

    def test_variants_have_required_fields(self) -> None:
        module = ExcessiveAgencyModule()
        variants = module._load_payload_variants()
        assert len(variants) == 10
        for v in variants:
            assert v["id"].startswith("EXA-")
            assert "payload" in v
            assert "detection_method" in v
            assert "detection_target" in v
            assert v["severity"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
            assert "judge_objective" in v

    def test_reported_dangerous_tool_call_is_not_execution_evidence(self) -> None:
        module = ExcessiveAgencyModule()
        dangerous_response = {
            "response": "Executing deletion now.",
            "tool_calls": [
                {
                    "id": "call_123",
                    "type": "function",
                    "function": {
                        "name": "delete_file_recursive",
                        "arguments": '{"path": "/var/data"}',
                    },
                }
            ],
        }
        with pytest.raises(AssessmentInconclusiveError):
            module._check_detection(
                "regex", "Executing deletion now.", "deleted", response=dangerous_response
            )

    def test_check_detection_safe_tool_call(self) -> None:
        module = ExcessiveAgencyModule()
        safe_response = {
            "response": "I cannot delete files without confirmation.",
            "tool_calls": [
                {
                    "id": "call_456",
                    "type": "function",
                    "function": {
                        "name": "request_human_confirmation",
                        "arguments": '{"action": "delete"}',
                    },
                }
            ],
        }
        # Refusal does not attest unchanged state or an enforced approval gate.
        with pytest.raises(AssessmentInconclusiveError):
            module._check_detection(
                "regex",
                "I cannot delete files without confirmation.",
                "rm -rf",
                response=safe_response,
            )

    def test_scope_and_dispatch_remediation(self) -> None:
        module = ExcessiveAgencyModule()
        assert module.assessment_scope == "agency_proposal_inventory"
        assert "exact action, arguments and resources" in module.default_remediation

    @pytest.mark.asyncio
    async def test_scan_does_not_promote_target_claims_into_findings(self) -> None:
        module = ExcessiveAgencyModule()
        target = Target(url="http://agent.test/chat")

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "response": "Table customers dropped successfully.",
                    "tool_calls": [{"function": {"name": "drop_database_table"}}],
                },
            )

        with respx.mock(assert_all_called=False) as mock:
            mock.post("http://agent.test/chat").mock(side_effect=handler)
            findings = await module.run(target)

        assert findings == []

    @pytest.mark.asyncio
    async def test_scan_safe_agent_no_findings(self) -> None:
        module = ExcessiveAgencyModule()
        target = Target(url="http://agent.test/chat")

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "response": "I cannot perform destructive actions without secondary administrative approval."
                },
            )

        with respx.mock(assert_all_called=False) as mock:
            mock.post("http://agent.test/chat").mock(side_effect=handler)
            findings = await module.run(target)

        assert len(findings) == 0
