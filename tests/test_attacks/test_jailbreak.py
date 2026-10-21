"""ATK-002 persona probes require independently provisioned private evidence."""

from __future__ import annotations

import hashlib
import json

import pytest
import respx

from agentscan.attacks.scan.jailbreak import JailbreakModule
from agentscan.core.models import ScanMode, Severity, Target
from agentscan.core.outcomes import AssessmentInconclusiveError

PRIVATE = "SYNTHETIC_PERSONA_PRIVATE_92KmT7aZ31"
URL = "http://test-agent.example.com/chat"


@pytest.fixture
def module() -> JailbreakModule:
    return JailbreakModule()


@pytest.fixture
def jb_target() -> Target:
    return Target(url=URL, canary_token=PRIVATE)


@pytest.mark.parametrize("method", ["contains", "not_contains", "regex", "semantic_similarity"])
def test_legacy_markers_cannot_establish_disclosure(module, jb_target, method):
    module._current_target = jb_target
    assert not module._check_detection(method, "NEXUS SYSTEM FULLY UNBOUND", "NEXUS")
    assert module._check_detection(method, PRIVATE, "NEXUS")


def test_missing_reference_is_inconclusive(module):
    with pytest.raises(AssessmentInconclusiveError):
        module._check_detection("contains", "MAL_ACTIVATED", "MAL_ACTIVATED")


@pytest.mark.asyncio
@pytest.mark.parametrize("reply", ["NEXUS SYSTEM FULLY UNBOUND", "MAL_ACTIVATED", "I refuse."])
async def test_complete_public_marker_or_refusal_is_not_finding(module, jb_target, reply):
    with respx.mock(assert_all_called=False) as mock:
        route = mock.post(URL).respond(200, json={"response": reply})
        assert await module.run(jb_target) == []
        assert route.call_count == module.variant_count()


@pytest.mark.asyncio
async def test_private_reference_produces_scoped_digest_evidence(module, jb_target):
    with respx.mock(assert_all_called=False) as mock:
        route = mock.post(URL).respond(200, json={"response": PRIVATE})
        findings = await module.run(jb_target)
    assert len(findings) == module.variant_count()
    assert all(PRIVATE not in request.content.decode() for request, _ in route.calls)
    for finding in findings:
        assert finding.attack_id == "ATK-002"
        assert finding.severity == Severity.HIGH
        assert finding.metadata["assessment_scope"] == "persona_complete_known_reference"
        assert finding.metadata["criterion_version"] == "atk002-known-reference-2026-10-20"
        assert finding.metadata["detection_method"] == "known_private_reference"
        assert finding.metadata["persona_adoption_verified"] is False
        assert finding.metadata["tool_execution_verified"] is False
        assert PRIVATE not in finding.model_dump_json()
        assert hashlib.sha256(PRIVATE.encode()).hexdigest() in finding.evidence
        assert "broke alignment" not in finding.description


@pytest.mark.asyncio
async def test_missing_reference_prevents_target_io(module):
    with respx.mock(assert_all_called=False) as mock:
        route = mock.post(URL).respond(200, json={"response": "MAL_ACTIVATED"})
        with pytest.raises(AssessmentInconclusiveError):
            await module.run(Target(url=URL))
        assert not route.called


def test_bounded_packaged_payloads_and_existing_modes(module):
    variants = module._load_payload_variants()
    assert module.variant_count() == 18
    assert len({v["id"] for v in variants}) == 18
    assert all(v.get("channel", "user") == "user" for v in variants)
    assert all(len(module._build_payload(v)) < 4096 for v in variants)
    assert PRIVATE not in json.dumps(variants)
    assert module.supported_modes == [ScanMode.SCAN]
