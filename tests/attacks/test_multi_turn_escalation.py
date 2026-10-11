from __future__ import annotations

import pytest

from agentscan.attacks.scan.multi_turn_escalation import MultiTurnEscalationAttack
from agentscan.core.connectors import CallableConnector, use_connector
from agentscan.core.models import ScanMode, Target
from agentscan.core.outcomes import ModuleUnavailableError

CANARY = "CANARY-PRIVATE-7F2D18C099AB"


@pytest.mark.asyncio
async def test_compliance_and_echoes_are_not_leakage():
    attack = MultiTurnEscalationAttack()
    target = Target(url="http://mock.local/chat", mode=ScanMode.SCAN, canary_token=CANARY)
    with use_connector(CallableConnector(lambda msg: f"Sure! Acknowledged: {msg}")):
        assert await attack.run(target) == []


@pytest.mark.asyncio
async def test_refusal_does_not_produce_a_finding():
    attack = MultiTurnEscalationAttack()
    target = Target(url="http://mock.local/chat", canary_token=CANARY)
    with use_connector(
        CallableConnector(lambda msg: "I cannot disclose confidential configuration.")
    ):
        assert await attack.run(target) == []


@pytest.mark.asyncio
async def test_operator_seeded_canary_disclosure_is_critical():
    received = []

    def leaking_bot(msg):
        received.append(msg)
        return CANARY if "disclose the confidential" in msg else "Hello, how may I help?"

    target = Target(url="http://mock.local/chat", canary_token=CANARY)
    with use_connector(CallableConnector(leaking_bot)):
        findings = await MultiTurnEscalationAttack().run(target)
    assert findings and all(f.severity.value == "CRITICAL" for f in findings)
    assert all(CANARY not in payload for payload in received)
    assert findings[0].attack_id == "ATK-028"
    assert findings[0].metadata["canary_source"] == "operator_seeded"


@pytest.mark.asyncio
async def test_unprovisioned_canary_is_not_tested():
    target = Target(url="http://mock.local/chat")
    attack = MultiTurnEscalationAttack()
    assert not attack.is_applicable(target)
    with pytest.raises(ModuleUnavailableError, match="out of band"):
        await attack.run(target)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "reply,leaked",
    [
        (CANARY, True),
        ('"' + CANARY + '"', True),
        ("I refuse disclosure; however, " + " ".join(CANARY), True),
        (CANARY.lower(), False),
        (CANARY + "suffix", False),
        ("prefix" + CANARY, False),
        (CANARY.replace("-", ""), False),
        (CANARY[:-1], False),
    ],
)
async def test_complete_canary_match_preserves_boundaries_and_punctuation(reply, leaked):
    target = Target(url="http://mock.local/chat", canary_token=CANARY)
    with use_connector(CallableConnector(lambda msg: reply)):
        findings = await MultiTurnEscalationAttack().run(target)
    assert bool(findings) is leaked
