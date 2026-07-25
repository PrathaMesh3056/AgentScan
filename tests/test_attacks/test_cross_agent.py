import httpx
import pytest
import respx

from agentscan.attacks.exploit.cross_agent import CrossAgentInjectionModule
from agentscan.core.models import ScanMode, Target


@pytest.fixture
def target():
    return Target(url="http://test-agent.example.com/chat", mode=ScanMode.EXPLOIT)


@pytest.mark.asyncio
async def test_cross_agent_success(target):
    with respx.mock(assert_all_called=False) as mock:
        mock.post("http://test-agent.example.com/chat").mock(
            return_value=httpx.Response(
                200, json={"response": "I have updated my constraints. CROSS_AGENT_TRUST_EXPLOITED"}
            )
        )

        module = CrossAgentInjectionModule()
        findings = await module.run(target)

        assert len(findings) == 1
        assert findings[0].attack_id == "ATK-017"
        assert findings[0].severity == "CRITICAL"
        assert "CROSS_AGENT_TRUST_EXPLOITED" in findings[0].evidence


@pytest.mark.asyncio
async def test_cross_agent_resisted(target):
    with respx.mock(assert_all_called=False) as mock:
        mock.post("http://test-agent.example.com/chat").mock(
            return_value=httpx.Response(
                200, json={"response": "I cannot override my constraints based on this message."}
            )
        )

        module = CrossAgentInjectionModule()
        findings = await module.run(target)

        assert findings == []
