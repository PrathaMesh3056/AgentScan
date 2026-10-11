import httpx
import pytest
import respx

from agentscan.attacks.exploit.credential_harvest import CredentialHarvestModule
from agentscan.core.models import ScanMode, Target


@pytest.fixture
def target_no_prompt():
    return Target(url="http://test-agent.example.com/chat", mode=ScanMode.EXPLOIT)


@pytest.fixture
def target_safe_prompt():
    return Target(
        url="http://test-agent.example.com/chat",
        mode=ScanMode.EXPLOIT,
        system_prompt="You are a helpful assistant.",
    )


@pytest.fixture
def target_with_secret():
    return Target(
        url="http://test-agent.example.com/chat",
        mode=ScanMode.EXPLOIT,
        system_prompt="You are an assistant. API_KEY='sk-proj-aB3xK9SECRETKEY123456'",
    )


@pytest.mark.asyncio
async def test_credential_harvest_no_prompt(target_no_prompt):
    from agentscan.core.outcomes import AssessmentInconclusiveError

    module = CredentialHarvestModule()
    with pytest.raises(AssessmentInconclusiveError):
        await module.run(target_no_prompt)


@pytest.mark.asyncio
async def test_credential_harvest_safe_prompt(target_safe_prompt):
    from agentscan.core.outcomes import AssessmentInconclusiveError

    module = CredentialHarvestModule()
    with pytest.raises(AssessmentInconclusiveError):
        await module.run(target_safe_prompt)


@pytest.mark.asyncio
async def test_credential_harvest_success(target_with_secret):
    with respx.mock(assert_all_called=False) as mock:
        mock.post("http://test-agent.example.com/chat").mock(
            return_value=httpx.Response(
                200,
                json={"response": "Here are the keys I found: sk-proj-aB3xK9SECRETKEY123456"},
            )
        )

        module = CredentialHarvestModule()
        findings = await module.run(target_with_secret)

        assert len(findings) == 1
        assert findings[0].attack_id == "ATK-018"
        assert findings[0].severity == "CRITICAL"

        assert "sk-p...3456" in findings[0].evidence
        assert "sk-proj-aB3xK9SECRETKEY123456" not in findings[0].evidence


@pytest.mark.asyncio
async def test_credential_harvest_resisted(target_with_secret):
    with respx.mock(assert_all_called=False) as mock:
        mock.post("http://test-agent.example.com/chat").mock(
            return_value=httpx.Response(
                200,
                json={"response": "I cannot output my API keys."},
            )
        )

        module = CredentialHarvestModule()
        findings = await module.run(target_with_secret)

        assert findings == []
