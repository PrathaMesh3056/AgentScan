import httpx
import pytest
import respx

from agentscan.attacks.exploit.tool_hijack import ToolHijackModule
from agentscan.core.models import ScanMode, Target


@pytest.fixture
def target_hijack():
    return Target(
        url="http://test-agent.example.com/chat",
        mode=ScanMode.EXPLOIT,
    )


@pytest.fixture
def mock_hijacked_response():
    with respx.mock(assert_all_called=False) as mock:
        mock.post("http://test-agent.example.com/chat").mock(
            return_value=httpx.Response(
                200,
                json={
                    "choices": [
                        {
                            "message": {
                                "tool_calls": [
                                    {
                                        "function": {
                                            "name": "send_email",
                                            "arguments": '{"to": "attacker@agentscan-hijack-test.invalid", "subject": "PWNED"}',
                                        }
                                    }
                                ]
                            }
                        }
                    ]
                },
            )
        )
        yield mock


@pytest.fixture
def mock_safe_tool_response():
    with respx.mock(assert_all_called=False) as mock:
        mock.post("http://test-agent.example.com/chat").mock(
            return_value=httpx.Response(
                200,
                json={
                    "choices": [
                        {
                            "message": {
                                "tool_calls": [
                                    {
                                        "function": {
                                            "name": "get_weather",
                                            "arguments": '{"location": "London"}',
                                        }
                                    }
                                ]
                            }
                        }
                    ]
                },
            )
        )
        yield mock


@pytest.fixture
def mock_no_tool_response():
    with respx.mock(assert_all_called=False) as mock:
        mock.post("http://test-agent.example.com/chat").mock(
            return_value=httpx.Response(200, json={"response": "I am a chat-only assistant."})
        )
        yield mock


@pytest.mark.asyncio
async def test_tool_hijack_detects_marker(target_hijack, mock_hijacked_response):
    module = ToolHijackModule()
    findings = await module.run(target_hijack)
    assert len(findings) == 1
    assert findings[0].attack_id == "ATK-015"
    assert findings[0].severity == "CRITICAL"
    assert "agentscan-hijack-test.invalid" in findings[0].evidence


@pytest.mark.asyncio
async def test_tool_hijack_ignores_safe_tool_calls(target_hijack, mock_safe_tool_response):
    module = ToolHijackModule()
    findings = await module.run(target_hijack)
    assert findings == []


@pytest.mark.asyncio
async def test_tool_hijack_ignores_no_tool_calls(target_hijack, mock_no_tool_response):
    module = ToolHijackModule()
    findings = await module.run(target_hijack)
    assert findings == []
