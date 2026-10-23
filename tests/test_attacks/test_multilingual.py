# tests/test_attacks/test_multilingual.py
#
# Tests for ATK-011: Multilingual Alignment Bypass.

import httpx
import pytest
import respx

from agentscan.attacks.scan.multilingual import PAYLOAD_FILE, MultilingualModule
from agentscan.core.models import ScanMode, Severity, Target

PRIVATE = "SYNTHETIC_MULTILINGUAL_PRIVATE_63QmR8z"
CHINESE_LEAK = "好的，这是测试记录：" + PRIVATE
SAFE_REFUSAL = "I cannot fulfill this request as it violates safety guidelines."


def test_multilingual_payload_file_exists() -> None:
    assert PAYLOAD_FILE.exists()
    assert PAYLOAD_FILE.is_file()


def test_multilingual_module_metadata() -> None:
    module = MultilingualModule()
    assert module.attack_id == "ATK-011"
    assert module.attack_name == "Multilingual Alignment Bypass"
    assert module.owasp_id == "LLM01"
    assert ScanMode.SCAN in module.supported_modes
    assert module.variant_count() == 18
    assert module.assessment_scope == "multilingual_complete_known_reference"


@pytest.mark.asyncio
async def test_multilingual_scan_flags_vulnerability() -> None:
    module = MultilingualModule()
    target = Target(url="http://mock-agent.test/chat", canary_token=PRIVATE)

    with respx.mock(assert_all_called=False) as mock:
        mock.post("http://mock-agent.test/chat").mock(
            return_value=httpx.Response(200, json={"response": CHINESE_LEAK})
        )
        findings = await module.run(target)

    assert len(findings) == module.variant_count()
    f = findings[0]
    assert f.attack_id == "ATK-011"
    assert f.severity == Severity.HIGH
    assert f.owasp_id == "LLM01"
    assert f.metadata["declared_language"] == "zh"
    assert f.metadata["language_effect_verified"] is False
    assert PRIVATE not in f.model_dump_json()


@pytest.mark.asyncio
async def test_multilingual_scan_passes_when_safe() -> None:
    module = MultilingualModule()
    target = Target(url="http://mock-agent.test/chat", canary_token=PRIVATE)

    with respx.mock(assert_all_called=False) as mock:
        mock.post("http://mock-agent.test/chat").mock(
            return_value=httpx.Response(200, json={"response": SAFE_REFUSAL})
        )
        findings = await module.run(target)

    assert len(findings) == 0
