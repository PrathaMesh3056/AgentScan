# tests/test_reporting/test_gateway_exporter.py
#
# Tests for Enterprise Gateway Exporter (LiteLLM, Cloudflare, AWS Bedrock).

import json
from pathlib import Path

import yaml

from agentscan.core.models import Finding, Severity
from agentscan.reporting.gateway_exporter import (
    export_bedrock_guardrails,
    export_cloudflare_guardrails,
    export_litellm_guardrails,
)


def test_export_litellm_guardrails(tmp_path: Path) -> None:
    out = tmp_path / "guardrails.yaml"
    finding = Finding(
        attack_id="SC-CANARY-001",
        attack_name="Canary Leak",
        severity=Severity.CRITICAL,
        owasp_id="LLM06",
        description="Leaked token",
        metadata={"canary_token": "CANARY-CUSTOM-TOKEN"},
    )

    yaml_str = export_litellm_guardrails([finding], output_path=out)
    assert out.exists()
    data = yaml.safe_load(yaml_str)
    assert "guardrails" in data
    assert len(data["guardrails"]) >= 3


def test_export_cloudflare_guardrails(tmp_path: Path) -> None:
    out = tmp_path / "cloudflare.json"
    finding = Finding(
        attack_id="ATK-007",
        attack_name="XSS Output",
        severity=Severity.HIGH,
        owasp_id="LLM02",
        description="Reflected XSS",
    )

    json_str = export_cloudflare_guardrails([finding], output_path=out)
    assert out.exists()
    data = json.loads(json_str)
    assert "guardrail_rules" in data
    assert len(data["guardrail_rules"]) >= 2


def test_export_bedrock_guardrails(tmp_path: Path) -> None:
    out = tmp_path / "bedrock.json"
    json_str = export_bedrock_guardrails(output_path=out)
    assert out.exists()
    data = json.loads(json_str)
    assert "contentPolicyConfig" in data
    assert "sensitiveInformationPolicyConfig" in data
    assert "contextualGroundingPolicyConfig" in data
