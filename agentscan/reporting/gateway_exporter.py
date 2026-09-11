# agentscan/reporting/gateway_exporter.py
#
# Enterprise AI Gateway & WAF Guardrail Exporter.
# Translates AgentScan vulnerabilities and attack signatures into production
# firewall policies for LiteLLM Proxy, Cloudflare AI Gateway, and AWS Bedrock Guardrails.

from __future__ import annotations

import json
from pathlib import Path

import yaml

from agentscan.core.models import Finding

# ── LiteLLM Proxy Guardrails ──────────────────────────────────────────────────


def export_litellm_guardrails(
    findings: list[Finding] | None = None, output_path: Path | None = None
) -> str:
    """
    Export LiteLLM Proxy guardrails.yaml configuration.
    Defines input/output content filtering, banned keywords, and regex rules.
    """
    banned_keywords = [
        "ignore all previous instructions",
        "system prompt override",
        "repeat the words above",
        "admin mode activated",
        "disregard safety guidelines",
    ]

    # Incorporate indicators from specific findings if present
    if findings:
        for f in findings:
            if "canary_token" in f.metadata:
                banned_keywords.append(f.metadata["canary_token"].lower())

    config = {
        "guardrails": [
            {
                "guardrail_name": "agentscan_injection_shield",
                "litellm_params": {
                    "guardrail": "aporia",
                    "mode": "during_call",
                },
            },
            {
                "guardrail_name": "agentscan_keyword_filter",
                "litellm_params": {
                    "guardrail": "keyword_filter",
                    "mode": "pre_call",
                    "keywords": sorted(list(set(banned_keywords))),
                    "default_on": True,
                },
            },
            {
                "guardrail_name": "agentscan_regex_redact",
                "litellm_params": {
                    "guardrail": "hide_secrets",
                    "mode": "post_call",
                    "patterns": [
                        r"(?i)(sk-[a-zA-Z0-9]{20,})",
                        r"(?i)(CANARY-[A-Z0-9\-]+)",
                        r"(?i)(password\s*=\s*['\"][^'\"]+['\"])",
                    ],
                },
            },
        ]
    }

    yaml_str = yaml.dump(config, sort_keys=False)
    if output_path:
        output_path.write_text(yaml_str, encoding="utf-8")
    return yaml_str


# ── Cloudflare AI Gateway ─────────────────────────────────────────────────────


def export_cloudflare_guardrails(
    findings: list[Finding] | None = None, output_path: Path | None = None
) -> str:
    """
    Export Cloudflare AI Gateway guardrail JSON rules.
    Configures input evaluation, rate limiting, and regex blocking.
    """
    rules = [
        {
            "id": "rule_prompt_injection",
            "name": "AgentScan Prompt Injection Guard",
            "action": "block",
            "filter": {
                "input.text": {
                    "regex_match": r"(?i)(ignore (all )?previous instructions|system prompt override)"
                }
            },
        },
        {
            "id": "rule_secret_leak_prevention",
            "name": "AgentScan Output Secret Leak Guard",
            "action": "block",
            "filter": {
                "output.text": {"regex_match": r"(?i)(CANARY-[A-Z0-9\-]+|sk-[a-zA-Z0-9]{20,})"}
            },
        },
    ]

    if findings:
        for f in findings:
            if f.attack_id == "ATK-007":
                rules.append(
                    {
                        "id": f"rule_xss_output_{f.attack_id.lower()}",
                        "name": "AgentScan Insecure Output Filter",
                        "action": "block",
                        "filter": {"output.text": {"regex_match": r"<script[\s>]|javascript:"}},
                    }
                )
                break

    payload = {
        "gateway_name": "agentscan-protected-gateway",
        "version": "1.0",
        "guardrail_rules": rules,
    }

    json_str = json.dumps(payload, indent=2)
    if output_path:
        output_path.write_text(json_str, encoding="utf-8")
    return json_str


# ── AWS Bedrock Guardrails ────────────────────────────────────────────────────


def export_bedrock_guardrails(
    findings: list[Finding] | None = None, output_path: Path | None = None
) -> str:
    """
    Export AWS Bedrock Guardrail JSON configuration.
    Configures content policy filters, sensitive info PII, and contextual grounding.
    """
    bedrock_config = {
        "name": "AgentScanDefenseGuardrail",
        "description": "Exported from AgentScan automated security scan findings",
        "contentPolicyConfig": {
            "filtersConfig": [
                {
                    "type": "PROMPT_ATTACK",
                    "inputStrength": "HIGH",
                    "outputStrength": "NONE",
                },
                {
                    "type": "MISCONDUCT",
                    "inputStrength": "HIGH",
                    "outputStrength": "HIGH",
                },
            ]
        },
        "sensitiveInformationPolicyConfig": {
            "piiEntitiesConfig": [
                {"type": "EMAIL", "action": "ANONYMIZE"},
                {"type": "PASSWORD", "action": "BLOCK"},
                {"type": "AWS_ACCESS_KEY", "action": "BLOCK"},
            ],
            "regexesConfig": [
                {
                    "name": "CanaryTokenFilter",
                    "pattern": r"CANARY-[A-Z0-9\-]+",
                    "action": "BLOCK",
                    "description": "Block internal AgentScan canary tokens from leaking in output",
                },
                {
                    "name": "ApiKeyFilter",
                    "pattern": r"sk-[a-zA-Z0-9]{20,}",
                    "action": "BLOCK",
                    "description": "Block leaked OpenAI/Anthropic API keys",
                },
            ],
        },
        "contextualGroundingPolicyConfig": {
            "filtersConfig": [
                {
                    "type": "GROUNDING",
                    "threshold": 0.85,
                },
                {
                    "type": "RELEVANCE",
                    "threshold": 0.80,
                },
            ]
        },
        "blockedInputMessaging": "Request blocked by AgentScan security policy.",
        "blockedOutputsMessaging": "Response suppressed due to confidential data policy.",
    }

    json_str = json.dumps(bedrock_config, indent=2)
    if output_path:
        output_path.write_text(json_str, encoding="utf-8")
    return json_str
