# agentscan/ui/status_labels.py
#
# Evidence-derived status labels for dashboard surfaces (QA issue #35).
#
# Every helper answers one question: what does the recorded evidence actually support?
# When the evidence is missing the label degrades to Not assessed / Not deployed /
# Unknown instead of painting a positive assurance such as ACTIVE, ENFORCED, or READY.

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

NOT_ASSESSED = "Not assessed"
NOT_DEPLOYED = "Not deployed"
UNKNOWN = "Unknown"


def _label(state: str, label: str, **evidence: Any) -> dict[str, Any]:
    return {"state": state, "label": label, "evidence": evidence}


def assess_canary_monitoring(sentinel: Mapping[str, Any]) -> dict[str, Any]:
    """Return the canary monitoring state supported by the sentinel payload."""
    running = bool(sentinel.get("running"))
    configured = bool(sentinel.get("canary_token"))
    if running and configured:
        return _label("monitoring", "Monitoring", running=True, canary_token_configured=True)
    if configured:
        return _label(
            "inactive", "Configured - not running", running=False, canary_token_configured=True
        )
    if running:
        return _label(
            "missing_evidence", "No canary token", running=True, canary_token_configured=False
        )
    return _label("not_deployed", NOT_DEPLOYED, running=False, canary_token_configured=False)


def _non_negative_int(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _finding_count(record: Mapping[str, Any]) -> int:
    return _non_negative_int(record.get("findings_count")) or 0


def assess_canary_leaks(sentinel: Mapping[str, Any]) -> dict[str, Any]:
    """Return the leak state supported by recorded probe/cycle outcomes.

    Absence of leak records is not evidence of absence: until at least one probe
    cycle has been recorded the label is Not assessed.
    """
    records = [record for record in sentinel.get("alerts") or [] if isinstance(record, Mapping)]
    probes_run = _non_negative_int(sentinel.get("probes_run"))
    if probes_run is None:
        probes_run = len(records)
    leaks = _non_negative_int(sentinel.get("leaks_detected"))
    if leaks is None:
        leaks = sum(_finding_count(record) for record in records)

    if probes_run <= 0:
        return _label("not_assessed", NOT_ASSESSED, probes_run=0, leaks_detected=0)
    if leaks > 0:
        return _label("alert", "Alert", probes_run=probes_run, leaks_detected=leaks)
    return _label("clear", "No leaks recorded", probes_run=probes_run, leaks_detected=0)


def assess_guardrail_deployment(exported_config: Any) -> dict[str, Any]:
    """Return the deployment state of an exported gateway guardrail config.

    AgentScan only exports a template; it never observes the gateway deployment,
    so a present template is Exported - not deployed rather than ACTIVE/ENFORCED.
    """
    exported = bool(exported_config)
    if not exported:
        return _label("not_deployed", NOT_DEPLOYED, exported=False, deployment_verified=False)
    return _label(
        "export_only", "Exported - not deployed", exported=True, deployment_verified=False
    )


def assess_mcp_tool_registration(mcp: Mapping[str, Any]) -> dict[str, Any]:
    """Return the readiness state supported by the MCP payload.

    The tools are metadata registered in-process; no per-tool invocation or health
    probe is recorded, so metadata is Registered - not verified, not READY.
    """
    tools = mcp.get("tools")
    registered = len(tools) if isinstance(tools, list) else 0
    if registered == 0:
        return _label("unknown", UNKNOWN, tools_registered=0, invocation_verified=False)
    return _label(
        "registered",
        "Registered - not verified",
        tools_registered=registered,
        invocation_verified=False,
    )


def _agent_field(agent: Any, name: str) -> Any:
    if isinstance(agent, Mapping):
        return agent.get(name)
    return getattr(agent, name, None)


def assess_manifest_enforcement(
    agent: Any, role_policies: Mapping[str, Any] | None
) -> dict[str, Any]:
    """Return the enforcement state supported by an identity manifest.

    A manifest declares a role; AgentScan compares that declaration with the loaded
    role policies. Neither step enforces anything at runtime, so the strongest
    supported label is Declared - not verified.
    """
    role = _agent_field(agent, "declared_role")
    if not role_policies:
        return _label(
            "not_assessed", NOT_ASSESSED, declared_role=role, reason="no role policies loaded"
        )
    if not isinstance(role, str) or not role or role not in role_policies:
        return _label(
            "not_assessed", NOT_ASSESSED, declared_role=role, reason="no matching role policy"
        )
    return _label(
        "declared",
        "Declared - not verified",
        declared_role=role,
        matched_role_policy=role,
        enforcement_verified=False,
    )
