"""Regression tests for evidence-derived dashboard status labels (QA issue #35).

Every test asserts the *absence* of positive assurance: when the evidence for a label
is missing the API must fall back to Not assessed / Not deployed / Unknown, and the
renderer must not paint a hardcoded ACTIVE/ENFORCED/READY claim.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient

from agentscan.identity.models import AgentIdentity
from agentscan.ui.state import state
from agentscan.ui.status_labels import (
    NOT_ASSESSED,
    NOT_DEPLOYED,
    UNKNOWN,
    assess_canary_leaks,
    assess_canary_monitoring,
    assess_guardrail_deployment,
    assess_manifest_enforcement,
    assess_mcp_tool_registration,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
STATIC_DIR = REPO_ROOT / "agentscan" / "ui" / "static"
DEMO_AGENTS = REPO_ROOT / "tests" / "fixtures" / "demo-agents"


def _empty_sentinel() -> dict[str, Any]:
    return {
        "running": False,
        "target": None,
        "interval": 60,
        "canary_token": None,
        "webhook_url": None,
        "alerts": [],
    }


@pytest.fixture
def sentinel_state() -> Iterator[None]:
    previous = state.sentinel_status
    state.sentinel_status = _empty_sentinel()
    try:
        yield
    finally:
        state.sentinel_status = previous


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    from agentscan.ui.app import create_app

    previous = (state.report, state.report_path, state.identity_path)
    app = create_app(project_root=tmp_path)
    try:
        with TestClient(app) as instance:
            yield instance
    finally:
        state.report, state.report_path, state.identity_path = previous


# ── Sentinel: canary monitoring and leak labels ──────────────────────────────


def test_sentinel_status_without_evidence_is_not_assessed(
    client: TestClient, sentinel_state: None
) -> None:
    response = client.get("/api/sentinel/status")
    assert response.status_code == 200
    body = response.json()

    assert body["canary_monitoring"]["state"] == "not_deployed"
    assert body["canary_monitoring"]["label"] == NOT_DEPLOYED
    assert body["canary_leaks"]["state"] == "not_assessed"
    assert body["canary_leaks"]["label"] == NOT_ASSESSED
    assert body["probes_run"] == 0
    assert body["leaks_detected"] == 0

    # A clean-looking label must never appear before a probe has run.
    assert "ACTIVE" not in response.text
    assert "NO RECORDED FINDING" not in response.text.upper()


def test_sentinel_status_with_probe_evidence_reports_actual_outcome(
    client: TestClient, sentinel_state: None
) -> None:
    state.sentinel_status = {
        "running": True,
        "target": "http://127.0.0.1:9/chat",
        "interval": 30,
        "canary_token": "SYNTHETIC_CANARY_QA035_TOKEN",
        "webhook_url": None,
        "alerts": [
            {"status": "PASS", "findings_count": 0},
            {"status": "ALERT", "findings_count": 2},
        ],
    }

    body = client.get("/api/sentinel/status").json()
    assert body["canary_monitoring"]["state"] == "monitoring"
    assert body["canary_monitoring"]["label"] == "Monitoring"
    assert body["canary_leaks"]["state"] == "alert"
    assert body["canary_leaks"]["label"] == "Alert"
    assert body["probes_run"] == 2
    assert body["leaks_detected"] == 2


def test_sentinel_status_with_clean_probes_is_not_a_safety_claim(
    client: TestClient, sentinel_state: None
) -> None:
    state.sentinel_status = {
        "running": False,
        "target": "http://127.0.0.1:9/chat",
        "interval": 30,
        "canary_token": "SYNTHETIC_CANARY_QA035_TOKEN",
        "webhook_url": None,
        "alerts": [{"status": "PASS", "findings_count": 0}],
    }

    body = client.get("/api/sentinel/status").json()
    assert body["canary_monitoring"]["state"] == "inactive"
    assert body["canary_monitoring"]["label"] == "Configured - not running"
    assert body["canary_leaks"]["state"] == "clear"
    assert body["canary_leaks"]["label"] == "No leaks recorded"
    assert "SAFE" not in json.dumps(body)


def test_canary_assessment_helpers_are_evidence_driven() -> None:
    assert assess_canary_monitoring({})["state"] == "not_deployed"
    assert assess_canary_monitoring({"running": True})["label"] == "No canary token"
    assert assess_canary_leaks({})["state"] == "not_assessed"
    assert assess_canary_leaks({"alerts": [{"findings_count": 0}]})["state"] == "clear"


# ── Guardrails: export templates are not deployed controls ──────────────────


def test_guardrails_report_export_only_deployment(client: TestClient, sentinel_state: None) -> None:
    response = client.get("/api/guardrails")
    assert response.status_code == 200
    body = response.json()
    assert body["deployment_verified"] is False
    for key in ("litellm", "cloudflare", "bedrock"):
        assessment = body["deployment"][key]
        assert assessment["state"] == "export_only"
        assert assessment["label"] == "Exported - not deployed"
        assert assessment["evidence"]["deployment_verified"] is False

    payload = json.dumps(body)
    assert "ACTIVE" not in payload
    assert "ENFORCED" not in payload


@pytest.mark.parametrize("config", [None, "", {}, []])
def test_guardrail_without_export_is_not_deployed(config: Any) -> None:
    assessment = assess_guardrail_deployment(config)
    assert assessment["state"] == "not_deployed"
    assert assessment["label"] == NOT_DEPLOYED
    assert assessment["evidence"]["exported"] is False


# ── MCP: registered metadata is not readiness ───────────────────────────────


def test_mcp_tools_are_registered_not_ready(client: TestClient) -> None:
    response = client.get("/api/mcp")
    assert response.status_code == 200
    body = response.json()
    assert body["tool_status"]["state"] == "registered"
    assert body["tool_status"]["label"] == "Registered - not verified"
    assert body["tool_status"]["evidence"]["invocation_verified"] is False
    assert "READY" not in json.dumps(body)


def test_mcp_without_tool_metadata_is_unknown() -> None:
    assessment = assess_mcp_tool_registration({})
    assert assessment["state"] == "unknown"
    assert assessment["label"] == UNKNOWN


# ── RBAC / identity: declared policy is not enforced policy ─────────────────


def test_manifest_enforcement_without_role_policy_is_not_assessed() -> None:
    agent = AgentIdentity(
        agent_id="synthetic_agent",
        declared_role="unmapped_role",
        manifest_path="synthetic.agent.json",
    )
    assert assess_manifest_enforcement(agent, {})["label"] == NOT_ASSESSED
    assert assess_manifest_enforcement(agent, {"customer_support_agent": object()})["label"] == (
        NOT_ASSESSED
    )


def test_manifest_enforcement_with_matching_role_is_declared_not_verified() -> None:
    agent = AgentIdentity(
        agent_id="synthetic_agent",
        declared_role="customer_support_agent",
        manifest_path="synthetic.agent.json",
    )
    assessment = assess_manifest_enforcement(agent, {"customer_support_agent": object()})
    assert assessment["state"] == "declared"
    assert assessment["label"] == "Declared - not verified"
    assert assessment["evidence"]["enforcement_verified"] is False


def test_rbac_and_identity_expose_evidence_derived_enforcement(tmp_path: Path) -> None:
    from agentscan.ui.app import create_app

    previous = (state.report, state.report_path, state.identity_path)
    app = create_app(project_root=tmp_path, identity_path=DEMO_AGENTS)
    try:
        with TestClient(app) as instance:
            rbac_response = instance.get("/api/rbac")
            assert rbac_response.status_code == 200
            agent_nodes = [
                node for node in rbac_response.json()["nodes"] if node.get("node_type") == "agent"
            ]
            assert agent_nodes, "demo manifests should produce agent nodes"
            for node in agent_nodes:
                assert node["enforcement"]["state"] in {"declared", "not_assessed"}
                assert node["enforcement"]["label"] in {"Declared - not verified", NOT_ASSESSED}
            assert "ENFORCED" not in rbac_response.text

            identity_response = instance.get("/api/identity")
            assert identity_response.status_code == 200
            agents = identity_response.json()["agents"]
            assert agents
            for agent in agents:
                assert agent["enforcement"]["state"] in {"declared", "not_assessed"}
                assert agent["enforcement"]["label"] in {
                    "Declared - not verified",
                    NOT_ASSESSED,
                }
            assert "RBAC Enforced" not in identity_response.text
    finally:
        state.report, state.report_path, state.identity_path = previous


# ── Static dashboard shell / renderer ───────────────────────────────────────


def test_dashboard_sources_do_not_render_hardcoded_assurance_labels() -> None:
    renderers = (STATIC_DIR / "dashboard-app-renderers.js").read_text(encoding="utf-8")
    index = (STATIC_DIR / "index.html").read_text(encoding="utf-8")

    for literal in (
        ">ACTIVE</span>",
        ">ENFORCED</span>",
        ">READY</span>",
        ">RBAC Enforced</span>",
        "NO RECORDED FINDING",
        "3 TEAMS READY",
    ):
        assert literal not in renderers
        assert literal not in index

    # The renderer must consume the evidence-derived fields instead.
    for needle in (
        "snt.canary_monitoring",
        "snt.canary_leaks",
        "gw.deployment",
        "mcpData.tool_status",
        "n.enforcement",
        "a.enforcement",
        "swarm-teams-count",
    ):
        assert needle in renderers or needle in index, needle
