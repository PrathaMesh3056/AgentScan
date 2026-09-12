# tests/test_ui.py

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentscan.core.models import Finding, ScanMode, ScanReport, Severity, TurnRecord
from agentscan.identity.manifest_loader import load_manifests
from agentscan.identity.permission_mapper import load_dangerous_keywords, load_role_policies
from agentscan.identity.rbac_graph import build_rbac_graph, graph_to_view


def test_graph_to_view_has_nodes_and_edges() -> None:
    agents = load_manifests("tests/fixtures/demo-agents")
    graph = build_rbac_graph(agents, load_role_policies(), load_dangerous_keywords())
    view = graph_to_view(graph)
    assert view["nodes"]
    assert any(n.get("node_type") == "agent" for n in view["nodes"])


@pytest.fixture
def sample_report(tmp_path: Path) -> Path:
    report = ScanReport(
        target_url="http://agent.example/chat",
        scan_mode=ScanMode.SCAN,
        findings=[
            Finding(
                attack_id="ATK-001",
                attack_name="Direct Prompt Injection",
                severity=Severity.HIGH,
                owasp_id="LLM01",
                description="Target accepted a prompt injection payload.",
            )
        ],
        trajectory=[TurnRecord(turn=1, payload="hi", response="hello", tool_calls=["search"])],
    )
    report.complete(50, tests_run=1)
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report.to_dict()), encoding="utf-8")
    return path


def test_ui_api_serves_report_and_rbac(sample_report: Path) -> None:
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from agentscan.ui.app import create_app

    app = create_app(sample_report, Path("tests/fixtures/demo-agents"))
    client = TestClient(app)
    home = client.get("/")
    assert home.status_code == 200
    assert b"AgentScan" in home.content

    report = client.get("/api/report").json()
    assert report["target_url"] == "http://agent.example/chat"
    assert report["findings"][0]["attack_id"] == "ATK-001"

    traj = client.get("/api/trajectory").json()
    assert traj["turns"][0]["payload"] == "hi"

    rbac = client.get("/api/rbac").json()
    assert rbac["agent_count"] >= 1
    assert rbac["nodes"]
    assert "policies" in rbac
    assert "escalations" in rbac

    traffic = client.get("/api/traffic").json()
    assert "entries" in traffic

    attacks = client.get("/api/attacks").json()
    assert attacks["count"] >= 23
    assert any(a["attack_id"] == "ATK-001" for a in attacks["attacks"])
    assert any("SCAN" in a["modes"] or "scan" in a["modes"] for a in attacks["attacks"])

    guardrails = client.get("/api/guardrails").json()
    assert "litellm" in guardrails
    assert "cloudflare" in guardrails
    assert "bedrock" in guardrails
    assert "AgentScanDefenseGuardrail" in guardrails["bedrock"]

    swarms = client.get("/api/swarms").json()
    assert "teams" in swarms
    assert "trio" in swarms["teams"]
    assert "agency" in swarms["teams"]
    assert "stealth" in swarms["teams"]
    assert "blackboard" in swarms

    cert_resp = client.get("/api/certificate")
    assert cert_resp.status_code == 200
    cert = cert_resp.json()
    assert cert["algorithm"] == "HMAC-SHA256"
    assert "report_sha256" in cert

    verify_resp = client.post("/api/verify-certificate", json={"certificate": cert})
    assert verify_resp.status_code == 200
    assert verify_resp.json()["valid"] is True

    bad_verify = client.post(
        "/api/verify-certificate",
        json={"certificate": {**cert, "signature": "bad_sig_12345"}},
    )
    assert bad_verify.status_code == 200
    assert bad_verify.json()["valid"] is False


def test_ui_uvicorn_config_is_local_single_worker() -> None:
    pytest.importorskip("uvicorn")
    pytest.importorskip("fastapi")
    import uvicorn

    from agentscan.ui.app import build_uvicorn_config, create_app

    app = create_app()
    config = build_uvicorn_config(app)
    assert config.host == "127.0.0.1"
    assert config.port == 8765
    assert config.reload is False
    assert config.workers == 1
    server = uvicorn.Server(config)
    assert server.config is config
