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


def test_ui_vault_zip_download(sample_report: Path) -> None:
    import io
    import zipfile

    from fastapi.testclient import TestClient

    from agentscan.ui.app import create_app

    app = create_app(sample_report, Path("tests/fixtures/demo-agents"))
    client = TestClient(app)

    resp = client.get("/api/vault/zip")
    assert resp.status_code == 200
    assert "zip" in resp.headers.get("content-type", "")

    zf = zipfile.ZipFile(io.BytesIO(resp.content))
    names = zf.namelist()
    assert "report.json" in names
    assert "summary.md" in names
    assert any("findings/" in n for n in names)
    assert "remediation.patch" in names
    assert "guardrails/litellm.yaml" in names


def test_ui_custom_secret_key_certificate(sample_report: Path) -> None:
    from fastapi.testclient import TestClient

    from agentscan.ui.app import create_app

    app = create_app(sample_report, Path("tests/fixtures/demo-agents"))
    client = TestClient(app)

    custom_key = "test_custom_secret_key_98765"
    cert_resp = client.get(f"/api/certificate?secret_key={custom_key}")
    assert cert_resp.status_code == 200
    cert = cert_resp.json()

    valid_resp = client.post(
        "/api/verify-certificate",
        json={"certificate": cert, "secret_key": custom_key},
    )
    assert valid_resp.status_code == 200
    assert valid_resp.json()["valid"] is True

    # Test with mismatched secret key
    mismatched_resp = client.post(
        "/api/verify-certificate",
        json={"certificate": cert, "secret_key": "wrong_key_123"},
    )
    assert mismatched_resp.status_code == 200
    assert mismatched_resp.json()["valid"] is False


def test_ui_live_scan_controller_and_discovery(sample_report: Path, tmp_path: Path) -> None:
    from fastapi.testclient import TestClient

    from agentscan.ui.app import create_app

    app = create_app(sample_report, Path("tests/fixtures/demo-agents"))
    client = TestClient(app)

    # Test Scan Trigger
    scan_resp = client.post(
        "/api/scan",
        json={"target": "127.0.0.1:8765/chat", "mode": "FAST", "concurrency": 2},
    )
    assert scan_resp.status_code == 200
    assert "scan_id" in scan_resp.json()

    status_resp = client.get("/api/scan/status")
    assert status_resp.status_code == 200
    assert "status" in status_resp.json()

    cancel_resp = client.post("/api/scan/cancel")
    assert cancel_resp.status_code == 200
    assert cancel_resp.json()["status"] == "cancelled"

    # Test Discovery
    disc_resp = client.post(
        "/api/discovery",
        json={"target": "http://127.0.0.1:8765", "method": "OPTIONS"},
    )
    assert disc_resp.status_code == 200
    disc_data = disc_resp.json()
    assert "endpoints" in disc_data or "routes" in disc_data

    save_resp = client.post(
        "/api/discovery/save",
        json={"manifest": disc_data, "output_path": str(tmp_path / "discovered_agent.json")},
    )
    assert save_resp.status_code == 200


def test_ui_static_audit_and_supply_chain(sample_report: Path) -> None:
    from fastapi.testclient import TestClient

    from agentscan.ui.app import create_app

    app = create_app(sample_report, Path("tests/fixtures/demo-agents"))
    client = TestClient(app)

    # Static audit
    audit_resp = client.post("/api/audit", json={"path": "tests/fixtures/demo-agents"})
    assert audit_resp.status_code == 200
    audit_data = audit_resp.json()
    assert "findings" in audit_data

    # AIBOM
    aibom_resp = client.get("/api/aibom")
    assert aibom_resp.status_code == 200
    aibom_data = aibom_resp.json()
    assert aibom_data.get("bomFormat") == "CycloneDX"

    aibom_dl = client.get("/api/aibom/download")
    assert aibom_dl.status_code == 200
    assert "application/json" in aibom_dl.headers.get("content-type", "")

    # Dependency Graph
    dep_resp = client.get("/api/dependencies/graph")
    assert dep_resp.status_code == 200
    dep_data = dep_resp.json()
    assert "nodes" in dep_data or "packages" in dep_data


def test_ui_calibration_and_benchmarking(sample_report: Path) -> None:
    from fastapi.testclient import TestClient

    from agentscan.ui.app import create_app

    app = create_app(sample_report, Path("tests/fixtures/demo-agents"))
    client = TestClient(app)

    # Calibration
    cal_resp = client.post("/api/calibrate", json={"target": "http://127.0.0.1:8765", "probes": 3})
    assert cal_resp.status_code == 200
    cal_data = cal_resp.json()
    assert "baseline_latency_ms" in cal_data or "target" in cal_data

    # Benchmark
    bench_get = client.get("/api/benchmark")
    assert bench_get.status_code == 200
    assert "suites" in bench_get.json()

    bench_run = client.post("/api/benchmark/run", json={"suite": "AGENT_BENCH_V1", "rounds": 1})
    assert bench_run.status_code == 200
    bench_data = bench_run.json()
    assert "discrimination_score" in bench_data or "status" in bench_data


def test_ui_sentinel_mcp_and_swarms(sample_report: Path) -> None:
    from fastapi.testclient import TestClient

    from agentscan.ui.app import create_app

    app = create_app(sample_report, Path("tests/fixtures/demo-agents"))
    client = TestClient(app)

    # Sentinel
    snt_resp = client.get("/api/sentinel/status")
    assert snt_resp.status_code == 200
    assert "running" in snt_resp.json()

    probe_resp = client.post("/api/sentinel/probe")
    assert probe_resp.status_code == 200
    assert "status" in probe_resp.json()

    start_resp = client.post("/api/sentinel/start", json={"interval": 10})
    assert start_resp.status_code == 200
    assert start_resp.json()["running"] is True

    stop_resp = client.post("/api/sentinel/stop")
    assert stop_resp.status_code == 200
    assert stop_resp.json()["running"] is False

    # Native MCP
    mcp_resp = client.get("/api/mcp")
    assert mcp_resp.status_code == 200
    mcp_data = mcp_resp.json()
    assert mcp_data.get("status") == "ONLINE"
    assert len(mcp_data.get("tools", [])) >= 4

    invoke_resp = client.post(
        "/api/mcp/invoke", json={"tool": "agentscan_list_attacks", "arguments": {}}
    )
    assert invoke_resp.status_code == 200
    assert "result" in invoke_resp.json()

    # Swarms & Blackboard
    swarm_resp = client.post("/api/swarms/run", json={"strategy": "COLLABORATIVE", "max_rounds": 1})
    assert swarm_resp.status_code == 200

    bb_add = client.post(
        "/api/swarms/blackboard/add",
        json={"key": "test_credential", "value": "secret_abc", "discovered_by": "TestAgent"},
    )
    assert bb_add.status_code == 200

    bb_clear = client.post("/api/swarms/blackboard/clear")
    assert bb_clear.status_code == 200
    assert bb_clear.json()["items"] == []


def test_ui_self_healing_apply_and_server(sample_report: Path, tmp_path: Path) -> None:
    from fastapi.testclient import TestClient

    from agentscan.ui.app import create_app

    app = create_app(sample_report, Path("tests/fixtures/demo-agents"))
    client = TestClient(app)

    # Heal apply
    heal_resp = client.post("/api/heal/apply", json={"backup": True})
    assert heal_resp.status_code == 200
    assert "applied" in heal_resp.json()

    # Heal server status & simulate
    srv_resp = client.get("/api/heal/server/status")
    assert srv_resp.status_code == 200
    assert "status" in srv_resp.json()

    sim_resp = client.post(
        "/api/heal/server/simulate",
        json={
            "file": "tests/fixtures/sample_agent.py",
            "vulnerability_type": "PROMPT_INJECTION",
            "evidence": "Injected payload bypassed filter",
        },
    )
    assert sim_resp.status_code == 200
    assert "patch" in sim_resp.json()
