# tests/test_remediation/test_secret_retention.py
#
# QA-037: secret fields leave the DOM once used and never land in status artifacts.

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agentscan.ui.app import create_app
from agentscan.ui.state import UiState, state

ROOT = Path(__file__).resolve().parents[2]
TOKEN = "SYNTHETIC_CANARY_REFERENCE_001"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.delenv("AGENTSCAN_UI_TOKEN", raising=False)
    monkeypatch.setattr(state, "active_scan", None)
    monkeypatch.setattr(state, "sentinel_task", None)
    monkeypatch.setattr(state, "report", None)
    monkeypatch.setattr(state, "sentinel_status", UiState().sentinel_status)
    (tmp_path / "example.py").write_text("print('example')\n", encoding="utf-8")
    with TestClient(create_app(project_root=tmp_path), base_url="http://127.0.0.1:8765") as value:
        value.get("/")
        yield value


@pytest.fixture
def idle_watcher(monkeypatch):
    async def run_loop(self, connector, callback=None):
        return None

    monkeypatch.setattr("agentscan.sentinel.watcher.ContinuousWatcher.run_loop", run_loop)


def test_sentinel_status_does_not_retain_operator_canary_token(client, idle_watcher, monkeypatch):
    published = []

    async def publish(event):
        published.append(event)

    monkeypatch.setattr("agentscan.ui.routers.sentinel.event_bus.publish", publish)
    response = client.post(
        "/api/sentinel/start",
        json={
            "target_url": "http://127.0.0.1:9/chat",
            "interval_seconds": 5,
            "canary_token": TOKEN,
        },
    )
    assert response.status_code == 200
    assert response.json()["canary_token"] == TOKEN

    status = client.get("/api/sentinel/status").json()

    assert status["canary_token_configured"] is True
    assert TOKEN not in json.dumps(status)
    assert TOKEN not in json.dumps(published)
    client.post("/api/sentinel/stop")


def test_sentinel_status_does_not_retain_generated_canary_token(client, idle_watcher):
    response = client.post(
        "/api/sentinel/start",
        json={"target_url": "http://127.0.0.1:9/chat", "interval_seconds": 5},
    )
    assert response.status_code == 200
    generated = response.json()["canary_token"]
    assert generated

    status = client.get("/api/sentinel/status").json()

    assert status["canary_token_configured"] is True
    assert generated not in json.dumps(status)
    client.post("/api/sentinel/stop")


def test_sentinel_status_without_a_token_reports_not_configured(client):
    status = client.get("/api/sentinel/status").json()

    assert status["canary_token_configured"] is False


def test_secret_fields_are_cleared_from_the_dom_once_used() -> None:
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is required to exercise the dashboard secret-field reset")
    script = r"""
    const assert = require('node:assert/strict');
    const forms = require('./agentscan/ui/static/form-validation.js');
    const inputs = {
      'cert-secret-key': { value: 'x'.repeat(40) },
      'scan-canary-token': { value: 'SYNTHETIC_CANARY_REFERENCE_001' },
      'scan-target-url': { value: 'http://127.0.0.1:9/chat' }
    };
    globalThis.document = { getElementById: id => inputs[id] || null };
    assert.equal(forms.clearSecretFields('certificate'), 1);
    assert.equal(inputs['cert-secret-key'].value, '');
    assert.ok(forms.clearSecretFields('scan') >= 1);
    assert.equal(inputs['scan-canary-token'].value, '');
    assert.equal(inputs['scan-target-url'].value, 'http://127.0.0.1:9/chat');
    """
    subprocess.run(
        [node, "-e", script], cwd=ROOT, check=True, capture_output=True, text=True, timeout=20
    )


def test_dashboard_flows_clear_secret_fields_and_send_no_duplicate_secret() -> None:
    actions = (ROOT / "agentscan/ui/static/dashboard-app-actions.js").read_text(encoding="utf-8")
    renderers = (ROOT / "agentscan/ui/static/dashboard-app-renderers.js").read_text(
        encoding="utf-8"
    )

    assert "clearSecretFields('scan')" in actions
    assert "clearSecretFields('certificate')" in renderers
    assert "payload.secret = secret" not in renderers
