# tests/test_remediation/test_self_healing.py
#
# Test suite for Automated Self-Healing, Unified Git Patching, and Webhook Ingestion.

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from agentscan.cli import app
from agentscan.remediation.models import FixAction, FixPlan
from agentscan.remediation.patch_generator import generate_github_pr_payload, generate_unified_patch
from agentscan.remediation.webhook_receiver import app as webhook_app

runner = CliRunner()
client = TestClient(webhook_app)


@pytest.fixture(autouse=True)
def webhook_configuration(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("AGENTSCAN_HEAL_TOKEN", "synthetic-test-token")
    monkeypatch.setenv("AGENTSCAN_HEAL_ROOT", str(tmp_path))
    monkeypatch.setenv("AGENTSCAN_HEAL_ALLOW_APPLY", "1")
    client.headers["Authorization"] = "Bearer synthetic-test-token"
    yield
    client.headers.pop("Authorization", None)


def test_generate_unified_patch_empty():
    plan = FixPlan(actions=[])
    patch = generate_unified_patch(plan)
    assert patch == ""


def test_generate_unified_patch_with_actions(tmp_path: Path):
    target_file = tmp_path / "app.py"
    target_file.write_text("import pickle\npickle.loads(data)\n", encoding="utf-8")

    action = FixAction(
        path=str(target_file),
        kind="ast_patch",
        finding_id="SC-011",
        before="import pickle\npickle.loads(data)\n",
        after="# Safe alternative\nimport json\njson.loads(data)\n",
    )
    plan = FixPlan(actions=[action])

    patch = generate_unified_patch(plan, base_dir=tmp_path)
    assert "--- a/app.py" in patch
    assert "+++ b/app.py" in patch
    assert "-import pickle" in patch
    assert "+# Safe alternative" in patch


def test_generate_github_pr_payload(tmp_path: Path):
    target_file = tmp_path / "model.py"
    action = FixAction(
        path=str(target_file),
        kind="ast_patch",
        finding_id="SC-012",
        before="torch.load('weights.pt')\n",
        after="torch.load('weights.pt', weights_only=True)\n",
    )
    plan = FixPlan(actions=[action])

    payload = generate_github_pr_payload(
        plan, branch_name="agentscan/fix-weights", base_branch="develop"
    )
    assert payload["head"] == "agentscan/fix-weights"
    assert payload["base"] == "develop"
    assert "AgentScan Self-Healing" in payload["title"]
    assert "SC-012" in payload["body"]
    assert "**Total Actions Planned**: 1" in payload["body"]


def test_webhook_health_endpoint():
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["service"] == "agentscan-self-healing"


def test_webhook_alert_validation(tmp_path: Path):
    # Missing findings
    resp = client.post("/webhook/alert", json={"target_repo": str(tmp_path)})
    assert resp.status_code == 400
    assert "No valid findings" in resp.json()["detail"]

    # Non-existent repository path
    fake_path = tmp_path / "non_existent_folder_xyz"
    resp = client.post(
        "/webhook/alert",
        json={
            "target_repo": str(fake_path),
            "finding_ids": ["SC-011"],
        },
    )
    assert resp.status_code == 403


def test_webhook_alert_planning_and_patch(tmp_path: Path):
    target_py = tmp_path / "agent.py"
    target_py.write_text("import torch\nweights = torch.load('model.pt')\n", encoding="utf-8")

    alert_data = {
        "source": "sentinel",
        "target_repo": str(tmp_path),
        "finding_ids": ["SC-011"],
        "branch_name": "fix/pickle-unsafe",
        "apply": False,
        "patch_out": str(tmp_path / "patch.diff"),
    }
    resp = client.post("/webhook/alert", json=alert_data)
    assert resp.status_code == 200
    body = resp.json()

    assert body["status"] == "remediation_planned"
    assert body["total_actions"] >= 1
    assert "patch" in body
    assert "--- a/agent.py" in body["patch"]

    # Verify patch file was created on disk
    patch_file = tmp_path / "patch.diff"
    assert patch_file.exists()
    assert "+weights = torch.load('model.pt', weights_only=True)" in patch_file.read_text(
        encoding="utf-8"
    )


def test_webhook_alert_apply_mode(tmp_path: Path):
    target_py = tmp_path / "agent.py"
    target_py.write_text("import torch\nweights = torch.load('model.pt')\n", encoding="utf-8")

    alert_data = {
        "source": "cloudflare",
        "target_repo": str(tmp_path),
        "finding_ids": ["SC-011"],
        "apply": True,
    }
    resp = client.post("/webhook/heal", json=alert_data)
    assert resp.status_code == 200
    body = resp.json()

    assert body["status"] == "remediation_applied"
    assert body["applied_count"] >= 1

    # Verify file was updated on disk
    content = target_py.read_text(encoding="utf-8")
    assert "weights_only=True" in content


def test_cli_heal_dry_run_and_patch(tmp_path: Path):
    target_py = tmp_path / "unsafe.py"
    target_py.write_text("import torch\nres = torch.load('model.pt')\n", encoding="utf-8")
    patch_path = tmp_path / "cli.patch"

    # Run heal in dry-run mode
    result = runner.invoke(app, ["heal", str(tmp_path), "--patch-out", str(patch_path)])
    assert result.exit_code == 0
    assert "DRY-RUN" in result.output
    assert "SC-011" in result.output
    assert patch_path.exists()
    assert "Unified git patch written to" in result.output

    # File should not be modified yet
    assert "weights_only=True" not in target_py.read_text(encoding="utf-8")


def test_cli_heal_apply(tmp_path: Path):
    target_py = tmp_path / "unsafe.py"
    target_py.write_text("import torch\nres = torch.load('model.pt')\n", encoding="utf-8")

    # Run heal with --apply
    result = runner.invoke(app, ["heal", str(tmp_path), "--apply"])
    assert result.exit_code == 0
    assert "APPLY" in result.output
    assert "Successfully applied" in result.output

    # File should now be patched
    assert "weights_only=True" in target_py.read_text(encoding="utf-8")
