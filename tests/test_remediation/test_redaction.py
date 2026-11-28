import json
from pathlib import Path

from typer.testing import CliRunner

from agentscan.cli import app

runner = CliRunner()


def _seed(tmp_path: Path) -> Path:
    target = tmp_path / "app.py"
    target.write_text(
        'OPENAI_API_KEY = "sk-synthetic-secret-1234567890"\n'
        'DB_SECRET = "db-super-secret"\n'
        "DEBUG = True\n",
        encoding="utf-8",
    )
    return tmp_path


SECRET_VALUES = ("sk-synthetic-secret-1234567890", "db-super-secret")


def test_fix_stdout_and_plan_redact_secrets(tmp_path: Path) -> None:
    root = _seed(tmp_path)
    plan_path = tmp_path / "plan.json"

    # (a) stdout diff must not contain raw secrets.
    result = runner.invoke(app, ["fix", str(root)])
    assert result.exit_code == 0, result.output
    for secret in SECRET_VALUES:
        assert secret not in result.output

    # Finding stays actionable: attack id and non-secret context remain.
    assert "SC-014" in result.output
    assert "DEBUG" in result.output

    # (b) --output plan JSON must not contain raw secrets.
    result = runner.invoke(app, ["fix", str(root), "--output", str(plan_path)])
    assert result.exit_code == 0, result.output
    assert plan_path.exists()
    plan_text = plan_path.read_text(encoding="utf-8")
    for secret in SECRET_VALUES:
        assert secret not in plan_text
    plan_data = json.loads(plan_text)
    assert plan_data.get("sensitive") is True
    assert any(a.get("finding_id") == "SC-014" for a in plan_data.get("actions", []))
    # Non-secret context preserved in the redacted artifact.
    assert "DEBUG" in plan_text


def test_heal_patch_out_redacts_secrets(tmp_path: Path) -> None:
    root = _seed(tmp_path)
    patch_path = tmp_path / "out.patch"

    result = runner.invoke(app, ["heal", str(root), "--patch-out", str(patch_path)])
    assert result.exit_code == 0, result.output
    assert patch_path.exists()
    patch_text = patch_path.read_text(encoding="utf-8")
    for secret in SECRET_VALUES:
        assert secret not in patch_text
    assert "DEBUG" in patch_text


def test_heal_webhook_response_redacts_secrets(tmp_path: Path, monkeypatch) -> None:
    from fastapi.testclient import TestClient

    _seed(tmp_path)
    monkeypatch.setenv("AGENTSCAN_HEAL_TOKEN", "synthetic-test-token")
    monkeypatch.setenv("AGENTSCAN_HEAL_ROOT", str(tmp_path))
    monkeypatch.setenv("AGENTSCAN_HEAL_ALLOW_APPLY", "1")

    from agentscan.remediation.webhook_receiver import app as webhook_app

    client = TestClient(webhook_app)
    client.headers["Authorization"] = "Bearer synthetic-test-token"
    response = client.post(
        "/webhook/alert",
        json={
            "source": "sentinel",
            "target_repo": ".",
            "finding_ids": ["SC-014"],
            "branch_name": "fix/redaction",
            "apply": False,
        },
    )
    assert response.status_code == 200, response.text
    body_text = response.text
    for secret in SECRET_VALUES:
        assert secret not in body_text
    body = response.json()
    assert body["pr_payload"]["metadata"].get("sensitive") is True
    assert body["total_actions"] >= 1
