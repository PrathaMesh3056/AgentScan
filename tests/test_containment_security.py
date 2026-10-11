from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from pydantic import BaseModel, field_validator

from agentscan.core.models import Finding, Severity
from agentscan.guard.command import CommandSecurityError, PosixCommandGuard
from agentscan.guard.firewall import CapabilityGuard
from agentscan.guard.mcp_proxy import MCPCapabilityProxy
from agentscan.guard.path import PathSecurityError
from agentscan.remediation.engine import RemediationEngine
from agentscan.remediation.models import FixAction, FixConflictError, FixPlan
from agentscan.remediation.webhook_receiver import app as webhook_app
from agentscan.sandbox.container import ContainerSandbox
from agentscan.sandbox.selector import SandboxUnavailableError, select_sandbox
from agentscan.sandbox.subprocess_audit import SubprocessAuditSandbox
from agentscan.ui.app import create_app


def debug_finding(path: Path) -> Finding:
    return Finding(
        attack_id="SC-014",
        attack_name="Debug configuration",
        severity=Severity.HIGH,
        owasp_id="LLM05",
        description="Debug enabled",
        metadata={"file": str(path)},
    )


def action(path: Path, before: str, after: str) -> FixAction:
    return FixAction(
        path=str(path), kind="ast_patch", finding_id="SC-014", before=before, after=after
    )


@pytest.mark.parametrize("argv", [["/attacker/bin/git", "status"], ["unapproved", "anything"]])
def test_direct_command_execution_cannot_bypass_executable_policy(argv: list[str]) -> None:
    guard = PosixCommandGuard(["git"])
    with patch("subprocess.run") as launch, pytest.raises(CommandSecurityError):
        guard.execute(argv)
    launch.assert_not_called()


def test_command_uses_preconfigured_absolute_executable(tmp_path: Path) -> None:
    guard = PosixCommandGuard(["git"])
    with patch("subprocess.run") as launch:
        guard.execute(["git", "status"], cwd=tmp_path)
    executable = Path(launch.call_args.args[0][0])
    assert executable.is_absolute()
    assert executable.parent != tmp_path


@pytest.mark.parametrize(
    "value", [{"config": {"path": "../outside.txt"}}, {"files": ["local.txt", "../outside.txt"]}]
)
def test_nested_tool_parameters_are_confined(tmp_path: Path, value: dict) -> None:
    result = CapabilityGuard(allowed_root=tmp_path).inspect_parameters(value)
    assert result is not None
    assert json.loads(result)["type"] == "path_confinement_error"


def test_tool_executes_normalized_schema_values_and_canonical_paths(tmp_path: Path) -> None:
    class Schema(BaseModel):
        file_path: str
        count: int

        @field_validator("file_path")
        @classmethod
        def clean_path(cls, value: str) -> str:
            return value.strip()

    (tmp_path / "item.txt").write_text("owned", encoding="utf-8")
    guard = CapabilityGuard(allowed_root=tmp_path)

    @guard.protect_tool(schema_model=Schema)
    def read(file_path: str, count: int) -> tuple[str, int]:
        return Path(file_path).read_text(encoding="utf-8"), count

    assert read(" item.txt ", "2") == ("owned", 2)


def test_cyclic_tool_arguments_fail_closed() -> None:
    cycle: dict = {}
    cycle["self"] = cycle
    error = CapabilityGuard().inspect_parameters(cycle)
    assert json.loads(error)["type"] == "argument_structure_error"


@pytest.mark.parametrize("domains", [[], ["allowed.example"]])
def test_mcp_enforces_nested_network_domain_policy(tmp_path: Path, domains: list[str]) -> None:
    proxy = MCPCapabilityProxy(tmp_path, allowed_domains=domains)
    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"arguments": {"config": {"url": "https://denied.example/data"}}},
    }
    result = proxy.process_request(json.dumps(request))
    assert json.loads(result)["result"]["isError"] is True
    request["params"]["arguments"]["config"]["url"] = "https://allowed.example/data"
    assert (proxy.process_request(json.dumps(request)) is None) == bool(domains)


def test_planning_rejects_sibling_metadata_path_before_read(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    sibling = tmp_path / "root-other.py"
    sibling.write_text("DEBUG=True\n", encoding="utf-8")
    with pytest.raises(PathSecurityError):
        RemediationEngine(root).plan([debug_finding(sibling)])
    assert sibling.read_text(encoding="utf-8") == "DEBUG=True\n"


def test_stale_multi_file_plan_changes_nothing(tmp_path: Path) -> None:
    first, second = tmp_path / "first.py", tmp_path / "second.py"
    first.write_text("first", encoding="utf-8")
    second.write_text("second", encoding="utf-8")
    plan = FixPlan(actions=[action(first, "first", "fixed"), action(second, "second", "fixed")])
    plan.bind_root(tmp_path)
    second.write_text("user edit", encoding="utf-8")
    with pytest.raises(FixConflictError):
        plan.apply()
    assert first.read_text() == "first"
    assert second.read_text() == "user edit"
    assert plan.applied_count == 0


def test_plan_rejects_new_file_that_appeared_after_review(tmp_path: Path) -> None:
    destination = tmp_path / "new.txt"
    plan = FixPlan(actions=[action(destination, "", "generated")])
    plan.bind_root(tmp_path)
    destination.write_text("", encoding="utf-8")
    with pytest.raises(FixConflictError):
        plan.apply()
    assert destination.read_text() == ""


def test_atomic_replacement_failure_rolls_back_prior_files(tmp_path: Path) -> None:
    first, second = tmp_path / "a.txt", tmp_path / "b.txt"
    first.write_text("a", encoding="utf-8")
    second.write_text("b", encoding="utf-8")
    plan = FixPlan(actions=[action(first, "a", "new a"), action(second, "b", "new b")])
    plan.bind_root(tmp_path)
    original_replace = os.replace
    calls = 0

    def fail_second(source, destination):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("Synthetic write failure")
        return original_replace(source, destination)

    with patch("os.replace", side_effect=fail_second), pytest.raises(OSError):
        plan.apply()
    assert (first.read_text(), second.read_text()) == ("a", "b")
    assert plan.applied_count == 0
    assert not list(tmp_path.glob(".agentscan-*"))


def test_chained_actions_for_one_file_commit_once(tmp_path: Path) -> None:
    path = tmp_path / "requirements.txt"
    path.write_text("old", encoding="utf-8")
    plan = FixPlan(actions=[action(path, "old", "middle"), action(path, "middle", "final")])
    plan.bind_root(tmp_path)
    assert plan.apply() == 2
    assert path.read_text() == "final"
    assert plan.apply() == 0


def test_unbound_plan_cannot_write(tmp_path: Path) -> None:
    plan = FixPlan(actions=[action(tmp_path / "file", "", "unsafe")])
    with pytest.raises(PermissionError, match="trusted project root"):
        plan.apply()


def test_webhook_rejects_unauthorized_and_out_of_root_writes(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "project"
    root.mkdir()
    file = root / "agent.py"
    file.write_text("DEBUG=True\n", encoding="utf-8")
    monkeypatch.setenv("AGENTSCAN_HEAL_TOKEN", "synthetic-webhook-token")
    monkeypatch.setenv("AGENTSCAN_HEAL_ROOT", str(root))
    monkeypatch.delenv("AGENTSCAN_HEAL_ALLOW_APPLY", raising=False)
    client = TestClient(webhook_app)
    payload = {"finding_ids": ["SC-014"], "apply": True}
    assert client.post("/webhook/alert", json=payload).status_code == 401
    client.headers["Authorization"] = "Bearer synthetic-webhook-token"
    assert client.post("/webhook/alert", json=payload).status_code == 403
    monkeypatch.setenv("AGENTSCAN_HEAL_ALLOW_APPLY", "1")
    assert (
        client.post("/webhook/alert", json={**payload, "target_repo": str(tmp_path)}).status_code
        == 403
    )
    assert (
        client.post(
            "/webhook/alert", json={**payload, "patch_out": str(tmp_path / "outside.patch")}
        ).status_code
        == 403
    )
    assert file.read_text() == "DEBUG=True\n"
    assert not (tmp_path / "outside.patch").exists()


@pytest.mark.parametrize(
    "headers",
    [
        {"Host": "dashboard.attacker.example"},
        {"Origin": "http://attacker.example"},
        {"Sec-Fetch-Site": "cross-site"},
    ],
)
def test_dashboard_rejects_browser_origin_and_host_attacks(tmp_path: Path, headers: dict) -> None:
    client = TestClient(create_app(project_root=tmp_path))
    client.get("/")
    response = client.post("/api/scan/cancel", headers=headers)
    assert response.status_code == 403


def test_dashboard_requires_mutation_session_and_token_bootstrap_works(tmp_path: Path) -> None:
    client = TestClient(create_app(token="synthetic-ui-token", project_root=tmp_path))
    assert client.post("/api/scan/cancel").status_code == 401
    response = client.get("/?token=synthetic-ui-token", follow_redirects=False)
    assert response.status_code == 303
    assert "token=" not in response.headers["location"]
    assert "HttpOnly" in response.headers["set-cookie"]
    assert "SameSite=lax" in response.headers["set-cookie"]
    assert client.get("/api/attacks").status_code == 200
    assert client.get("/api/events?limit=1").status_code == 200
    assert (
        client.post("/api/scan/cancel", headers={"Origin": "http://testserver"}).status_code == 200
    )


def test_dashboard_rejects_root_override_and_profile_overwrite(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    client = TestClient(create_app(project_root=root))
    client.get("/")
    assert client.post("/api/heal/apply", json={"root_path": str(tmp_path)}).status_code == 403
    assert (
        client.post(
            "/api/discovery/save",
            json={
                "profile": {"url": "http://owned"},
                "output_path": str(tmp_path / "project-other.yaml"),
            },
        ).status_code
        == 403
    )
    data = {"profile": {"url": "http://owned"}, "output_path": "target.yaml"}
    assert client.post("/api/discovery/save", json=data).status_code == 200
    assert client.post("/api/discovery/save", json=data).status_code == 409
    assert (root / ".agentscan/profiles/target.yaml").exists()


def test_requested_sandbox_cannot_silently_downgrade() -> None:
    with (
        patch.object(ContainerSandbox, "is_available", return_value=False),
        pytest.raises(SandboxUnavailableError),
    ):
        select_sandbox("docker")
    with pytest.raises(SandboxUnavailableError):
        select_sandbox("dockre")


def test_host_subprocess_requires_explicit_consent(tmp_path: Path) -> None:
    with pytest.raises(PermissionError, match="explicit opt-in"):
        SubprocessAuditSandbox().execute_in_sandbox(
            ["never-launched"], tmp_path, network_disabled=False
        )


def test_container_mounts_disposable_copy_and_reports_real_file_diff(tmp_path: Path) -> None:
    source = tmp_path / "input.txt"
    source.write_text("original", encoding="utf-8")
    (tmp_path / ".env").write_text("SYNTHETIC_SECRET=fixture", encoding="utf-8")
    mounted: Path | None = None

    def docker_run(argv, **kwargs):
        nonlocal mounted
        import subprocess

        if argv[:2] == ["docker", "create"]:
            mounted = Path(argv[argv.index("-v") + 1].removesuffix(":/workspace:rw"))
            assert mounted != tmp_path
            assert not (mounted / ".env").exists()
            assert argv[argv.index("--user") + 1] == "65534:65534"
            assert argv[argv.index("--pids-limit") + 1] == "64"
            return subprocess.CompletedProcess(argv, 0, "fixture-cid", "")
        if argv[:3] == ["docker", "start", "-a"]:
            (mounted / "input.txt").write_text("changed", encoding="utf-8")
        output = (
            '[{"State":{"ExitCode":0,"OOMKilled":false}}]'
            if argv[:2] == ["docker", "inspect"]
            else ""
        )
        return subprocess.CompletedProcess(argv, 0, output, "")

    with patch("subprocess.run", side_effect=docker_run):
        result = ContainerSandbox().execute_in_sandbox(["owned-fixture"], tmp_path)
    assert source.read_text() == "original"
    assert {"kind": "C", "path": "/workspace/input.txt"} in result.filesystem_diff
    assert not mounted.exists()


def test_sandbox_copy_excludes_sensitive_recovery_backups_and_staging(tmp_path):
    from agentscan.sandbox.workspace import prepare_workspace

    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("print('ordinary input')")
    backups = source / ".agentscan-recovery" / "synthetic-transaction"
    backups.mkdir(parents=True)
    (backups / "0.before").write_text("synthetic sensitive preimage")
    for prefix in (".agentscan-fix-", ".agentscan-rollback-", ".agentscan-recover-"):
        (source / (prefix + "synthetic")).write_text("synthetic sensitive staged content")
    destination = tmp_path / "isolated"
    prepare_workspace(source, destination)
    assert sorted(p.name for p in destination.iterdir()) == ["app.py"]
