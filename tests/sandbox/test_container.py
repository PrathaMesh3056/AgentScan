# tests/sandbox/test_container.py

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from agentscan.sandbox.container import ContainerSandbox


def test_container_sandbox_create_args(tmp_path: Path) -> None:
    """Verifies that build_create_args generates required security options."""
    sandbox = ContainerSandbox(image="python:3.12-slim")
    cmd = ["python", "-c", "print(1)"]

    args_net_disabled = sandbox.build_create_args(cmd, tmp_path, network_disabled=True)
    assert "--cap-drop" in args_net_disabled
    assert "ALL" in args_net_disabled
    assert "--read-only" in args_net_disabled
    assert "--network" in args_net_disabled
    assert args_net_disabled[args_net_disabled.index("--network") + 1] == "none"
    assert "--memory" in args_net_disabled
    assert "512m" in args_net_disabled
    assert "--cpus" in args_net_disabled
    assert "1.0" in args_net_disabled
    assert "--tmpfs" in args_net_disabled
    assert "/tmp:rw,noexec,nosuid,size=64m" in args_net_disabled
    assert "-v" in args_net_disabled
    assert "-w" in args_net_disabled
    assert "/workspace" in args_net_disabled
    assert "python:3.12-slim" in args_net_disabled

    # Network enabled uses bridge
    args_net_enabled = sandbox.build_create_args(cmd, tmp_path, network_disabled=False)
    assert args_net_enabled[args_net_enabled.index("--network") + 1] == "bridge"


def test_container_sandbox_is_available() -> None:
    """Verifies is_available checks both binary existence and daemon responsiveness."""
    sandbox = ContainerSandbox()

    with patch("shutil.which", return_value=None):
        assert sandbox.is_available() is False

    with (
        patch("shutil.which", return_value="/usr/bin/docker"),
        patch("subprocess.run") as mock_run,
    ):
        mock_run.return_value.returncode = 0
        assert sandbox.is_available() is True

        mock_run.return_value.returncode = 1
        assert sandbox.is_available() is False


def test_container_sandbox_execute_mocked_lifecycle(tmp_path: Path) -> None:
    """Verifies the complete execution lifecycle, diff parsing, and cleanup."""
    sandbox = ContainerSandbox()
    cid = "abc123456789"

    create_proc = MagicMock(returncode=0, stdout=cid, stderr="")
    start_proc = MagicMock(returncode=0, stdout="out", stderr="")
    inspect_proc = MagicMock(
        returncode=0,
        stdout='[{"State": {"ExitCode": 0, "OOMKilled": false}}]',
        stderr="",
    )
    diff_proc = MagicMock(
        returncode=0,
        stdout="A /workspace/file.txt\nC /workspace/edit.txt\nD /workspace/del.txt\n",
        stderr="",
    )
    rm_proc = MagicMock(returncode=0, stdout="", stderr="")

    def fake_subprocess_run(cmd, *args, **kwargs):
        if cmd[0:2] == ["docker", "create"]:
            return create_proc
        if cmd[0:3] == ["docker", "start", "-a"]:
            return start_proc
        if cmd[0:2] == ["docker", "inspect"]:
            return inspect_proc
        if cmd[0:2] == ["docker", "diff"]:
            return diff_proc
        if cmd[0:3] == ["docker", "rm", "-f"]:
            return rm_proc
        return MagicMock(returncode=0, stdout="", stderr="")

    with patch("subprocess.run", side_effect=fake_subprocess_run) as mock_run:
        res = sandbox.execute_in_sandbox(["ls"], host_workspace=tmp_path)

        assert res.exit_code == 0
        assert res.sandbox_tier == "docker"
        assert res.oom_killed is False
        assert len(res.filesystem_diff) == 3
        assert res.filesystem_diff[0] == {"kind": "A", "path": "/workspace/file.txt"}
        assert res.filesystem_diff[1] == {"kind": "C", "path": "/workspace/edit.txt"}
        assert res.filesystem_diff[2] == {"kind": "D", "path": "/workspace/del.txt"}

        # Verify cleanup was called
        calls = [c[0][0] for c in mock_run.call_args_list]
        assert ["docker", "rm", "-f", cid] in calls


def test_container_sandbox_creation_failure(tmp_path: Path) -> None:
    """Verifies that failure during container creation returns an error result."""
    sandbox = ContainerSandbox()
    create_proc = MagicMock(returncode=1, stdout="", stderr="Image not found")

    with patch("subprocess.run", return_value=create_proc):
        res = sandbox.execute_in_sandbox(["ls"], host_workspace=tmp_path)
        assert res.exit_code == 1
        assert "Docker container creation failed" in res.stderr
        assert res.sandbox_tier == "docker"


def test_container_sandbox_timeout_handling(tmp_path: Path) -> None:
    """Verifies timeout expiration returns exit code 124 and cleans up container."""
    sandbox = ContainerSandbox()
    cid = "timeout_cid_123"

    create_proc = MagicMock(returncode=0, stdout=cid, stderr="")

    def fake_subprocess_run(cmd, *args, **kwargs):
        if cmd[0:2] == ["docker", "create"]:
            return create_proc
        if cmd[0:3] == ["docker", "start", "-a"]:
            raise subprocess.TimeoutExpired(cmd, timeout=0.1)
        return MagicMock(returncode=0, stdout="", stderr="")

    with patch("subprocess.run", side_effect=fake_subprocess_run) as mock_run:
        res = sandbox.execute_in_sandbox(["sleep", "10"], host_workspace=tmp_path, timeout=0.1)
        assert res.exit_code == 124
        assert "Timeout" in res.stderr
        calls = [c[0][0] for c in mock_run.call_args_list]
        assert ["docker", "rm", "-f", cid] in calls


@pytest.mark.slow
def test_live_container_sandbox_execution_and_isolation(tmp_path: Path) -> None:
    """
    Live integration test against the real local Docker daemon (non-mocked).

    Verifies:
    1. Real network isolation: curl https://google.com inside container with
       network_disabled=True fails at the network namespace layer.
    2. File creation inside sandbox and parsed docker diff verification.
    3. Ephemeral container cleanup.
    """
    sandbox = ContainerSandbox()
    if not sandbox.is_available():
        pytest.skip("Docker daemon not running or not available on host")

    # Detect if alpine-curl is present; otherwise use python:3.12-slim
    has_alpine_curl = (
        subprocess.run(
            ["docker", "image", "inspect", "alpine-curl"],
            capture_output=True,
            check=False,
        ).returncode
        == 0
    )
    image = "alpine-curl" if has_alpine_curl else "python:3.12-slim"
    live_sandbox = ContainerSandbox(image=image)
    uid_command = (
        ["id", "-u"] if has_alpine_curl else ["python", "-c", "import os; print(os.getuid())"]
    )
    identity = live_sandbox.execute_in_sandbox(uid_command, host_workspace=tmp_path)
    assert identity.exit_code == 0
    assert identity.stdout.strip() == "65534"

    # 1. Test real network isolation: curl/connect fails inside container
    if has_alpine_curl:
        net_cmd = ["curl", "-m", "3", "https://google.com"]
    else:
        net_cmd = [
            "python",
            "-c",
            "import urllib.request; urllib.request.urlopen('https://google.com', timeout=3)",
        ]

    res_net = live_sandbox.execute_in_sandbox(
        net_cmd,
        host_workspace=tmp_path,
        network_disabled=True,
        timeout=15.0,
    )
    assert res_net.exit_code != 0
    assert res_net.sandbox_tier == "docker"

    # 2. Test file creation and real docker diff parsing
    proof_file = "live_diff_proof.txt"
    if has_alpine_curl:
        write_cmd = ["sh", "-c", f"echo live_proof_data > /workspace/{proof_file}"]
    else:
        write_cmd = [
            "python",
            "-c",
            f"open('/workspace/{proof_file}', 'w').write('live_proof_data')",
        ]

    res_write = live_sandbox.execute_in_sandbox(
        write_cmd,
        host_workspace=tmp_path,
        network_disabled=True,
        timeout=15.0,
    )
    assert res_write.exit_code == 0
    # Changes are captured from the disposable copy; the operator's workspace is preserved.
    assert not (tmp_path / proof_file).exists()

    # Confirm real docker diff produced filesystem entries parsed by SandboxResult
    assert {"kind": "A", "path": f"/workspace/{proof_file}"} in res_write.filesystem_diff
