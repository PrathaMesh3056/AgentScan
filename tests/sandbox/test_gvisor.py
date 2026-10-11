# tests/sandbox/test_gvisor.py

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from agentscan.sandbox.container import ContainerSandbox
from agentscan.sandbox.gvisor import GVisorSandboxEngine


def test_gvisor_sandbox_args(tmp_path: Path) -> None:
    """Verifies that gVisor sandbox injects runtime runsc, nobody user, and pid limits."""
    engine = GVisorSandboxEngine()
    assert engine.tier_name == "gvisor"

    args = engine.build_create_args(["python", "app.py"], tmp_path, network_disabled=True)
    assert "--runtime" in args
    assert args[args.index("--runtime") + 1] == "runsc"
    assert "--user" in args
    assert args[args.index("--user") + 1] == "65534:65534"
    assert "--pids-limit" in args
    assert args[args.index("--pids-limit") + 1] == "64"
    assert "gcr.io/distroless/python3-debian12" in args


def test_gvisor_is_available_platform_checks() -> None:
    """Verifies platform constraints and binary checks for gVisor."""
    engine = GVisorSandboxEngine()

    with patch("sys.platform", "win32"):
        assert engine.is_available() is False

    with patch("sys.platform", "linux"):
        # Docker unavailable
        with patch.object(ContainerSandbox, "is_available", return_value=False):
            assert engine.is_available() is False

        # Docker available, runsc in PATH
        with patch.object(ContainerSandbox, "is_available", return_value=True):
            with patch("shutil.which", return_value="/usr/bin/runsc"):
                assert engine.is_available() is True

            # runsc not in PATH, but present in docker info
            with patch("shutil.which", return_value=None):
                mock_info = MagicMock(returncode=0, stdout="Runtimes: runsc runc")
                with patch("subprocess.run", return_value=mock_info):
                    assert engine.is_available() is True

                mock_info_no_runsc = MagicMock(returncode=0, stdout="Runtimes: runc")
                with patch("subprocess.run", return_value=mock_info_no_runsc):
                    assert engine.is_available() is False


def test_gvisor_execute_mocked(tmp_path: Path) -> None:
    """Verifies that executing via GVisorSandboxEngine produces sandbox_tier='gvisor'."""
    engine = GVisorSandboxEngine()

    create_proc = MagicMock(returncode=0, stdout="gvisor_cid_123", stderr="")
    start_proc = MagicMock(returncode=0, stdout="gvisor_output", stderr="")
    inspect_proc = MagicMock(
        returncode=0,
        stdout='[{"State": {"ExitCode": 0, "OOMKilled": false}}]',
        stderr="",
    )
    diff_proc = MagicMock(returncode=0, stdout="", stderr="")

    def fake_subprocess_run(cmd, *args, **kwargs):
        if cmd[0:2] == ["docker", "create"]:
            return create_proc
        if cmd[0:3] == ["docker", "start", "-a"]:
            return start_proc
        if cmd[0:2] == ["docker", "inspect"]:
            return inspect_proc
        if cmd[0:2] == ["docker", "diff"]:
            return diff_proc
        return MagicMock(returncode=0, stdout="", stderr="")

    with patch("subprocess.run", side_effect=fake_subprocess_run):
        res = engine.execute_in_sandbox(["ls"], host_workspace=tmp_path)
        assert res.exit_code == 0
        assert res.sandbox_tier == "gvisor"
