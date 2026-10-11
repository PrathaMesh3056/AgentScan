# tests/sandbox/test_bwrap.py

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

from agentscan.sandbox.bwrap import BubblewrapSandbox


def test_bwrap_sandbox_args(tmp_path: Path) -> None:
    """Verifies that Bubblewrap builds proper unprivileged isolation arguments."""
    sandbox = BubblewrapSandbox()
    assert sandbox.tier_name == "bwrap"

    with patch("shutil.which", return_value="/usr/bin/bwrap"):
        args = sandbox.build_bwrap_args(["ls", "-la"], tmp_path, network_disabled=True)
        assert args[0] == "/usr/bin/bwrap"
        assert "--ro-bind" in args
        assert "--bind" in args
        assert str(tmp_path) in args
        assert "/workspace" in args
        assert "--unshare-all" in args
        assert "--unshare-net" in args
        assert "--chdir" in args
        assert "ls" in args
        assert "-la" in args


def test_bwrap_is_available() -> None:
    """Verifies that bwrap is only reported available on Linux with binary present."""
    sandbox = BubblewrapSandbox()

    with patch("sys.platform", "win32"):
        assert sandbox.is_available() is False

    with patch("sys.platform", "linux"):
        with patch("shutil.which", return_value=None):
            assert sandbox.is_available() is False
        with patch("shutil.which", return_value="/usr/bin/bwrap"):
            assert sandbox.is_available() is True


def test_bwrap_execute_mocked(tmp_path: Path) -> None:
    """Verifies execution flow through Bubblewrap."""
    sandbox = BubblewrapSandbox()
    mock_proc = MagicMock(returncode=0, stdout="bwrap_out", stderr="")

    with (
        patch.object(sandbox, "is_available", return_value=True),
        patch("subprocess.run", return_value=mock_proc),
    ):
        res = sandbox.execute_in_sandbox(["echo", "hi"], host_workspace=tmp_path)
        assert res.exit_code == 0
        assert res.stdout == "bwrap_out"
        assert res.sandbox_tier == "bwrap"


def test_bwrap_execute_timeout_and_exception(tmp_path: Path) -> None:
    """Verifies bwrap timeout expiration and generic exception handling."""
    sandbox = BubblewrapSandbox()

    with patch.object(sandbox, "is_available", return_value=True):
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(["bwrap"], timeout=0.1)):
            res = sandbox.execute_in_sandbox(["sleep", "10"], host_workspace=tmp_path, timeout=0.1)
            assert res.exit_code == 124
            assert "Timeout" in res.stderr

        with patch("subprocess.run", side_effect=RuntimeError("bwrap crashed")):
            res_err = sandbox.execute_in_sandbox(["crash"], host_workspace=tmp_path)
            assert res_err.exit_code == 1
            assert "Bubblewrap execution error" in res_err.stderr


def test_bwrap_unavailable_returns_error(tmp_path: Path) -> None:
    """Verifies executing when bwrap is unavailable returns an explicit error result."""
    sandbox = BubblewrapSandbox()
    with patch.object(sandbox, "is_available", return_value=False):
        res = sandbox.execute_in_sandbox(["echo", "hi"], host_workspace=tmp_path)
        assert res.exit_code == 1
        assert "not available" in res.stderr
