# tests/guard/test_command.py

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from agentscan.guard.command import CommandSecurityError, PosixCommandGuard


def test_whitelisted_binary_succeeds() -> None:
    """Verifies that an allowed binary executes cleanly and captures output."""
    guard = PosixCommandGuard(allowed_binaries=["git"])

    res = guard.sanitize_and_execute("git --version")
    assert res.returncode == 0
    assert "git version" in res.stdout.lower()


def test_non_whitelisted_binary_blocked() -> None:
    """Verifies that attempting to run a non-whitelisted binary raises CommandSecurityError."""
    guard = PosixCommandGuard(allowed_binaries=["git", "ls"])

    with pytest.raises(CommandSecurityError) as exc_info:
        guard.sanitize_and_execute("curl http://malicious.com")
    assert "Unauthorized binary execution: 'curl'" in str(exc_info.value)
    assert "Allowed binaries" in str(exc_info.value)


def test_pipe_injection_blocked() -> None:
    """Verifies that piping (| and ||) is intercepted and blocked."""
    guard = PosixCommandGuard(allowed_binaries=["git", "ls", "grep"])

    with pytest.raises(CommandSecurityError) as exc_info:
        guard.sanitize_and_execute("git status | grep main")
    assert "Disallowed shell metacharacter" in str(exc_info.value)

    with pytest.raises(CommandSecurityError) as exc_info:
        guard.sanitize_and_execute("git status || echo fail")
    assert "Disallowed shell metacharacter" in str(exc_info.value)


def test_command_chaining_semicolon_blocked() -> None:
    """Verifies that semicolon command chaining is intercepted and blocked."""
    guard = PosixCommandGuard(allowed_binaries=["git", "rm"])

    with pytest.raises(CommandSecurityError) as exc_info:
        guard.sanitize_and_execute("git status; rm -rf /")
    assert "Disallowed shell metacharacter" in str(exc_info.value)


def test_command_chaining_ampersand_blocked() -> None:
    """Verifies that ampersand command chaining (&&, &) is blocked."""
    guard = PosixCommandGuard(allowed_binaries=["git", "whoami"])

    with pytest.raises(CommandSecurityError) as exc_info:
        guard.sanitize_and_execute("git status && whoami")
    assert "Disallowed shell metacharacter" in str(exc_info.value)

    with pytest.raises(CommandSecurityError) as exc_info:
        guard.sanitize_and_execute("git status &")
    assert "Disallowed shell metacharacter" in str(exc_info.value)


def test_subshell_injection_blocked() -> None:
    """Verifies that subshell execution ($(), ``) is intercepted and blocked."""
    guard = PosixCommandGuard(allowed_binaries=["git", "echo"])

    with pytest.raises(CommandSecurityError) as exc_info:
        guard.sanitize_and_execute("git log $(whoami)")
    assert "Disallowed shell metacharacter" in str(exc_info.value)

    with pytest.raises(CommandSecurityError) as exc_info:
        guard.sanitize_and_execute("echo `whoami`")
    assert "Disallowed shell metacharacter" in str(exc_info.value)


def test_redirection_blocked() -> None:
    """Verifies that shell redirection (> and <) is blocked."""
    guard = PosixCommandGuard(allowed_binaries=["git"])

    with pytest.raises(CommandSecurityError) as exc_info:
        guard.sanitize_and_execute("git status > /tmp/output.txt")
    assert "Disallowed shell metacharacter" in str(exc_info.value)


def test_empty_command_rejected() -> None:
    """Verifies that empty or whitespace-only commands are rejected."""
    guard = PosixCommandGuard(allowed_binaries=["git"])

    with pytest.raises(CommandSecurityError) as exc_info:
        guard.sanitize_and_execute("")
    assert "Empty command rejected" in str(exc_info.value)

    with pytest.raises(CommandSecurityError) as exc_info:
        guard.sanitize_and_execute("    ")
    assert "Empty command rejected" in str(exc_info.value)


def test_malformed_command_string() -> None:
    """Verifies that malformed shell grammar (e.g. unclosed quotes) raises CommandSecurityError."""
    guard = PosixCommandGuard(allowed_binaries=["git"])

    with pytest.raises(CommandSecurityError) as exc_info:
        guard.sanitize_and_execute("git commit -m 'unclosed quote")
    assert "Malformed shell command string" in str(exc_info.value)


def test_cwd_and_timeout_forwarded(tmp_path: Path) -> None:
    """Verifies that cwd and timeout are passed to subprocess.run."""
    guard = PosixCommandGuard(allowed_binaries=["git"])

    with patch("subprocess.run") as mock_run:
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = "mocked"
        mock_run.return_value.stderr = ""

        res = guard.sanitize_and_execute(
            "git status",
            cwd=tmp_path,
            timeout=5.0,
        )
        assert res.returncode == 0
        mock_run.assert_called_once()
        _, kwargs = mock_run.call_args
        assert kwargs["cwd"] == str(tmp_path)
        assert kwargs["timeout"] == 5.0
        assert kwargs["shell"] is False
