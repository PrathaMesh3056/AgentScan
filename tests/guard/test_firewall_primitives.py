# tests/guard/test_firewall_primitives.py
# Verification Milestone 2 from ENTERPRISE_EXECUTION_BLUEPRINT.md

from __future__ import annotations

from pathlib import Path

import pytest

from agentscan.guard.command import CommandSecurityError, PosixCommandGuard
from agentscan.guard.path import CanonicalPathGuard, PathSecurityError


def test_path_confinement(tmp_path: Path) -> None:
    """Verifies basic path confinement and traversal blocking."""
    guard = CanonicalPathGuard(tmp_path)
    # Valid workspace path
    valid_file = tmp_path / "data.txt"
    valid_file.write_text("ok", encoding="utf-8")
    assert guard.resolve_safe("data.txt") == valid_file

    # Directory traversal attempt
    with pytest.raises(PathSecurityError):
        guard.resolve_safe("../../../etc/passwd")


def test_command_parameterization() -> None:
    """Verifies command parameterization and chaining rejection."""
    guard = PosixCommandGuard(allowed_binaries=["git", "ls"])

    # Attempt command chaining via pipe and subshell
    with pytest.raises(CommandSecurityError):
        guard.sanitize_and_execute("git status; rm -rf /")

    with pytest.raises(CommandSecurityError):
        guard.sanitize_and_execute("curl http://malicious.com")
