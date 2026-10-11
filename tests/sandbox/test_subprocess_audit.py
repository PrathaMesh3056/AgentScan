# tests/sandbox/test_subprocess_audit.py

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from agentscan.sandbox.subprocess_audit import SubprocessAuditSandbox


def test_subprocess_audit_happy_path(tmp_path: Path) -> None:
    """Verifies that command executes and captures stdout/stderr and execution time."""
    sandbox = SubprocessAuditSandbox(allow_host_execution=True)
    assert sandbox.is_available() is True
    assert sandbox.tier_name == "subprocess"

    res = sandbox.execute_in_sandbox(
        [sys.executable, "-c", "print('hello_sandbox')"],
        host_workspace=tmp_path,
        network_disabled=False,
    )
    assert res.exit_code == 0
    assert "hello_sandbox" in res.stdout
    assert res.sandbox_tier == "subprocess"
    assert res.execution_ms > 0.0


def test_subprocess_audit_filesystem_diff_added(tmp_path: Path) -> None:
    """Verifies created files appear in filesystem_diff with kind 'A'."""
    sandbox = SubprocessAuditSandbox(allow_host_execution=True)

    # Command creates a new file in the workspace
    create_script = (
        "from pathlib import Path; Path('new_file.txt').write_text('payload', encoding='utf-8')"
    )
    res = sandbox.execute_in_sandbox(
        [sys.executable, "-c", create_script],
        host_workspace=tmp_path,
        network_disabled=False,
    )
    assert res.exit_code == 0
    added_entries = [d for d in res.filesystem_diff if d["kind"] == "A"]
    assert len(added_entries) == 1
    assert added_entries[0]["path"] == "new_file.txt"


def test_subprocess_audit_filesystem_diff_modified_and_deleted(tmp_path: Path) -> None:
    """Verifies modified files appear as 'C' and deleted files appear as 'D'."""
    sandbox = SubprocessAuditSandbox(allow_host_execution=True)

    existing_file = tmp_path / "target.txt"
    existing_file.write_text("initial", encoding="utf-8")

    # Modify file
    mod_script = "import time, os; time.sleep(0.01); open('target.txt', 'w').write('updated')"
    res_mod = sandbox.execute_in_sandbox(
        [sys.executable, "-c", mod_script],
        host_workspace=tmp_path,
        network_disabled=False,
    )
    assert any(d["kind"] == "C" and d["path"] == "target.txt" for d in res_mod.filesystem_diff)

    # Delete file
    del_script = "import os; os.remove('target.txt')"
    res_del = sandbox.execute_in_sandbox(
        [sys.executable, "-c", del_script],
        host_workspace=tmp_path,
        network_disabled=False,
    )
    assert any(d["kind"] == "D" and d["path"] == "target.txt" for d in res_del.filesystem_diff)


def test_subprocess_audit_network_isolation_fails(tmp_path: Path) -> None:
    sandbox = SubprocessAuditSandbox(allow_host_execution=True)
    with pytest.raises(PermissionError, match="cannot enforce network isolation"):
        sandbox.execute_in_sandbox([sys.executable, "-c", "print(1)"], tmp_path)


def test_subprocess_audit_timeout_expiration(tmp_path: Path) -> None:
    """Verifies command timeout expiration is handled cleanly with exit code 124."""
    sandbox = SubprocessAuditSandbox(allow_host_execution=True)

    sleep_script = "import time; time.sleep(5)"
    res = sandbox.execute_in_sandbox(
        [sys.executable, "-c", sleep_script],
        host_workspace=tmp_path,
        network_disabled=False,
        timeout=0.2,
    )
    assert res.exit_code == 124
    assert "Timeout" in res.stderr


def test_subprocess_audit_path_containment_violation(tmp_path: Path) -> None:
    """Verifies executing in a non-existent or escaping workspace raises PathSecurityError."""
    sandbox = SubprocessAuditSandbox(allow_host_execution=True)
    non_existent = tmp_path / "does_not_exist"

    with pytest.raises(FileNotFoundError):
        sandbox.execute_in_sandbox(
            ["echo", "hi"], host_workspace=non_existent, network_disabled=False
        )
