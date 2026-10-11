from __future__ import annotations

import subprocess
import sys

import pytest

from agentscan.remediation.recovery import pending_transactions, recover_transaction


def test_process_exit_keeps_recoverable_preimages_and_preserves_later_edits(tmp_path):
    for name in ("a.py", "b.py"):
        (tmp_path / name).write_text("before\n", encoding="utf-8")
    script = """
import os, sys
from pathlib import Path
from agentscan.remediation.models import FixAction, FixPlan
root = Path(sys.argv[1])
actions = [FixAction(path=str(root / name), kind='ast_patch', finding_id='SC-011', before='before\\n', after='after\\n') for name in ('a.py','b.py')]
plan = FixPlan(actions=actions)
plan.bind_root(root)
original = os.replace
def interrupt(source, target):
    original(source, target)
    if Path(target).name == 'a.py':
        os._exit(73)
os.replace = interrupt
plan.apply()
"""
    result = subprocess.run(
        [sys.executable, "-c", script, str(tmp_path)], timeout=15, capture_output=True
    )
    assert result.returncode == 73, result.stderr.decode()
    journals = pending_transactions(tmp_path)
    assert len(journals) == 1
    assert (tmp_path / "a.py").read_text() == "after\n"
    assert (tmp_path / "b.py").read_text() == "before\n"
    assert len(list(tmp_path.glob(".agentscan-fix-*"))) == 1
    (tmp_path / "b.py").write_text("editor changed this\n", encoding="utf-8")
    with pytest.raises(ValueError, match="subsequent file changes"):
        recover_transaction(tmp_path, journals[0])
    assert (tmp_path / "a.py").read_text() == "after\n"  # Preflight prevented partial recovery.
    (tmp_path / "b.py").write_text("before\n", encoding="utf-8")
    assert recover_transaction(tmp_path, journals[0]) == 1
    assert all((tmp_path / name).read_text() == "before\n" for name in ("a.py", "b.py"))
    assert pending_transactions(tmp_path) == []
    assert not list(tmp_path.glob(".agentscan-fix-*"))
