# tests/sandbox/test_base.py

from __future__ import annotations

from agentscan.sandbox.base import SandboxResult


def test_sandbox_result_fields() -> None:
    """Verifies that SandboxResult dataclass has all required fields with proper defaults."""
    res = SandboxResult(
        exit_code=0,
        stdout="ok",
        stderr="",
        filesystem_diff=[{"kind": "A", "path": "file.txt"}],
        oom_killed=False,
        sandbox_tier="docker",
        execution_ms=12.5,
    )
    assert res.exit_code == 0
    assert res.stdout == "ok"
    assert res.stderr == ""
    assert res.filesystem_diff == [{"kind": "A", "path": "file.txt"}]
    assert res.oom_killed is False
    assert res.sandbox_tier == "docker"
    assert res.execution_ms == 12.5
