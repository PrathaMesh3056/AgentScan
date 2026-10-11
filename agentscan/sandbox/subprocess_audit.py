# agentscan/sandbox/subprocess_audit.py
#
# Fallback audit-mode sandbox using host subprocess execution and filesystem diffing.

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

from agentscan.guard.path import CanonicalPathGuard
from agentscan.sandbox.base import SandboxBase, SandboxResult

DUMMY_BLACK_HOLE_PROXY: str = "http://127.0.0.1:0"


class SubprocessAuditSandbox(SandboxBase):
    """
    Fallback execution tier providing audit mode and telemetry tracking without kernel isolation.

    Monitors execution time, stdout/stderr, and filesystem modifications within host_workspace.
    """

    def __init__(self, *, allow_host_execution: bool = False) -> None:
        self.allow_host_execution = allow_host_execution

    @property
    def tier_name(self) -> str:
        """Return the tier identifier."""
        return "subprocess"

    def is_available(self) -> bool:
        """Subprocess audit mode is always available on any host."""
        return True

    def execute_in_sandbox(
        self,
        command: list[str],
        host_workspace: Path,
        network_disabled: bool = True,
        timeout: float = 30.0,
    ) -> SandboxResult:
        """
        Execute command via host subprocess, capturing filesystem diffs and output.

        Parameters
        ----------
        command : list[str]
            Command line tokens to execute.
        host_workspace : Path
            Working directory for execution.
        network_disabled : bool
            Whether to enforce proxy-based egress blockage.
        timeout : float
            Execution timeout in seconds.

        Returns
        -------
        SandboxResult
            Execution results including computed filesystem diffs.
        """
        if not self.allow_host_execution:
            raise PermissionError("Host subprocess execution requires explicit opt-in")
        if network_disabled:
            raise PermissionError("Host subprocess mode cannot enforce network isolation")
        path_guard = CanonicalPathGuard(host_workspace)
        safe_workspace = path_guard.resolve_safe(host_workspace, must_exist=True)

        before_state = self._snapshot_workspace(safe_workspace)

        env = {
            name: value
            for name, value in os.environ.items()
            if name.upper() in {"PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "LANG"}
        }

        t0 = time.perf_counter()
        try:
            proc = subprocess.run(
                command,
                cwd=str(safe_workspace),
                env=env,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            exit_code = proc.returncode
            stdout = proc.stdout
            stderr = proc.stderr
        except subprocess.TimeoutExpired as exc:
            exit_code = 124
            stdout = exc.stdout or "" if isinstance(exc.stdout, str) else ""
            stderr = (
                exc.stderr or "" if isinstance(exc.stderr, str) else ""
            ) + f"\nTimeout ({timeout}s) expired."
        except Exception as err:
            exit_code = 1
            stdout = ""
            stderr = f"Subprocess execution error: {err}"

        execution_ms = (time.perf_counter() - t0) * 1000.0

        after_state = self._snapshot_workspace(safe_workspace)
        diff = self._compute_diff(before_state, after_state)

        return SandboxResult(
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            filesystem_diff=diff,
            oom_killed=False,
            sandbox_tier=self.tier_name,
            execution_ms=execution_ms,
        )

    def _snapshot_workspace(self, workspace: Path) -> dict[str, float]:
        """Record modification timestamps for all files currently in workspace."""
        snapshot: dict[str, float] = {}
        for path in workspace.rglob("*"):
            if path.is_file():
                try:
                    rel = path.relative_to(workspace).as_posix()
                    snapshot[rel] = path.stat().st_mtime
                except OSError:
                    continue
        return snapshot

    def _compute_diff(
        self,
        before: dict[str, float],
        after: dict[str, float],
    ) -> list[dict[str, str]]:
        """Compute Added ('A'), Modified ('C'), and Deleted ('D') files."""
        diff: list[dict[str, str]] = []

        # Check for added and modified files
        for rel_path, mtime in after.items():
            if rel_path not in before:
                diff.append({"kind": "A", "path": rel_path})
            elif mtime > before[rel_path]:
                diff.append({"kind": "C", "path": rel_path})

        # Check for deleted files
        for rel_path in before:
            if rel_path not in after:
                diff.append({"kind": "D", "path": rel_path})

        return diff
