# agentscan/sandbox/bwrap.py
#
# Linux Bubblewrap (bwrap) unprivileged user-namespace sandbox.

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from agentscan.guard.path import CanonicalPathGuard
from agentscan.sandbox.base import SandboxBase, SandboxResult
from agentscan.sandbox.workspace import content_diff, prepare_workspace, snapshot


class BubblewrapSandbox(SandboxBase):
    """
    Fast, unprivileged user-namespace container sandbox using Bubblewrap (bwrap).

    Available on Linux systems for unprivileged rootless isolation without Docker daemon.
    """

    @property
    def tier_name(self) -> str:
        """Return the tier identifier."""
        return "bwrap"

    def is_available(self) -> bool:
        """Check whether Bubblewrap is executable and running on Linux."""
        return sys.platform == "linux" and shutil.which("bwrap") is not None

    def build_bwrap_args(
        self,
        command: list[str],
        safe_workspace: Path,
        network_disabled: bool,
    ) -> list[str]:
        """Construct the argument vector for bwrap invocation."""
        bwrap_bin = shutil.which("bwrap") or "bwrap"
        args = [
            bwrap_bin,
            "--ro-bind",
            "/usr",
            "/usr",
            "--ro-bind",
            "/lib",
            "/lib",
            "--ro-bind",
            "/bin",
            "/bin",
        ]
        if Path("/lib64").exists():
            args.extend(["--ro-bind", "/lib64", "/lib64"])

        args.extend(
            [
                "--bind",
                str(safe_workspace),
                "/workspace",
                "--unshare-all",
            ]
        )
        if network_disabled:
            args.append("--unshare-net")

        args.extend(
            [
                "--new-session",
                "--die-with-parent",
                "--clearenv",
                "--setenv",
                "PATH",
                "/usr/bin:/bin",
                "--dir",
                "/tmp",
                "--chdir",
                "/workspace",
                "--",
            ]
        )
        args.extend(command)
        return args

    def execute_in_sandbox(
        self,
        command: list[str],
        host_workspace: Path,
        network_disabled: bool = True,
        timeout: float = 30.0,
    ) -> SandboxResult:
        """Execute command inside Bubblewrap sandbox."""
        if not self.is_available():
            return SandboxResult(
                exit_code=1,
                stdout="",
                stderr="Bubblewrap (bwrap) is not available or supported on this host.",
                filesystem_diff=[],
                oom_killed=False,
                sandbox_tier=self.tier_name,
                execution_ms=0.0,
            )

        path_guard = CanonicalPathGuard(host_workspace)
        safe_workspace = path_guard.resolve_safe(host_workspace, must_exist=True)
        disposable = tempfile.TemporaryDirectory(prefix="agentscan-bwrap-")
        copied_workspace = Path(disposable.name) / "workspace"
        try:
            prepare_workspace(safe_workspace, copied_workspace)
            before_state = snapshot(copied_workspace)
        except BaseException:
            disposable.cleanup()
            raise
        args = self.build_bwrap_args(command, copied_workspace, network_disabled)

        t0 = time.perf_counter()
        try:
            proc = subprocess.run(
                args,
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
            stderr = f"Bubblewrap execution error: {err}"

        execution_ms = (time.perf_counter() - t0) * 1000.0
        try:
            after_state = snapshot(copied_workspace)
            diff = content_diff(before_state, after_state)
        finally:
            disposable.cleanup()

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
        for rel_path, mtime in after.items():
            if rel_path not in before:
                diff.append({"kind": "A", "path": rel_path})
            elif mtime > before[rel_path]:
                diff.append({"kind": "C", "path": rel_path})
        for rel_path in before:
            if rel_path not in after:
                diff.append({"kind": "D", "path": rel_path})
        return diff
