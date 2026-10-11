# agentscan/sandbox/container.py
#
# Docker container isolation tier with filesystem diff telemetry.

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from agentscan.guard.path import CanonicalPathGuard
from agentscan.sandbox.base import SandboxBase, SandboxResult
from agentscan.sandbox.workspace import content_diff, prepare_workspace, snapshot

DEFAULT_IMAGE: str = "python:3.12-slim"
DEFAULT_MEMORY_LIMIT: str = "512m"
DEFAULT_CPU_LIMIT: str = "1.0"
DEFAULT_TMPFS: str = "/tmp:rw,noexec,nosuid,size=64m"


class ContainerSandbox(SandboxBase):
    """
    Executes commands in an ephemeral, unprivileged Docker container sandbox.

    Enforces network isolation, capability stripping, readonly rootfs,
    and captures container inspect telemetry and filesystem diffs.
    """

    def __init__(self, image: str = DEFAULT_IMAGE) -> None:
        """
        Initialize the container sandbox.

        Parameters
        ----------
        image : str
            Base container image to execute commands against.
        """
        self.image: str = image

    @property
    def tier_name(self) -> str:
        """Return the tier identifier."""
        return "docker"

    def is_available(self) -> bool:
        """Check whether the Docker CLI is installed and the daemon is reachable."""
        if not shutil.which("docker"):
            return False
        try:
            res = subprocess.run(
                ["docker", "info"],
                capture_output=True,
                timeout=3.0,
                check=False,
            )
            return res.returncode == 0
        except (subprocess.SubprocessError, OSError):
            return False

    def build_create_args(
        self,
        command: list[str],
        safe_workspace: Path,
        network_disabled: bool,
    ) -> list[str]:
        """Build the argument vector for docker create."""
        # Convert path to absolute POSIX format suitable for volume binding
        mount_arg = f"{safe_workspace.resolve().as_posix()}:/workspace:rw"
        network_mode = "none" if network_disabled else "bridge"

        args = [
            "docker",
            "create",
            "--cap-drop",
            "ALL",
            "--user",
            "65534:65534",
            "--pids-limit",
            "64",
            "--read-only",
            "--network",
            network_mode,
            "--memory",
            DEFAULT_MEMORY_LIMIT,
            "--cpus",
            DEFAULT_CPU_LIMIT,
            "--security-opt",
            "no-new-privileges:true",
            "--tmpfs",
            DEFAULT_TMPFS,
            "-v",
            mount_arg,
            "-w",
            "/workspace",
            self.image,
        ]
        args.extend(command)
        return args

    def execute_in_sandbox(
        self,
        command: list[str],
        host_workspace: Path,
        network_disabled: bool = True,
        timeout: float = 30.0,
    ) -> SandboxResult:
        """Execute command in an ephemeral container with capability and network controls."""
        path_guard = CanonicalPathGuard(host_workspace)
        safe_workspace = path_guard.resolve_safe(host_workspace, must_exist=True)
        if not safe_workspace.is_dir():
            raise ValueError("Sandbox workspace must be a directory")
        disposable = tempfile.TemporaryDirectory(prefix="agentscan-sandbox-")
        copied_workspace = Path(disposable.name) / "workspace"
        try:
            prepare_workspace(safe_workspace, copied_workspace)
            before = snapshot(copied_workspace)
        except BaseException:
            disposable.cleanup()
            raise

        create_cmd = self.build_create_args(command, copied_workspace, network_disabled)
        t0 = time.perf_counter()

        cid: str | None = None
        exit_code = 1
        stdout = ""
        stderr = ""
        diff: list[dict[str, str]] = []
        oom_killed = False

        try:
            create_proc = subprocess.run(
                create_cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            if create_proc.returncode != 0:
                return SandboxResult(
                    exit_code=create_proc.returncode,
                    stdout="",
                    stderr=f"Docker container creation failed: {create_proc.stderr}",
                    filesystem_diff=[],
                    oom_killed=False,
                    sandbox_tier=self.tier_name,
                    execution_ms=(time.perf_counter() - t0) * 1000.0,
                )

            cid = create_proc.stdout.strip()

            # Start container and stream output
            start_proc = subprocess.run(
                ["docker", "start", "-a", cid],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            stdout = start_proc.stdout
            stderr = start_proc.stderr

            # Inspect exit code and OOM status
            inspect_proc = subprocess.run(
                ["docker", "inspect", cid],
                capture_output=True,
                text=True,
                timeout=min(timeout, 5.0),
                check=False,
            )
            if inspect_proc.returncode == 0:
                try:
                    data = json.loads(inspect_proc.stdout)
                    state = data[0].get("State", {})
                    exit_code = state.get("ExitCode", start_proc.returncode)
                    oom_killed = state.get("OOMKilled", False)
                except (json.JSONDecodeError, IndexError, KeyError):
                    exit_code = start_proc.returncode
            else:
                exit_code = start_proc.returncode

            # Fetch filesystem diff
            diff_proc = subprocess.run(
                ["docker", "diff", cid],
                capture_output=True,
                text=True,
                timeout=min(timeout, 5.0),
                check=False,
            )
            if diff_proc.returncode == 0:
                diff = self._parse_diff_output(diff_proc.stdout)

        except subprocess.TimeoutExpired as exc:
            exit_code = 124
            stdout = exc.stdout or "" if isinstance(exc.stdout, str) else ""
            stderr = (
                exc.stderr or "" if isinstance(exc.stderr, str) else ""
            ) + f"\nTimeout ({timeout}s) expired."
        except Exception as err:
            exit_code = 1
            stderr = f"Docker execution error: {err}"
        finally:
            if cid:
                try:
                    cleanup = subprocess.run(
                        ["docker", "rm", "-f", cid], capture_output=True, check=False, timeout=5.0
                    )
                    if cleanup.returncode:
                        exit_code = 1
                        stderr += "\nSandbox container cleanup failed."
                except (subprocess.SubprocessError, OSError):
                    exit_code = 1
                    stderr += "\nSandbox container cleanup failed."
            mutations = content_diff(before, snapshot(copied_workspace))
            diff.extend(entry for entry in mutations if entry not in diff)
            disposable.cleanup()

        execution_ms = (time.perf_counter() - t0) * 1000.0
        return SandboxResult(
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            filesystem_diff=diff,
            oom_killed=oom_killed,
            sandbox_tier=self.tier_name,
            execution_ms=execution_ms,
        )

    def _parse_diff_output(self, diff_text: str) -> list[dict[str, str]]:
        """Parse `docker diff` output into structured kind and path entries."""
        changes: list[dict[str, str]] = []
        for line in diff_text.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(maxsplit=1)
            if len(parts) == 2:
                kind, path = parts[0], parts[1]
                changes.append({"kind": kind, "path": path})
        return changes
