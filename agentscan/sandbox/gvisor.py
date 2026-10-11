# agentscan/sandbox/gvisor.py
#
# gVisor kernel-isolated container execution engine (runsc).

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

from agentscan.sandbox.container import ContainerSandbox

DEFAULT_GVISOR_IMAGE: str = "gcr.io/distroless/python3-debian12"
GVISOR_USER_NOBODY: str = "65534:65534"
GVISOR_PIDS_LIMIT: str = "64"


class GVisorSandboxEngine(ContainerSandbox):
    """
    Hardened container sandbox leveraging Google's gVisor (runsc) application kernel.

    Intercepts syscalls at the user/kernel boundary, drops all capabilities,
    and enforces non-root execution (nobody:nogroup) with fork-bomb pid ceilings.
    """

    def __init__(self, image: str = DEFAULT_GVISOR_IMAGE) -> None:
        """
        Initialize the gVisor sandbox engine.

        Parameters
        ----------
        image : str
            Distroless or minimal container image configured for gVisor execution.
        """
        super().__init__(image=image)

    @property
    def tier_name(self) -> str:
        """Return the tier identifier."""
        return "gvisor"

    def is_available(self) -> bool:
        """
        Check whether gVisor runsc runtime is available and registered with Docker.

        Requires Linux host, Docker daemon running, and runsc runtime detected.
        """
        if sys.platform != "linux":
            return False

        if not super().is_available():
            return False

        if shutil.which("runsc") is not None:
            return True

        # Check Docker info for registered runsc runtime
        try:
            info = subprocess.run(
                ["docker", "info"],
                capture_output=True,
                text=True,
                timeout=3.0,
                check=False,
            )
            return "runsc" in info.stdout
        except (subprocess.SubprocessError, OSError):
            return False

    def build_create_args(
        self,
        command: list[str],
        safe_workspace: Path,
        network_disabled: bool,
    ) -> list[str]:
        """Build docker create arguments augmented with gVisor runsc security options."""
        base_args = super().build_create_args(command, safe_workspace, network_disabled)

        # Inject gVisor runtime parameters right after 'docker create'
        gvisor_flags = [
            "--runtime",
            "runsc",
            "--user",
            GVISOR_USER_NOBODY,
            "--pids-limit",
            GVISOR_PIDS_LIMIT,
        ]
        # base_args is ['docker', 'create', ...]
        return base_args[:2] + gvisor_flags + base_args[2:]
