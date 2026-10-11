# agentscan/sandbox/base.py
#
# Base classes and result structures for sandboxed exploit verification.

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class SandboxResult:
    """
    Standardized execution telemetry from a sandboxed environment.

    Attributes
    ----------
    exit_code : int
        Process exit code (0 for success, non-zero for failure).
    stdout : str
        Standard output captured from the sandbox execution.
    stderr : str
        Standard error captured from the sandbox execution.
    filesystem_diff : list[dict[str, str]]
        List of filesystem modifications during execution, formatted as
        [{'kind': 'A'|'D'|'C', 'path': '...'}].
    oom_killed : bool
        Whether the container/process was killed due to out-of-memory.
    sandbox_tier : str
        The tier backend that executed the workload ("gvisor" | "docker" | "bwrap" | "subprocess").
    execution_ms : float
        Elapsed execution wall-clock time in milliseconds.
    """

    exit_code: int
    stdout: str
    stderr: str
    filesystem_diff: list[dict[str, str]] = field(default_factory=list)
    oom_killed: bool = False
    sandbox_tier: str = "subprocess"
    execution_ms: float = 0.0


class SandboxBase(ABC):
    """Abstract interface implemented by all sandbox isolation tiers."""

    @property
    @abstractmethod
    def tier_name(self) -> str:
        """Return the unique tier identifier name."""
        ...

    @abstractmethod
    def is_available(self) -> bool:
        """Check whether this sandbox tier is installed and functional on the host."""
        ...

    @abstractmethod
    def execute_in_sandbox(
        self,
        command: list[str],
        host_workspace: Path,
        network_disabled: bool = True,
        timeout: float = 30.0,
    ) -> SandboxResult:
        """
        Execute command inside the sandbox isolation boundary.

        Parameters
        ----------
        command : list[str]
            Argument vector of the command to execute.
        host_workspace : Path
            Host directory mounted as the target working directory.
        network_disabled : bool
            Whether network interfaces should be disabled (default True).
        timeout : float
            Maximum execution time in seconds before aborting.

        Returns
        -------
        SandboxResult
            Execution results and telemetry.
        """
        ...
