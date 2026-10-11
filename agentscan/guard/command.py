# agentscan/guard/command.py
#
# POSIX command execution parameterization engine and binary allowlist enforcement.

from __future__ import annotations

import re
import shlex
import shutil
import subprocess
from collections.abc import Sequence
from pathlib import Path

DEFAULT_COMMAND_TIMEOUT_SECONDS: float = 15.0

# Shell metacharacters, subshell invocations, and command-chaining operators
SHELL_INJECTION_PATTERN = re.compile(r"[;&|`$<>]|\b(exec|system|popen)\b")


class CommandSecurityError(PermissionError):
    """Raised when a command violates binary whitelisting or parameterization rules."""

    pass


class PosixCommandGuard:
    """
    Enforces strict command parameterization. Never invokes /bin/sh or cmd.exe.

    Neutralizes command chaining (; && ||), piping (|), subshell execution ($()),
    and rejects binaries not present in the explicit allowlist.
    """

    def __init__(self, allowed_binaries: Sequence[str]) -> None:
        """
        Initialize the PosixCommandGuard with an allowlist of permitted binary names.

        Parameters
        ----------
        allowed_binaries : Sequence[str]
            List of permitted executable binary names (e.g., ["git", "ls"]).
        """
        self.allowed_binaries: set[str] = set(allowed_binaries)
        # Resolve administrator-owned configuration once, before processing a request.
        # A caller's cwd or a later PATH change must not choose the executable.
        self._executables: dict[str, str] = {}
        for binary in allowed_binaries:
            configured = Path(binary)
            resolved = (
                str(configured.resolve()) if configured.is_absolute() else shutil.which(binary)
            )
            if resolved:
                self._executables[binary] = str(Path(resolved).resolve())

    def sanitize_command(self, command_line: str) -> list[str]:
        """
        Validates and parses a command string into a sanitized argument vector.

        Parameters
        ----------
        command_line : str
            Raw command line string to validate and tokenize.

        Returns
        -------
        list[str]
            Sanitized argument vector (argv) ready for execution.

        Raises
        ------
        CommandSecurityError
            If command contains shell metacharacters, is empty, or uses an unauthorized binary.
        """
        stripped = command_line.strip()
        if not stripped:
            raise CommandSecurityError("Empty command rejected.")

        # Detect shell metacharacters and chaining before execution
        match = SHELL_INJECTION_PATTERN.search(command_line)
        if match:
            raise CommandSecurityError(
                f"Disallowed shell metacharacter or command chaining detected: '{match.group(0)}' "
                f"in command '{command_line}'"
            )

        try:
            argv = shlex.split(stripped, posix=True)
        except ValueError as err:
            raise CommandSecurityError(f"Malformed shell command string: {err}") from err

        if not argv:
            raise CommandSecurityError("Empty command rejected.")

        return self.validate_argv(argv)

    def validate_argv(self, argv: Sequence[str]) -> list[str]:
        """Validate direct argv calls and replace the executable with its trusted path."""
        if not argv or not all(isinstance(arg, str) and "\x00" not in arg for arg in argv):
            raise CommandSecurityError("Empty or malformed command rejected.")
        binary = argv[0]
        trusted = self._executables.get(binary)
        if trusted is None and binary in self._executables.values():
            trusted = binary
        if trusted is None:
            raise CommandSecurityError(
                f"Unauthorized binary execution: '{binary}'. "
                f"Allowed binaries: {sorted(self.allowed_binaries)}"
            )
        if any(SHELL_INJECTION_PATTERN.search(arg) for arg in argv[1:]):
            raise CommandSecurityError("Disallowed shell metacharacter in command arguments")
        return [trusted, *argv[1:]]

    def execute(
        self,
        argv: list[str],
        cwd: str | Path | None = None,
        timeout: float = DEFAULT_COMMAND_TIMEOUT_SECONDS,
    ) -> subprocess.CompletedProcess[str]:
        """
        Executes a sanitized argument vector with shell=False.

        Parameters
        ----------
        argv : list[str]
            Tokenized argument vector.
        cwd : str | Path | None
            Working directory for execution.
        timeout : float
            Maximum execution time in seconds.

        Returns
        -------
        subprocess.CompletedProcess[str]
            Completed process execution results.
        """
        argv = self.validate_argv(argv)
        working_dir = str(cwd) if cwd is not None else None
        return subprocess.run(
            argv,
            shell=False,
            cwd=working_dir,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )

    def sanitize_and_execute(
        self,
        command_line: str,
        cwd: str | Path | None = None,
        timeout: float = DEFAULT_COMMAND_TIMEOUT_SECONDS,
    ) -> subprocess.CompletedProcess[str]:
        """
        Validates, tokenizes, and executes a command string safely without a shell.

        Parameters
        ----------
        command_line : str
            Raw command line string to sanitize and execute.
        cwd : str | Path | None
            Working directory for execution.
        timeout : float
            Maximum execution time in seconds.

        Returns
        -------
        subprocess.CompletedProcess[str]
            Completed process execution results.

        Raises
        ------
        CommandSecurityError
            If validation fails on unauthorized binary or shell injection.
        """
        argv = self.sanitize_command(command_line)
        return self.execute(argv, cwd=cwd, timeout=timeout)
