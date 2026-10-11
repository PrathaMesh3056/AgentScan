# agentscan/guard/path.py
#
# Canonical path resolution and filesystem containment firewall.

from __future__ import annotations

from pathlib import Path


class PathSecurityError(PermissionError):
    """Raised when an operation attempts to break filesystem containment."""

    pass


class CanonicalPathGuard:
    """
    Guarantees that file operations remain strictly within an allowed root.

    Defeats symlink escapes, parent directory traversal, and null-byte injection.
    """

    def __init__(self, allowed_root: str | Path) -> None:
        """
        Initialize the CanonicalPathGuard with an allowed root boundary.

        Parameters
        ----------
        allowed_root : str | Path
            The base directory serving as the containment root boundary.

        Raises
        ------
        FileNotFoundError
            If `allowed_root` does not exist on the filesystem.
        """
        self.allowed_root: Path = Path(allowed_root).resolve()
        if not self.allowed_root.exists():
            raise FileNotFoundError(
                f"Configured allowed_root does not exist: '{self.allowed_root}'"
            )

    def resolve_safe(self, requested_path: str | Path, must_exist: bool = False) -> Path:
        """
        Resolves `requested_path` to an absolute path within `self.allowed_root`.

        Parameters
        ----------
        requested_path : str | Path
            The raw path string or Path from untrusted input.
        must_exist : bool
            If True, raises FileNotFoundError if the path doesn't exist.

        Returns
        -------
        Path
            The resolved, contained absolute Path.

        Raises
        ------
        PathSecurityError
            If the resolved path escapes the allowed_root boundary.
        FileNotFoundError
            If must_exist is True and the target path does not exist.
        """
        clean_path = str(requested_path)
        if "\x00" in clean_path:
            raise PathSecurityError("Null bytes are not permitted in filesystem paths")
        target = Path(clean_path)

        if not target.is_absolute():
            target = self.allowed_root / target

        resolved_target = target.resolve(strict=must_exist)

        if not resolved_target.is_relative_to(self.allowed_root):
            raise PathSecurityError(
                f"Path containment violation: Target '{resolved_target}' "
                f"escapes containment boundary '{self.allowed_root}'"
            )

        return resolved_target
