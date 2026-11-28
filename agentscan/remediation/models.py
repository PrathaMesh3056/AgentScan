# agentscan/remediation/models.py

from __future__ import annotations

import hashlib
import os
import stat
import tempfile
from pathlib import Path

from pydantic import BaseModel, Field, PrivateAttr

from agentscan.remediation.paths import contained_path


class FixConflictError(ValueError):
    """A file no longer matches the reviewed remediation preimage."""


class FixAction(BaseModel):
    """One planned file change produced by `agentscan fix`."""

    path: str = Field(..., description="Filesystem path of the file to change.")
    kind: str = Field(
        ...,
        description="pin_bump | ast_patch | identity_shrink | guardrails",
    )
    finding_id: str = Field(
        ...,
        description="Source finding attack_id (SC- / ID- / ATK-). No FIX-* prefix.",
    )
    before: str = Field(default="", description="File contents before the change.")
    after: str = Field(default="", description="File contents after the change.")
    applied: bool = Field(default=False, description="True only after a successful --apply write.")
    owasp_id: str = Field(default="", description="Source finding OWASP category.")


class FixPlan(BaseModel):
    """A collection of FixAction changes planned by the remediation engine."""

    actions: list[FixAction] = Field(
        default_factory=list,
        description="All planned remediation actions.",
    )
    sensitive: bool = Field(
        default=True,
        description="Remediation artifacts are sensitive and must be redacted.",
    )
    _root_path: Path | None = PrivateAttr(default=None)
    _expected_files: dict[str, str | None] = PrivateAttr(default_factory=dict)

    def bind_root(self, root_path: str | Path) -> None:
        """Bind execution to an operator-selected root; never deserialize this authority."""
        root = Path(root_path).resolve(strict=True)
        if self._root_path is not None and self._root_path != root:
            raise PermissionError("Cannot change the project root of a bound remediation plan")
        for action in self.actions:
            path = contained_path(root, action.path)
            if str(path) not in self._expected_files:
                self._expected_files[str(path)] = (
                    hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None
                )
        self._root_path = root

    @property
    def total_actions(self) -> int:
        return len(self.actions)

    @property
    def applied_count(self) -> int:
        return sum(1 for a in self.actions if a.applied)

    @property
    def paths_affected(self) -> list[str]:
        seen: set[str] = set()
        paths: list[str] = []
        for a in self.actions:
            if a.path not in seen:
                seen.add(a.path)
                paths.append(a.path)
        return paths

    def apply(self) -> int:
        """Preflight all changes, then atomically replace each file with rollback on failure."""
        pending = [action for action in self.actions if not action.applied]
        if not pending:
            return 0
        if self._root_path is None:
            raise PermissionError("Remediation plans must be bound to a trusted project root")

        originals: dict[Path, bytes | None] = {}
        final: dict[Path, str] = {}
        modes: dict[Path, int] = {}
        for action in pending:
            path = contained_path(self._root_path, action.path)
            if path not in originals:
                if path.exists() and not path.is_file():
                    raise FixConflictError(f"Remediation target is not a regular file: {path}")
                originals[path] = path.read_bytes() if path.exists() else None
                expected = self._expected_files.get(str(path))
                original = originals[path]
                actual = hashlib.sha256(original).hexdigest() if original is not None else None
                if actual != expected:
                    raise FixConflictError(f"File changed since remediation was planned: {path}")
                final[path] = path.read_text(encoding="utf-8") if path.exists() else ""
                if path.exists():
                    modes[path] = stat.S_IMODE(path.stat().st_mode)
            if final[path] != action.before:
                raise FixConflictError(f"File changed since remediation was planned: {path}")
            final[path] = action.after

        staged: dict[Path, Path] = {}
        replaced: list[Path] = []
        from agentscan.remediation.recovery import (
            begin_transaction,
            discard_transaction,
            transaction_staging_paths,
        )

        journal = begin_transaction(self._root_path, originals, final, modes)
        staged = transaction_staging_paths(self._root_path, journal)
        try:
            for path, content in final.items():
                path.parent.mkdir(parents=True, exist_ok=True)
                contained_path(self._root_path, path)
                temporary = staged[path]
                fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(content.encode("utf-8"))
                    stream.flush()
                    os.fsync(stream.fileno())
                if path in modes:
                    temporary.chmod(modes[path])
            for path, temporary in staged.items():
                contained_path(self._root_path, path)
                current = path.read_bytes() if path.exists() else None
                if current != originals[path]:
                    raise FixConflictError(f"File changed during remediation application: {path}")
                os.replace(temporary, path)
                replaced.append(path)
        except BaseException:
            for path in reversed(replaced):
                original = originals[path]
                if original is None:
                    contained_path(self._root_path, path)
                    if path.exists() and path.read_bytes() != final[path].encode("utf-8"):
                        raise FixConflictError(
                            f"Rollback conflicts with a subsequent edit; recovery receipt: {journal}"
                        ) from None
                    path.unlink(missing_ok=True)
                else:
                    contained_path(self._root_path, path)
                    if not path.exists() or path.read_bytes() != final[path].encode("utf-8"):
                        raise FixConflictError(
                            f"Rollback conflicts with a subsequent edit; recovery receipt: {journal}"
                        ) from None
                    fd, name = tempfile.mkstemp(prefix=".agentscan-rollback-", dir=path.parent)
                    backup = Path(name)
                    try:
                        with os.fdopen(fd, "wb") as stream:
                            stream.write(original)
                            stream.flush()
                            os.fsync(stream.fileno())
                        if path in modes:
                            backup.chmod(modes[path])
                        os.replace(backup, path)
                    finally:
                        backup.unlink(missing_ok=True)
            discard_transaction(self._root_path, journal)
            raise
        finally:
            for temporary in staged.values():
                temporary.unlink(missing_ok=True)
        for action in pending:
            action.applied = True
        discard_transaction(self._root_path, journal)
        return len(pending)
