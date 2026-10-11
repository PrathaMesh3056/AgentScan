"""Durable local recovery receipts for file edits; never reset a Git repository."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import uuid
from pathlib import Path

from agentscan.remediation.paths import contained_path


def digest(data: bytes | None) -> str | None:
    return hashlib.sha256(data).hexdigest() if data is not None else None


def pending_transactions(root: Path) -> list[Path]:
    directory = root / ".agentscan-recovery"
    if not directory.exists():
        return []
    contained_path(root, directory)
    return sorted(directory.glob("*/journal.json"))


def begin_transaction(
    root: Path, originals: dict[Path, bytes | None], final: dict[Path, str], modes: dict[Path, int]
) -> Path:
    root = root if root.is_dir() else root.parent
    if pending_transactions(root):
        raise RuntimeError(
            "An unfinished remediation transaction requires review under .agentscan-recovery."
        )
    directory = root / ".agentscan-recovery" / uuid.uuid4().hex
    contained_path(root, directory)
    directory.mkdir(parents=True, mode=0o700)
    entries = []
    for index, (path, data) in enumerate(originals.items()):
        backup = directory / f"{index}.before"
        if data is not None:
            with backup.open("xb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            backup.chmod(0o600)
        entries.append(
            {
                "path": str(path.relative_to(root)),
                "before": digest(data),
                "after": digest(final[path].encode()),
                "backup": backup.name,
                "stage": str(
                    (path.parent / f".agentscan-fix-{directory.name}-{index}").relative_to(root)
                ),
                "mode": modes.get(path, 0o600),
            }
        )
    journal = directory / "journal.json"
    with journal.open("x", encoding="utf-8") as stream:
        json.dump({"version": 1, "root": str(root), "entries": entries}, stream)
        stream.flush()
        os.fsync(stream.fileno())
    journal.chmod(0o600)
    return journal


def transaction_staging_paths(root: Path, journal: Path) -> dict[Path, Path]:
    """Allocate no files until their exact owned paths have been durably recorded."""
    root = root if root.is_dir() else root.parent
    data = json.loads(journal.read_text(encoding="utf-8"))
    return {
        contained_path(root, entry["path"]): contained_path(root, entry["stage"])
        for entry in data["entries"]
    }


def discard_transaction(root: Path, journal: Path) -> None:
    root = root if root.is_dir() else root.parent
    path = contained_path(root, journal)
    base = (root / ".agentscan-recovery").resolve()
    if path.name != "journal.json" or path.parent.parent != base or len(path.parent.name) != 32:
        raise PermissionError("Invalid recovery transaction location")
    # Only this transaction directory, containing our reviewed backup artifacts.
    shutil.rmtree(path.parent)
    if not any(base.iterdir()):
        base.rmdir()


def recover_transaction(root_path: str | Path, journal_path: str | Path) -> int:
    """Restore a reviewed transaction only if each file matches its pre/post image.

    Preflight every target before editing. Preserve receipts on any conflict or
    recovery failure; never overwrite changes made by another editor.
    """
    root = Path(root_path).resolve(strict=True)
    root = root if root.is_dir() else root.parent
    journal = contained_path(root, journal_path)
    if journal not in pending_transactions(root):
        raise PermissionError("Recovery requires a transaction inside the selected project")
    data = json.loads(journal.read_text(encoding="utf-8"))
    if data.get("version") != 1 or data.get("root") != str(root):
        raise ValueError("Recovery receipt belongs to a different project or format")
    changes = []
    stages: list[Path] = []
    for entry in data["entries"]:
        path = contained_path(root, entry["path"])
        backup = contained_path(journal.parent, entry["backup"])
        original = backup.read_bytes() if entry["before"] is not None else None
        if digest(original) != entry["before"]:
            raise ValueError("Recovery backup does not match its recorded preimage")
        current = path.read_bytes() if path.exists() else None
        if digest(current) not in {entry["before"], entry["after"]}:
            raise ValueError(
                "Recovery conflicts with subsequent file changes; preserve and review the receipt"
            )
        if digest(current) == entry["after"]:
            changes.append((path, original, current, entry["mode"]))
        if entry.get("stage"):
            stage = contained_path(root, entry["stage"])
            if stage.parent != path.parent or not stage.name.startswith(
                f".agentscan-fix-{journal.parent.name}-"
            ):
                raise ValueError("Invalid staged replacement location")
            if stage.exists():
                if not stage.is_file() or digest(stage.read_bytes()) != entry["after"]:
                    raise ValueError("Staged replacement changed; preserve and review the receipt")
                stages.append(stage)
    for path, original, current, mode in changes:
        contained_path(root, path)
        if (path.read_bytes() if path.exists() else None) != current:
            raise ValueError("File changed during recovery")
        if original is None:
            path.unlink(missing_ok=True)
        else:
            fd, name = tempfile.mkstemp(prefix=".agentscan-recover-", dir=path.parent)
            replacement = Path(name)
            try:
                with os.fdopen(fd, "wb") as stream:
                    stream.write(original)
                    stream.flush()
                    os.fsync(stream.fileno())
                replacement.chmod(mode)
                os.replace(replacement, path)
            finally:
                replacement.unlink(missing_ok=True)
    for stage in stages:
        contained_path(root, stage)
        stage.unlink(missing_ok=True)
    discard_transaction(root, journal)
    return len(changes)
