"""In-process recovery receipt contract (issue #42, QA-025).

The crash-recovery path was only exercised through a child process that dies mid-apply.
That proves the happy path but not the guards that stop a recovery from overwriting an
editor's later changes or a tampered backup. These tests build the transaction journal
directly, so every preflight rejection is reachable.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentscan.remediation.recovery import (
    begin_transaction,
    digest,
    discard_transaction,
    pending_transactions,
    recover_transaction,
    transaction_staging_paths,
)


def _root(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    root.mkdir()
    return root


def _begin(root: Path, name: str = "a.py", *, before: bytes = b"before\n") -> tuple[Path, Path]:
    target = root / name
    target.write_bytes(before)
    journal = begin_transaction(
        root,
        {target: before},
        {target: "after\n"},
        {target: 0o600},
    )
    return journal, target


def _entries(journal: Path) -> list[dict]:
    return json.loads(journal.read_text(encoding="utf-8"))["entries"]


def test_recovery_restores_the_preimage_and_drops_the_receipt(tmp_path: Path) -> None:
    root = _root(tmp_path)
    journal, target = _begin(root)
    target.write_bytes(b"after\n")
    assert recover_transaction(root, journal) == 1
    assert target.read_bytes() == b"before\n"
    assert pending_transactions(root) == []
    assert not (root / ".agentscan-recovery").exists()


def test_recovery_rejects_a_later_edit_and_keeps_receipts(tmp_path: Path) -> None:
    root = _root(tmp_path)
    journal, target = _begin(root)
    target.write_bytes(b"after\n")
    target.write_bytes(b"editor changed this\n")
    with pytest.raises(ValueError, match="subsequent file changes"):
        recover_transaction(root, journal)
    assert target.read_bytes() == b"editor changed this\n"
    assert pending_transactions(root) == [journal]


def test_recovery_rejects_a_tampered_backup(tmp_path: Path) -> None:
    root = _root(tmp_path)
    journal, target = _begin(root)
    target.write_bytes(b"after\n")
    (journal.parent / "0.before").write_bytes(b"forged\n")
    with pytest.raises(ValueError, match="does not match its recorded preimage"):
        recover_transaction(root, journal)
    assert target.read_bytes() == b"after\n"


def test_recovery_rejects_a_receipt_from_another_project_or_version(tmp_path: Path) -> None:
    root = _root(tmp_path)
    journal, target = _begin(root)
    target.write_bytes(b"after\n")
    data = json.loads(journal.read_text(encoding="utf-8"))
    data["version"] = 2
    journal.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="different project or format"):
        recover_transaction(root, journal)


def test_recovery_requires_a_pending_transaction_inside_the_project(tmp_path: Path) -> None:
    root = _root(tmp_path)
    stray = root / "journal.json"
    stray.write_text("{}", encoding="utf-8")
    with pytest.raises(PermissionError, match="inside the selected project"):
        recover_transaction(root, stray)


def test_staged_replacement_must_stay_next_to_its_target(tmp_path: Path) -> None:
    root = _root(tmp_path)
    journal, target = _begin(root)
    target.write_bytes(b"after\n")
    data = json.loads(journal.read_text(encoding="utf-8"))
    data["entries"][0]["stage"] = "elsewhere/.agentscan-fix-before"
    journal.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid staged replacement location"):
        recover_transaction(root, journal)


def test_staged_replacement_must_still_match_its_postimage(tmp_path: Path) -> None:
    root = _root(tmp_path)
    journal, target = _begin(root)
    target.write_bytes(b"after\n")
    stage = target.parent / f".agentscan-fix-{journal.parent.name}-0"
    stage.write_bytes(b"someone else wrote this\n")
    data = json.loads(journal.read_text(encoding="utf-8"))
    data["entries"][0]["stage"] = str(stage.relative_to(root))
    journal.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="Staged replacement changed"):
        recover_transaction(root, journal)


def test_staging_paths_map_each_target_to_its_owned_stage(tmp_path: Path) -> None:
    root = _root(tmp_path)
    journal, target = _begin(root)
    stage = target.parent / f".agentscan-fix-{journal.parent.name}-0"
    data = json.loads(journal.read_text(encoding="utf-8"))
    data["entries"][0]["stage"] = str(stage.relative_to(root))
    journal.write_text(json.dumps(data), encoding="utf-8")
    assert transaction_staging_paths(root, journal) == {target: stage}


def test_second_transaction_is_refused_while_one_is_pending(tmp_path: Path) -> None:
    root = _root(tmp_path)
    journal, target = _begin(root)
    assert pending_transactions(root) == [journal]
    with pytest.raises(RuntimeError, match="unfinished remediation transaction"):
        begin_transaction(root, {target: b"before\n"}, {target: "after\n"}, {target: 0o600})


def test_discard_refuses_a_journal_outside_the_owned_transaction(tmp_path: Path) -> None:
    root = _root(tmp_path)
    _begin(root)
    stray = root / "journal.json"
    stray.write_text("{}", encoding="utf-8")
    with pytest.raises(PermissionError, match="Invalid recovery transaction location"):
        discard_transaction(root, stray)


def test_digest_is_none_for_an_absent_preimage() -> None:
    assert digest(None) is None
    assert digest(b"before\n") == digest(b"before\n")


def test_a_staged_replacement_is_removed_after_a_clean_recovery(tmp_path: Path) -> None:
    root = _root(tmp_path)
    journal, target = _begin(root)
    stage = target.parent / f".agentscan-fix-{journal.parent.name}-0"
    stage.write_bytes(b"after\n")
    target.write_bytes(b"after\n")
    data = json.loads(journal.read_text(encoding="utf-8"))
    data["entries"][0]["stage"] = str(stage.relative_to(root))
    journal.write_text(json.dumps(data), encoding="utf-8")
    assert recover_transaction(root, journal) == 1
    assert target.read_bytes() == b"before\n"
    assert not stage.exists()


def test_a_file_created_by_the_fix_is_removed_on_recovery(tmp_path: Path) -> None:
    root = _root(tmp_path)
    created = root / "created.py"
    journal = begin_transaction(
        root,
        {created: None},
        {created: "after\n"},
        {created: 0o600},
    )
    created.write_bytes(b"after\n")
    assert recover_transaction(root, journal) == 1
    assert not created.exists()
    assert pending_transactions(root) == []
