"""Private audit and operational files must never enter installable archives."""

from __future__ import annotations

import io
import runpy
import tarfile
import tomllib
import zipfile
from fnmatch import fnmatchcase
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
CHECKER = runpy.run_path(str(ROOT / ".github/scripts/check_artifact_contents.py"))
REQUIRED = CHECKER["_REQUIRED_RUNTIME"]


def write_archive(tmp_path, *, source, extra=None, remove=None):
    names = set(REQUIRED)
    names.update(
        {"rules/ai_rules.yaml", "pyproject.toml", "README.md", "LICENSE"}
        if source
        else {"agentscan/rules/ai_rules.yaml"}
    )
    names.difference_update(remove or [])
    names.update(extra or [])
    path = tmp_path / ("agentscan-0.2.0.tar.gz" if source else "agentscan-0.2.0-py3-none-any.whl")
    if source:
        with tarfile.open(path, "w:gz") as archive:
            for name in sorted(names):
                member = tarfile.TarInfo("agentscan-0.2.0/" + name)
                member.size = 11
                archive.addfile(member, io.BytesIO(b"placeholder"))
    else:
        with zipfile.ZipFile(path, "w") as archive:
            for name in names:
                archive.writestr(name, b"placeholder")
    return path


@pytest.mark.parametrize("source", [False, True])
def test_required_runtime_and_package_assets_pass(tmp_path, source):
    result = CHECKER["check_archive"](write_archive(tmp_path, source=source))
    assert result["files_checked"] >= len(REQUIRED)


@pytest.mark.parametrize("source", [False, True])
@pytest.mark.parametrize(
    "private_name",
    [
        "Codex audit/receipt.json",
        "AUDIT_PHASE2.md",
        "internal_docs/diagrams/report.json",
        ".test-tmp/report.txt",
        "agentscan/.env",
        "agentscan/nested/.env.production",
        "agentscan/agentscan-data.key",
        "agentscan/agentscan-jwt.pem",
        "agentscan/.agentscan/profiles/client.json",
        "agentscan/.agentscan-recovery/transaction/backup-0",
        "agentscan/core/.agentscan-fix-transaction-0",
        "agentscan/core/.agentscan-recover-staged",
        "agentscan/core/.agentscan-rollback-staged",
        "tests/.env",
        "tests/fixtures/signing.pem",
        "docs/internal_docs/receipt.json",
    ],
)
def test_private_files_are_rejected_without_reading_contents(tmp_path, source, private_name):
    artifact = write_archive(tmp_path, source=source, extra=[private_name])
    with pytest.raises(ValueError, match="Private or operational file"):
        CHECKER["check_archive"](artifact)


@pytest.mark.parametrize("source", [False, True])
def test_missing_runtime_asset_is_rejected(tmp_path, source):
    artifact = write_archive(tmp_path, source=source, remove=["agentscan/ui/static/dashboard.css"])
    with pytest.raises(ValueError, match="Required runtime assets are missing"):
        CHECKER["check_archive"](artifact)


def test_sdist_rejects_unapproved_top_level_files(tmp_path):
    artifact = write_archive(tmp_path, source=True, extra=["unexpected.txt"])
    with pytest.raises(ValueError, match="outside the distribution allowlist"):
        CHECKER["check_archive"](artifact)


@pytest.mark.parametrize("source_input", ["tests/test_sample.py", "docs/index.md", "uv.lock"])
def test_sdist_accepts_reviewed_source_inputs(tmp_path, source_input):
    artifact = write_archive(tmp_path, source=True, extra=[source_input])
    assert CHECKER["check_archive"](artifact)["kind"] == "sdist"


def test_hatch_required_root_gitignore_is_allowed_only_in_source_archive(tmp_path):
    source = write_archive(tmp_path, source=True, extra=[".gitignore"])
    assert CHECKER["check_archive"](source)["kind"] == "sdist"
    wheel = write_archive(tmp_path, source=False, extra=[".gitignore"])
    with pytest.raises(ValueError, match="outside the distribution allowlist"):
        CHECKER["check_archive"](wheel)


def test_sdist_archive_link_is_rejected(tmp_path):
    artifact = tmp_path / "agentscan-0.2.0.tar.gz"
    with tarfile.open(artifact, "w:gz") as archive:
        member = tarfile.TarInfo("agentscan-0.2.0/agentscan/private")
        member.type = tarfile.SYMTYPE
        member.linkname = "../../private"
        archive.addfile(member)
    with pytest.raises(ValueError, match="unsupported archive links"):
        CHECKER["check_archive"](artifact)


@pytest.mark.parametrize("source", [False, True])
def test_archive_path_escape_is_rejected(tmp_path, source):
    artifact = write_archive(tmp_path, source=source, extra=["../outside"])
    with pytest.raises(ValueError, match="unsafe archive path"):
        CHECKER["check_archive"](artifact)


def test_ci_validates_archive_contents_before_installing():
    source = (ROOT / ".github/scripts/smoke-artifacts.sh").read_text(encoding="utf-8")
    assert source.index("check_artifact_contents.py") < source.index("uv pip install")


def test_sdist_include_lists_tests_docs_and_lockfile():
    build = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["tool"]["hatch"][
        "build"
    ]["targets"]["sdist"]
    assert {"/tests/**", "/docs/**", "/uv.lock"} <= set(build["include"])


@pytest.mark.parametrize("target", ["wheel", "sdist"])
def test_both_build_targets_protect_nested_credentials_and_repair_files(target):
    build = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["tool"]["hatch"][
        "build"
    ]
    exclusions = build["targets"][target].get("exclude", build["exclude"])
    for name in [
        "agentscan/.env",
        "agentscan/nested/.env.production",
        "agentscan/nested/signing.pem",
        "agentscan/nested/data.key",
        "agentscan/.agentscan/profiles/client.json",
        "agentscan/.agentscan-recovery/transaction/backup-0",
        "agentscan/core/.agentscan-fix-transaction-0",
        "agentscan/core/.agentscan-recover-staged",
        "agentscan/core/.agentscan-rollback-staged",
    ]:
        assert any(fnmatchcase(name, pattern) for pattern in exclusions), (target, name)
    assert not any(fnmatchcase("agentscan/rules/ai_rules.yaml", pattern) for pattern in exclusions)
