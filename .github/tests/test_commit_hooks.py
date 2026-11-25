"""Keep commit-time validation consistent with the locked CI toolchain."""

import tomllib
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]


def hook_configuration():
    return yaml.safe_load((ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8"))


def locked_versions():
    lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
    return {package["name"]: package["version"] for package in lock["package"]}


@pytest.mark.parametrize(
    ("tool", "repository"),
    [
        ("ruff", "https://github.com/astral-sh/ruff-pre-commit"),
        ("mypy", "https://github.com/pre-commit/mirrors-mypy"),
    ],
)
def test_hook_tool_versions_match_locked_ci(tool, repository):
    repo = next(repo for repo in hook_configuration()["repos"] if repo["repo"] == repository)
    assert repo["rev"] == "v" + locked_versions()[tool]


def test_mypy_uses_current_redis_typing_and_locked_support_dependencies():
    hook = next(
        hook
        for repo in hook_configuration()["repos"]
        for hook in repo["hooks"]
        if hook["id"] == "mypy"
    )
    dependencies = hook["additional_dependencies"]
    assert not any(dependency.lower().startswith("types-redis") for dependency in dependencies)
    versions = locked_versions()
    for package in ("pydantic", "httpx", "types-pyyaml", "redis"):
        assert f"{package}=={versions[package]}" in dependencies


def test_mypy_checks_whole_runtime_even_when_no_python_files_are_staged():
    hook = next(
        hook
        for repo in hook_configuration()["repos"]
        for hook in repo["hooks"]
        if hook["id"] == "mypy"
    )
    assert hook["args"] == ["agentscan"]
    assert hook["pass_filenames"] is False
    assert hook["always_run"] is True


def test_pre_commit_stage_contract_is_explicit_and_current():
    config = hook_configuration()
    assert config["minimum_pre_commit_version"] == "4.0.0"
    assert config["default_stages"] == ["pre-commit", "manual"]
    assert tuple(map(int, locked_versions()["pre-commit"].split("."))) >= (4, 0, 0)

    hygiene = next(
        repo
        for repo in config["repos"]
        if repo["repo"] == "https://github.com/pre-commit/pre-commit-hooks"
    )
    assert hygiene["rev"] == "v6.0.0"
    legacy_stages = {"commit", "push", "merge-commit"}
    for repo in config["repos"]:
        for hook in repo["hooks"]:
            assert not legacy_stages.intersection(hook.get("stages", []))
