"""Exercise the composite Bash boundary and inspect required release gates."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tomllib
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
BASH = shutil.which("bash")
if os.name == "nt":
    git_bash = Path(os.environ.get("PROGRAMFILES", "C:/Program Files")) / "Git/bin/bash.exe"
    if git_bash.exists():
        BASH = str(git_bash)


def load_yaml(path):
    # BaseLoader keeps GitHub's `on` key intact instead of YAML 1.1 boolean coercion.
    return yaml.load((ROOT / path).read_text(encoding="utf-8"), Loader=yaml.BaseLoader)


ACTION = load_yaml("action.yml")
WORKFLOWS = {path.stem: load_yaml(path) for path in (ROOT / ".github/workflows").glob("*.yml")}


def shell_run(tmp_path, *, overrides=None, script=None, executable="agentscan"):
    if BASH is None:
        pytest.fail("Bash is required for action injection regression checks.")
    log = tmp_path / "argv.bin"
    env = os.environ.copy()
    env.update(
        AGENTSCAN_ACTION_PATH=ROOT.as_posix(),
        AGENTSCAN_COMMAND="audit",
        AGENTSCAN_PATH="project with spaces",
        AGENTSCAN_TARGET_URL="http://fixture.test/chat",
        AGENTSCAN_FAIL_ON="HIGH",
        AGENTSCAN_SARIF_OUTPUT="result with spaces.sarif",
        AGENTSCAN_JSON_OUTPUT="",
        AGENTSCAN_TEST_ARGV_LOG=log.as_posix(),
        AGENTSCAN_TEST_EXIT="0",
    )
    env.update(overrides or {})
    stub = (
        f'{executable}() {{ printf "%s\\0" "$@" > "$AGENTSCAN_TEST_ARGV_LOG"; '
        'return "$AGENTSCAN_TEST_EXIT"; }\n'
        f"export -f {executable}\n"
    )
    if script is None:
        step = next(step for step in ACTION["runs"]["steps"] if step["name"] == "Execute AgentScan")
        script = step["run"]
    result = subprocess.run(
        [BASH, "--noprofile", "--norc", "-c", stub + script],
        env=env,
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=15,
    )
    args = log.read_bytes().decode("utf-8").rstrip("\0").split("\0") if log.exists() else None
    return result, args


@pytest.mark.parametrize(
    "value",
    [
        "path with spaces",
        "quote\" and single'quote",
        "$HOME literal dollars and ${PATH}",
        "line one\nline two",
        "-looks-like-an-option",
        "semi;colon & pipe | wildcard *",
        "$(printf harmless > action-sentinel)",
        "`printf harmless > action-sentinel`",
    ],
)
@pytest.mark.parametrize("command", ["audit", "scan"])
def test_payload_is_one_literal_positional_argument(tmp_path, value, command):
    result, args = shell_run(
        tmp_path,
        overrides={
            "AGENTSCAN_COMMAND": command,
            "AGENTSCAN_PATH": value,
            "AGENTSCAN_TARGET_URL": value,
        },
    )
    assert result.returncode == 0, result.stderr
    assert args == [
        command,
        "--fail-on",
        "HIGH",
        "--output",
        "result with spaces.sarif",
        "--",
        value,
    ]
    assert not (tmp_path / "action-sentinel").exists()


@pytest.mark.parametrize("field", ["AGENTSCAN_SARIF_OUTPUT", "AGENTSCAN_JSON_OUTPUT"])
def test_output_is_literal_even_with_shell_metacharacters(tmp_path, field):
    value = 'out "$(printf harmless > action-sentinel)"\n--fail-on LOW.json'
    result, args = shell_run(
        tmp_path,
        overrides={"AGENTSCAN_SARIF_OUTPUT": "", "AGENTSCAN_JSON_OUTPUT": "", field: value},
    )
    assert result.returncode == 0, result.stderr
    assert args[4] == value
    assert not (tmp_path / "action-sentinel").exists()


@pytest.mark.parametrize(
    "overrides",
    [
        {"AGENTSCAN_COMMAND": "invalid"},
        {"AGENTSCAN_COMMAND": "audit; printf harmless > action-sentinel"},
        {"AGENTSCAN_FAIL_ON": "HIGH; printf harmless > action-sentinel"},
        {"AGENTSCAN_FAIL_ON": "NOT_A_SEVERITY"},
        {"AGENTSCAN_PATH": ""},
        {"AGENTSCAN_COMMAND": "scan", "AGENTSCAN_TARGET_URL": ""},
    ],
)
def test_invalid_configuration_fails_without_invocation(tmp_path, overrides):
    result, args = shell_run(tmp_path, overrides=overrides)
    assert result.returncode == 2, result.stderr
    assert args is None
    assert not (tmp_path / "action-sentinel").exists()


def test_scanner_failure_propagates(tmp_path):
    result, args = shell_run(tmp_path, overrides={"AGENTSCAN_TEST_EXIT": "7"})
    assert args is not None and result.returncode == 7


def test_install_path_never_becomes_shell_source(tmp_path):
    step = next(step for step in ACTION["runs"]["steps"] if step["name"] == "Install AgentScan")
    value = 'checkout "$(printf harmless > action-sentinel)" with spaces'
    result, args = shell_run(
        tmp_path,
        script=step["run"],
        executable="uv",
        overrides={"AGENTSCAN_ACTION_PATH": value},
    )
    assert result.returncode == 0, result.stderr
    assert args == ["pip", "install", "--system", value]
    assert not (tmp_path / "action-sentinel").exists()


def test_github_expressions_are_not_embedded_in_shell_source():
    for step in ACTION["runs"]["steps"]:
        assert "${{" not in step.get("run", "")


def test_release_uses_validation_artifact_without_rebuilding():
    ci, release = WORKFLOWS["ci"], WORKFLOWS["release"]
    assert ci["jobs"]["validation"]["uses"] == release["jobs"]["validation"]["uses"]
    publish = release["jobs"]["publish"]
    assert publish["needs"] == "validation"
    assert publish["environment"] == "pypi"
    assert publish["permissions"] == {"id-token": "write", "contents": "write"}
    assert all("run" not in step for step in publish["steps"])
    download = publish["steps"][0]
    assert download["uses"].startswith("actions/download-artifact@")
    assert download["with"]["name"] == "agentscan-distributions-3.12"


def test_audit_is_a_required_lock_export_gate():
    job = WORKFLOWS["validate"]["jobs"]["test"]
    audit = next(
        step for step in job["steps"] if step.get("name") == "Audit locked dependencies (required)"
    )
    source = audit["run"]
    assert "--frozen" in source and "--no-emit-project" in source
    assert "pip-audit==2.10.1" in source
    assert "--strict" in source and "--require-hashes" in source
    # Hashes make the export fully resolved, so --disable-pip can audit it
    # without pip re-resolving conflicting markers. --no-deps is redundant.
    assert "--disable-pip" in source
    assert "--no-deps" not in source
    assert "--desc" not in source
    assert "||" not in source and "continue-on-error" not in audit
    assert "continue-on-error" not in job
    assert any(
        step.get("name") == "Verify clean artifact installation profiles" for step in job["steps"]
    )


def test_gitleaks_scans_full_history_without_broad_allowlists():
    job = WORKFLOWS["validate"]["jobs"]["secrets"]
    checkout = next(
        step for step in job["steps"] if step.get("uses", "").startswith("actions/checkout@")
    )
    assert checkout["with"]["fetch-depth"] == "0"
    scan = next(step for step in job["steps"] if step.get("name") == "Scan for committed secrets")
    assert scan["uses"].startswith("gitleaks/gitleaks-action@")

    config = tomllib.loads((ROOT / ".gitleaks.toml").read_text(encoding="utf-8"))
    allowlists = config["allowlists"]
    assert allowlists
    for allowlist in allowlists:
        for path in allowlist.get("paths", []):
            assert path == r"(^|/)\.env\.example$"
        assert not any(
            directory in pattern
            for pattern in allowlist.get("paths", [])
            for directory in ("tests/fixtures", "tests/test_attacks", "tests/test_e2e")
        )


@pytest.mark.parametrize("exit_code", [1, 7])
def test_audit_vulnerability_and_tool_failure_abort_step(tmp_path, exit_code):
    audit = next(
        step
        for step in WORKFLOWS["validate"]["jobs"]["test"]["steps"]
        if step.get("name") == "Audit locked dependencies (required)"
    )
    source = f"uvx() {{ return {exit_code}; }}\n" + audit["run"]
    result, _ = shell_run(
        tmp_path, script=source, executable="uv", overrides={"RUNNER_TEMP": tmp_path.as_posix()}
    )
    assert result.returncode == exit_code


def test_all_external_actions_and_uv_are_pinned():
    steps = list(ACTION["runs"]["steps"])
    for workflow in WORKFLOWS.values():
        for job in workflow["jobs"].values():
            steps.extend(job.get("steps", []))
    for step in steps:
        if "uses" in step:
            assert re.search(r"@[0-9a-f]{40}$", step["uses"]), step["uses"]
        if step.get("uses", "").startswith("astral-sh/setup-uv@"):
            assert step["with"]["version"] == "0.12.3"


@pytest.mark.parametrize(
    "path", [".github/scripts/run-action.sh", ".github/scripts/smoke-artifacts.sh"]
)
def test_bash_helpers_pass_syntax_check(path):
    assert BASH is not None
    result = subprocess.run([BASH, "-n", path], cwd=ROOT, capture_output=True, timeout=15)
    assert result.returncode == 0, result.stderr
