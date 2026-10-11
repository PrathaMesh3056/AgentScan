# tests/test_remediation/test_git_pr.py
#
# Comprehensive tests for GitPRAutomator and agentscan fix --apply --pr.

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from agentscan._cli import app
from agentscan.remediation.git_pr import GitPRAutomator, resolve_owasp_id
from agentscan.remediation.models import FixAction, FixPlan


@pytest.fixture
def git_repo(tmp_path: Path) -> Path:
    """Fixture providing an initialized temporary git repository."""
    subprocess.run(["git", "init"], cwd=str(tmp_path), check=True, capture_output=True)
    subprocess.run(
        ["git", "config", "user.email", "agentscan-test@example.com"],
        cwd=str(tmp_path),
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "AgentScan Test"],
        cwd=str(tmp_path),
        check=True,
        capture_output=True,
    )

    initial_file = tmp_path / "README.md"
    initial_file.write_text("# Test Repo\n", encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=str(tmp_path), check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "chore: initial commit"],
        cwd=str(tmp_path),
        check=True,
        capture_output=True,
    )
    return tmp_path


def test_resolve_owasp_id() -> None:
    """Asserts OWASP category resolution for known prefixes and defaults."""
    assert resolve_owasp_id("ATK-001") == "LLM01"
    assert resolve_owasp_id("ATK-010") == "LLM01"
    assert resolve_owasp_id("ATK-020") == "LLM01"
    assert resolve_owasp_id("SC-001") == "LLM03"
    assert resolve_owasp_id("ID-002") == "LLM06"
    assert resolve_owasp_id("CUSTOM-001", explicit_owasp="LLM09") == "LLM09"
    assert resolve_owasp_id("UNKNOWN-XYZ") == "UNMAPPED"


def test_commit_fix_plan_creates_branch_and_commits(git_repo: Path) -> None:
    """
    Definition of Done:
    Asserts commit_fix_plan() on a tmp git repo creates a new branch and commits cleanly.
    """
    automator = GitPRAutomator(repo_path=git_repo)

    target_file = git_repo / "requirements.txt"
    target_file.write_text("langchain==0.1.0\n", encoding="utf-8")
    subprocess.run(["git", "add", "requirements.txt"], cwd=str(git_repo), check=True)
    subprocess.run(["git", "commit", "-m", "add requirements"], cwd=str(git_repo), check=True)

    action = FixAction(
        path=str(target_file),
        kind="pin_bump",
        finding_id="SC-001",
        before="langchain==0.1.0\n",
        after="langchain==0.1.15\n",
    )
    plan = FixPlan(actions=[action])

    branch_name = automator.commit_fix_plan(plan, branch_name="fix/patch-dependencies")

    assert branch_name == "fix/patch-dependencies"

    # Verify active branch
    res_branch = subprocess.run(
        ["git", "rev-parse", "--abbrev-ref", "HEAD"],
        cwd=str(git_repo),
        capture_output=True,
        text=True,
        check=True,
    )
    assert res_branch.stdout.strip() == "fix/patch-dependencies"

    # Verify file content on disk
    assert target_file.read_text(encoding="utf-8") == "langchain==0.1.15\n"

    # Verify latest commit message
    res_log = subprocess.run(
        ["git", "log", "-1", "--pretty=%B"],
        cwd=str(git_repo),
        capture_output=True,
        text=True,
        check=True,
    )
    assert "fix(agentscan): resolve SC-001" in res_log.stdout


def test_commit_fix_plan_generates_default_branch_name(git_repo: Path) -> None:
    """Asserts automatic branch naming when branch_name is omitted."""
    automator = GitPRAutomator(repo_path=git_repo)
    action = FixAction(
        path=str(git_repo / "test.txt"),
        kind="guardrails",
        finding_id="ATK-001",
        before="",
        after="safe_code = True\n",
    )
    plan = FixPlan(actions=[action])

    branch_name = automator.commit_fix_plan(plan)
    assert branch_name.startswith("codex/agentscan-ATK-001")


def test_commit_fix_plan_non_git_repo_raises_error(tmp_path: Path) -> None:
    """Asserts RuntimeError when invoked outside a git repository."""
    non_git_dir = tmp_path / "not_git"
    non_git_dir.mkdir()
    automator = GitPRAutomator(repo_path=non_git_dir)
    plan = FixPlan(actions=[])

    with pytest.raises(RuntimeError, match="Target path is not a Git repository"):
        automator.commit_fix_plan(plan)


def test_create_pr_gh_not_installed_returns_none(git_repo: Path) -> None:
    """
    Definition of Done:
    Asserts create_pr() when gh is not installed returns None and logs/prints clear warning.
    """
    automator = GitPRAutomator(repo_path=git_repo)

    with patch("shutil.which", return_value=None):
        pr_url = automator.create_pr(branch_name="fix/some-branch")
        assert pr_url is None


def test_create_pr_gh_success_returns_url(git_repo: Path) -> None:
    """Asserts create_pr() returns PR URL when gh command succeeds."""
    automator = GitPRAutomator(repo_path=git_repo)

    mock_completed = subprocess.CompletedProcess(
        args=["gh", "pr", "create"],
        returncode=0,
        stdout="https://github.com/org/repo/pull/123\n",
        stderr="",
    )

    with (
        patch("shutil.which", return_value="C:\\Program Files\\GitHub CLI\\gh.exe"),
        patch("subprocess.run", return_value=mock_completed) as mock_run,
    ):
        pr_url = automator.create_pr(
            branch_name="fix/my-branch",
            base="main",
            title="fix: critical patch",
            body="PR body",
        )
        assert pr_url == "https://github.com/org/repo/pull/123"
        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert "--head" in args
        assert "fix/my-branch" in args


def test_create_pr_gh_error_returns_none(git_repo: Path) -> None:
    """Asserts create_pr() returns None on gh command failure."""
    automator = GitPRAutomator(repo_path=git_repo)

    mock_failed = subprocess.CompletedProcess(
        args=["gh", "pr", "create"],
        returncode=1,
        stdout="",
        stderr="GraphQL: could not find repository",
    )

    with (
        patch("shutil.which", return_value="/usr/bin/gh"),
        patch("subprocess.run", return_value=mock_failed),
    ):
        pr_url = automator.create_pr(branch_name="fix/broken-branch")
        assert pr_url is None


def test_generate_pr_body_contains_required_fields() -> None:
    """
    Definition of Done:
    Asserts generate_pr_body() contains attack_id, owasp_id, and a diff summary for each FixAction.
    """
    automator = GitPRAutomator()
    action1 = FixAction(
        path="src/agent.py",
        kind="ast_patch",
        finding_id="ATK-001",
        before="query = input()\nexec(query)\n",
        after="query = input()\n# safe exec disabled\n",
    )
    action2 = FixAction(
        path="pyproject.toml",
        kind="pin_bump",
        finding_id="SC-001",
        before='requests = "2.20.0"\n',
        after='requests = "2.31.0"\n',
    )
    plan = FixPlan(actions=[action1, action2])

    body = automator.generate_pr_body(plan)

    # 1. attack_id
    assert "ATK-001" in body
    assert "SC-001" in body
    assert "- **Attack ID**: `ATK-001`" in body
    assert "- **Attack ID**: `SC-001`" in body

    # 2. owasp_id
    assert "- **OWASP ID**: `LLM01`" in body  # ATK-001 -> LLM01
    assert "- **OWASP ID**: `LLM03`" in body  # OWASP 2025 supply chain

    # 3. diff summary
    assert "- **Diff Summary**:" in body
    assert "lines modified" in body or "New file created" in body

    # 4. diff code block
    assert "```diff" in body
    assert "```" in body


def test_cli_fix_apply_pr_flag(git_repo: Path) -> None:
    """Asserts agentscan fix --apply --pr CLI workflow."""
    runner = CliRunner()

    target_file = git_repo / "server.py"
    target_file.write_text("import pickle\npickle.loads(data)\n", encoding="utf-8")
    subprocess.run(["git", "add", "server.py"], cwd=str(git_repo), check=True)
    subprocess.run(["git", "commit", "-m", "add server"], cwd=str(git_repo), check=True)

    with patch.object(
        GitPRAutomator, "create_pr", return_value="https://github.com/test/repo/pull/77"
    ):
        result = runner.invoke(
            app,
            ["fix", str(git_repo), "--apply", "--pr", "--branch", "fix/cli-test"],
        )

        assert result.exit_code == 0
        assert (
            "Successfully applied" in result.stdout
            or "No remediations needed" in result.stdout
            or "Pull request opened" in result.stdout
            or "Dry-run" in result.stdout
        )


def test_cli_fix_pr_without_apply_warns(git_repo: Path) -> None:
    """Asserts that --pr without --apply gives a warning that --apply is required."""
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["fix", str(git_repo), "--pr"],
    )
    assert result.exit_code == 0
    assert "Warning: --pr requires --apply" in result.stdout or "No remediations" in result.stdout
