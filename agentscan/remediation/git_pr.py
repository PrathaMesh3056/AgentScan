# agentscan/remediation/git_pr.py
#
# Automated Git branch creation, committing, and GitHub PR creation for remediation plans.

from __future__ import annotations

import difflib
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from loguru import logger

from agentscan.remediation.models import FixAction, FixPlan

# Mapping of known finding prefix patterns to OWASP Top 10 for LLM categories
OWASP_CATEGORY_MAP: dict[str, str] = {"SC-001": "LLM03", "SC-011": "LLM03", "SC-021": "LLM06"}

DEFAULT_OWASP_CATEGORY: str = "UNMAPPED"


def resolve_owasp_id(finding_id: str, explicit_owasp: str = "") -> str:
    """
    Resolve the OWASP Top 10 for LLMs identifier for a finding.

    Parameters
    ----------
    finding_id : str
        Finding or attack identifier (e.g., ATK-001, SC-001, ID-002).
    explicit_owasp : str
        Explicit OWASP category if already attached to the action.

    Returns
    -------
    str
        Standardized OWASP category string (e.g. LLM01, LLM05).
    """
    from agentscan.core.taxonomy import OWASP_CATEGORIES

    if explicit_owasp in OWASP_CATEGORIES:
        return explicit_owasp
    if finding_id in OWASP_CATEGORY_MAP:
        return OWASP_CATEGORY_MAP[finding_id]
    if finding_id.startswith("ID-"):
        return "LLM06"
    if finding_id.startswith("SEC-"):
        return "LLM02"

    # Check attack module registry if available
    try:
        from agentscan.attacks.registry import registry

        registry.load_all()
        mod = registry.get(finding_id)
        if mod and getattr(mod, "owasp_id", None):
            return str(mod.owasp_id)
    except Exception:
        pass

    return DEFAULT_OWASP_CATEGORY


class GitPRAutomator:
    """
    Automates local Git branch creation, fix staging, commit generation,
    and remote pull request publication via the GitHub CLI.
    """

    def __init__(self, repo_path: str | Path | None = None) -> None:
        """
        Initialize the Git PR automator.

        Parameters
        ----------
        repo_path : str | Path | None
            Filesystem root of the target Git repository (defaults to Path.cwd()).
        """
        self.repo_path: Path = Path(repo_path).resolve() if repo_path else Path.cwd().resolve()

    def commit_fix_plan(self, plan: FixPlan, branch_name: str | None = None) -> str:
        """
        Create a new Git branch, apply fix plan changes, and commit the diff.

        Parameters
        ----------
        plan : FixPlan
            The remediation plan containing the actions to apply.
        branch_name : str | None
            Optional target branch name. If omitted, a branch name is derived
            from finding IDs.

        Returns
        -------
        str
            The branch name that was checked out and committed to.

        Raises
        ------
        RuntimeError
            If Git command execution fails or the workspace is not a Git repository.
        """
        if not (self.repo_path / ".git").exists():
            raise RuntimeError(f"Target path is not a Git repository: {self.repo_path}")
        if not plan.actions:
            raise RuntimeError("Cannot commit an empty remediation plan")
        plan.bind_root(self.repo_path)
        if self._run_git(["status", "--porcelain"]).strip():
            raise RuntimeError("Remediation commits require a clean Git working tree and index")

        finding_ids = sorted({a.finding_id for a in plan.actions})
        if not branch_name:
            tag = "-".join(re.sub(r"[^A-Za-z0-9_-]", "", fid) for fid in finding_ids)
            tag = tag[:30].strip("-") or "remediation"
            branch_name = f"codex/agentscan-{tag}"

        logger.info(f"Creating git branch: {branch_name}")
        self._run_git(["check-ref-format", "--branch", branch_name])
        self._run_git(["checkout", "-b", branch_name])

        # Apply disk changes
        plan.bind_root(self.repo_path)
        plan.apply()

        # Stage affected paths or all changed files
        if plan.paths_affected:
            for p in plan.paths_affected:
                relative = Path(p).resolve().relative_to(self.repo_path).as_posix()
                self._run_git(["add", "--", relative])

        commit_findings = ", ".join(finding_ids) if finding_ids else "security findings"
        commit_message = f"fix(agentscan): resolve {commit_findings}"

        logger.info(f"Committing changes: {commit_message}")
        self._run_git(["commit", "-m", commit_message])

        return branch_name

    def create_pr(
        self,
        branch_name: str,
        base: str = "main",
        title: str | None = None,
        body: str | None = None,
        push: bool = False,
    ) -> str | None:
        """
        Create a GitHub Pull Request using the gh CLI.

        Parameters
        ----------
        branch_name : str
            Head branch containing the committed changes.
        base : str
            Target base branch for the pull request (defaults to 'main').
        title : str | None
            Pull request title.
        body : str | None
            Pull request Markdown body.
        push : bool
            Whether to push the branch to origin before opening the PR.

        Returns
        -------
        str | None
            The URL of the created pull request if successful, or None if gh is
            unavailable or execution failed.
        """
        gh_binary = shutil.which("gh")
        if not gh_binary:
            logger.warning(
                "GitHub CLI ('gh') is not installed or not found in system PATH. "
                "Skipping pull request creation. Branch has been committed locally."
            )
            return None

        # If push is requested and a remote is configured, push branch before PR creation
        if push:
            if "origin" not in self._run_git(["remote"]).split():
                raise RuntimeError("No origin remote is configured; PR creation stopped.")
            # An uncertain or rejected push must not proceed to publication.
            self._run_git(["push", "-u", "origin", branch_name])

        pr_title = title or f"fix(agentscan): automated remediation for {branch_name}"
        pr_body = body or "Automated remediation generated by AgentScan."

        cmd = [
            gh_binary,
            "pr",
            "create",
            "--head",
            branch_name,
            "--base",
            base,
            "--title",
            pr_title,
        ]

        try:
            with tempfile.TemporaryDirectory(prefix="agentscan-pr-") as directory:
                body_file = Path(directory) / "body.md"
                body_file.write_text(pr_body, encoding="utf-8")
                res = subprocess.run(
                    [*cmd, "--body-file", str(body_file)],
                    cwd=str(self.repo_path),
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=60,
                    stdin=subprocess.DEVNULL,
                    env={**os.environ, "GH_PROMPT_DISABLED": "1", "GIT_TERMINAL_PROMPT": "0"},
                )
            if res.returncode == 0:
                pr_url = res.stdout.strip()
                logger.info(f"Pull request created successfully: {pr_url}")
                return pr_url
            else:
                logger.warning(
                    f"GitHub CLI failed with exit code {res.returncode}: {res.stderr.strip()}"
                )
                return None
        except Exception as exc:
            logger.warning(f"Error executing GitHub CLI: {exc}")
            return None

    def generate_pr_body(self, plan: FixPlan) -> str:
        """
        Generate a structured Markdown pull request body detailing findings,
        OWASP mappings, and diff summaries.

        Parameters
        ----------
        plan : FixPlan
            The remediation plan to describe.

        Returns
        -------
        str
            Markdown pull request body.
        """
        lines: list[str] = [
            "## 🛡️ AgentScan Automated Security Remediation",
            "",
            "This pull request was automatically generated by **AgentScan** to remediate "
            "vulnerabilities and policy violations detected during security analysis.",
            "",
            "### 📊 Summary",
            f"- **Total Remediation Actions**: {plan.total_actions}",
            f"- **Files Modified**: {len(plan.paths_affected)}",
            "",
            "---",
            "",
            "### 🔍 Finding Remediations",
            "",
        ]

        for idx, action in enumerate(plan.actions, start=1):
            attack_id = action.finding_id
            owasp_id = resolve_owasp_id(attack_id, action.owasp_id)
            diff_summary = self._compute_diff_summary(action)
            relative_path = self._relative_path(action.path)

            lines.extend(
                [
                    f"#### {idx}. Finding `{attack_id}` ({action.kind})",
                    f"- **Attack ID**: `{attack_id}`",
                    f"- **OWASP ID**: `{owasp_id}`",
                    f"- **Remediation Kind**: `{action.kind}`",
                    f"- **File Path**: `{relative_path}`",
                    f"- **Diff Summary**: {diff_summary}",
                    "",
                    "```diff",
                    self._generate_unified_diff(action),
                    "```",
                    "",
                ]
            )

        lines.extend(
            [
                "---",
                "*Generated automatically by [AgentScan](https://github.com/PrathaMesh3056/AgentScan)*",
            ]
        )

        return "\n".join(lines)

    def _run_git(self, args: list[str]) -> str:
        """Execute a git subcommand in the target repository directory."""
        git_binary = shutil.which("git") or "git"
        cmd = [git_binary] + args
        try:
            res = subprocess.run(
                cmd,
                cwd=str(self.repo_path),
                capture_output=True,
                text=True,
                check=False,
                timeout=60,
                stdin=subprocess.DEVNULL,
                env={**os.environ, "GIT_TERMINAL_PROMPT": "0", "GCM_INTERACTIVE": "never"},
            )
            if res.returncode != 0:
                raise RuntimeError(
                    f"Git command failed ({' '.join(args)}): {res.stderr.strip() or res.stdout.strip()}"
                )
            return res.stdout.strip()
        except FileNotFoundError as exc:
            raise RuntimeError("Git executable not found on host system.") from exc
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                "Git operation timed out. Preserve the branch and inspect its state before retrying."
            ) from exc

    def _compute_diff_summary(self, action: FixAction) -> str:
        """Compute a concise text summary of changes for a single action."""
        before_lines = action.before.splitlines()
        after_lines = action.after.splitlines()

        if not action.before:
            return f"New file created ({len(after_lines)} lines)"

        added = max(0, len(after_lines) - len(before_lines))
        removed = max(0, len(before_lines) - len(after_lines))
        return f"+{added} / -{removed} lines modified"

    def _relative_path(self, path: str) -> str:
        """Render an action path relative to the repository for PR output."""
        candidate = Path(path)
        if not candidate.is_absolute():
            return candidate.as_posix()
        try:
            return candidate.resolve().relative_to(self.repo_path).as_posix()
        except (OSError, ValueError):
            # Never put an absolute host path into a PR body.
            return candidate.name

    def _generate_unified_diff(self, action: FixAction) -> str:
        """Generate unified diff string between before and after contents."""
        path_name = self._relative_path(action.path)
        diff_lines = list(
            difflib.unified_diff(
                action.before.splitlines(keepends=True),
                action.after.splitlines(keepends=True),
                fromfile=f"a/{path_name}",
                tofile=f"b/{path_name}",
            )
        )
        if not diff_lines:
            return f"# No textual diff recorded for {path_name}"
        return "".join(diff_lines)
