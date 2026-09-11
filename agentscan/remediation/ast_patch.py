# agentscan/remediation/ast_patch.py
#
# AST / code patching for insecure Python configurations:
#   SC-011: torch.load(...) -> add weights_only=True
#   SC-011: allow_dangerous_deserialization=True -> False
#   SC-013: shell=True -> False
#   SC-014: DEBUG = True -> DEBUG = False

from __future__ import annotations

import re
from pathlib import Path

from agentscan.core.models import Finding
from agentscan.remediation.models import FixAction


def _patch_torch_load(content: str) -> str:
    """Add weights_only=True to torch.load() calls that lack it."""

    # Matches torch.load(args) where weights_only is not in args
    def _repl(match: re.Match[str]) -> str:
        call = match.group(0)
        inner = match.group(1).strip()
        if "weights_only" in inner:
            return call
        if inner:
            return f"torch.load({inner}, weights_only=True)"
        return "torch.load(weights_only=True)"

    return re.sub(r"torch\.load\(([^)]*)\)", _repl, content)


def _patch_allow_dangerous_deserialization(content: str) -> str:
    """Flip allow_dangerous_deserialization=True to False."""
    return re.sub(
        r"allow_dangerous_deserialization\s*=\s*True",
        "allow_dangerous_deserialization=False",
        content,
    )


def _patch_shell_true(content: str) -> str:
    """Flip shell=True to shell=False in subprocess invocations."""
    return re.sub(
        r"\bshell\s*=\s*True\b",
        "shell=False",
        content,
    )


def _patch_debug_true(content: str) -> str:
    """Flip module-level DEBUG = True to DEBUG = False."""
    return re.sub(
        r"^(\s*DEBUG\s*=\s*)True(\s*(?:#.*)?)$",
        r"\g<1>False\g<2>",
        content,
        flags=re.MULTILINE,
    )


def plan_ast_patches(findings: list[Finding], root_path: Path) -> list[FixAction]:
    """Inspect AST / config findings and generate ast_patch FixActions."""
    ast_findings = [f for f in findings if f.attack_id in ("SC-011", "SC-012", "SC-013", "SC-014")]
    if not ast_findings or not root_path.exists():
        return []

    # Collect unique target files from metadata or scan directory
    target_files: set[Path] = set()
    for f in ast_findings:
        if "file" in f.metadata:
            p = Path(f.metadata["file"])
            if p.exists() and p.is_file():
                target_files.add(p.resolve())

    if not target_files:
        if root_path.is_file() and root_path.suffix == ".py":
            target_files.add(root_path.resolve())
        elif root_path.is_dir():
            target_files.update(p.resolve() for p in root_path.glob("**/*.py"))

    actions: list[FixAction] = []

    for file_path in sorted(target_files):
        try:
            content = file_path.read_text(encoding="utf-8")
        except Exception:
            continue

        updated = content
        for f in ast_findings:
            attack_id = f.attack_id
            if attack_id == "SC-011":
                updated = _patch_torch_load(updated)
                updated = _patch_allow_dangerous_deserialization(updated)
            elif attack_id in ("SC-012", "SC-013"):
                updated = _patch_shell_true(updated)
                updated = _patch_allow_dangerous_deserialization(updated)
            elif attack_id == "SC-014":
                updated = _patch_debug_true(updated)

        if updated != content:
            # Associate with the primary finding that triggered the change
            primary_id = ast_findings[0].attack_id
            for f in ast_findings:
                if f.metadata.get("file") == str(file_path):
                    primary_id = f.attack_id
                    break

            actions.append(
                FixAction(
                    path=str(file_path),
                    kind="ast_patch",
                    finding_id=primary_id,
                    before=content,
                    after=updated,
                    applied=False,
                )
            )

    return actions
