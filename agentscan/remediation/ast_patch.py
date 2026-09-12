# agentscan/remediation/ast_patch.py
#
# AST / code patching for insecure Python configurations & agent frameworks:
#   SC-011: torch.load(...) -> add weights_only=True
#   SC-011: allow_dangerous_deserialization=True -> False
#   SC-013: shell=True -> False
#   SC-014: DEBUG = True -> DEBUG = False
#   SC-FW-CREW-001: allow_code_execution=True -> False
#   SC-FW-AUTO-001: 'use_docker': False -> True
#   SC-FW-AUTO-003: human_input_mode='NEVER' -> 'ALWAYS'

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


def _patch_numpy_allow_pickle(content: str) -> str:
    """Flip allow_pickle=True to allow_pickle=False in numpy.load."""
    return re.sub(
        r"\ballow_pickle\s*=\s*True\b",
        "allow_pickle=False",
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


def _patch_crew_code_execution(content: str) -> str:
    """Flip allow_code_execution=True to allow_code_execution=False."""
    return re.sub(
        r"\ballow_code_execution\s*=\s*True\b",
        "allow_code_execution=False",
        content,
    )


def _patch_autogen_use_docker(content: str) -> str:
    """Flip 'use_docker': False to 'use_docker': True."""
    return re.sub(
        r"(['\"]use_docker['\"]\s*:\s*)False",
        r"\g<1>True",
        content,
    )


def _patch_autogen_human_input_mode(content: str) -> str:
    """Flip human_input_mode='NEVER' to 'ALWAYS'."""
    return re.sub(
        r"\bhuman_input_mode\s*=\s*['\"]NEVER['\"]",
        'human_input_mode="ALWAYS"',
        content,
    )


def plan_ast_patches(findings: list[Finding], root_path: Path) -> list[FixAction]:
    """Inspect AST / config / framework findings and generate ast_patch FixActions."""
    supported_ids = (
        "SC-011",
        "SC-012",
        "SC-013",
        "SC-014",
        "SC-FW-CREW-001",
        "SC-FW-AUTO-001",
        "SC-FW-AUTO-003",
    )
    ast_findings = [f for f in findings if f.attack_id in supported_ids]
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
                updated = _patch_numpy_allow_pickle(updated)
            elif attack_id in ("SC-012", "SC-013"):
                updated = _patch_shell_true(updated)
                updated = _patch_allow_dangerous_deserialization(updated)
            elif attack_id == "SC-014":
                updated = _patch_debug_true(updated)
            elif attack_id == "SC-FW-CREW-001":
                updated = _patch_crew_code_execution(updated)
            elif attack_id == "SC-FW-AUTO-001":
                updated = _patch_autogen_use_docker(updated)
            elif attack_id == "SC-FW-AUTO-003":
                updated = _patch_autogen_human_input_mode(updated)

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
