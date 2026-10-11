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

import ast
import json
from pathlib import Path

from agentscan.core.models import Finding
from agentscan.remediation.models import FixAction
from agentscan.remediation.paths import contained_path


def _patch_torch_load(content: str) -> str:
    """Patch the actual torch.load call, preserving surrounding source and nested args.

    Dynamic **kwargs may supply weights_only themselves, so leave those calls for
    manual review rather than introducing a duplicate-keyword runtime error.
    """
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return content
    lines = content.splitlines(keepends=True)

    def offset(line: int | None, column: int | None) -> int:
        # AST columns count UTF-8 bytes, including when the original text is Unicode.
        if line is None or column is None:
            raise ValueError("Parsed source node is missing its location")
        prefix = lines[line - 1].encode("utf-8")[:column].decode("utf-8")
        return sum(len(part) for part in lines[: line - 1]) + len(prefix)

    edits: list[tuple[int, int, str]] = []
    for node in ast.walk(tree):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "torch"
            and node.func.attr == "load"
        ):
            continue
        if any(keyword.arg is None for keyword in node.keywords):
            continue
        explicit = next((kw for kw in node.keywords if kw.arg == "weights_only"), None)
        if explicit is not None:
            if isinstance(explicit.value, ast.Constant) and explicit.value.value is False:
                value = explicit.value
                edits.append(
                    (
                        offset(value.lineno, value.col_offset),
                        offset(value.end_lineno, value.end_col_offset),
                        "True",
                    )
                )
            continue
        closing = offset(node.end_lineno, node.end_col_offset) - 1
        if not node.args and not node.keywords:
            insertion = "weights_only=True"
        else:
            arguments: list[ast.expr | ast.keyword] = [*node.args, *node.keywords]
            last = max(arguments, key=lambda item: (item.end_lineno or 0, item.end_col_offset or 0))
            tail = content[offset(last.end_lineno, last.end_col_offset) : closing]
            # The last argument may already have a trailing comma before a comment.
            trailing_comma = tail.lstrip().startswith(",")
            insertion = "weights_only=True" if trailing_comma else ", weights_only=True"
        edits.append((closing, closing, insertion))
    for start, end, replacement in sorted(edits, reverse=True):
        content = content[:start] + replacement + content[end:]
    return content


def _ast_edits(content: str, select) -> str:
    """Replace selected syntax nodes, leaving strings and comments intact."""
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return content
    lines = content.splitlines(keepends=True)

    def offset(line, column):
        return sum(len(part) for part in lines[: line - 1]) + len(
            lines[line - 1].encode("utf-8")[:column].decode("utf-8")
        )

    edits = []
    for node, replacement in select(tree):
        edits.append(
            (
                offset(node.lineno, node.col_offset),
                offset(node.end_lineno, node.end_col_offset),
                replacement,
            )
        )
    for start, end, value in sorted(edits, reverse=True):
        content = content[:start] + value + content[end:]
    return content


def _call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return _call_name(node.value) + "." + node.attr
    return ""


def _keyword_patch(content, keyword, before, after, call_names, predicate=lambda call: True):
    def select(tree):
        for call in ast.walk(tree):
            if not isinstance(call, ast.Call) or _call_name(call.func) not in call_names:
                continue
            if any(kw.arg is None for kw in call.keywords) or not predicate(call):
                continue
            for kw in call.keywords:
                if (
                    kw.arg == keyword
                    and isinstance(kw.value, ast.Constant)
                    and type(kw.value.value) is type(before)
                    and kw.value.value == before
                ):
                    yield kw.value, json.dumps(after) if isinstance(after, str) else repr(after)

    return _ast_edits(content, select)


def _patch_allow_dangerous_deserialization(content: str) -> str:
    return _keyword_patch(
        content,
        "allow_dangerous_deserialization",
        True,
        False,
        {"FAISS.load_local", "load_local", "create_pandas_dataframe_agent"},
    )


def _patch_numpy_allow_pickle(content: str) -> str:
    return _keyword_patch(content, "allow_pickle", True, False, {"np.load", "numpy.load"})


def _patch_shell_true(content: str) -> str:
    def safe_argv(call):
        command = (
            call.args[0]
            if call.args
            else next((kw.value for kw in call.keywords if kw.arg == "args"), None)
        )
        return (
            isinstance(command, (ast.List, ast.Tuple))
            and bool(command.elts)
            and all(
                isinstance(arg, ast.Constant) and isinstance(arg.value, str) for arg in command.elts
            )
        )

    # A shell command string cannot simply become argv: leave it for review.
    return _keyword_patch(
        content,
        "shell",
        True,
        False,
        {"subprocess." + name for name in ("run", "Popen", "call", "check_call", "check_output")},
        safe_argv,
    )


def _patch_debug_true(content: str) -> str:
    def select(tree):
        for node in tree.body:
            if (
                isinstance(node, ast.Assign)
                and isinstance(node.value, ast.Constant)
                and node.value.value is True
                and all(
                    isinstance(target, ast.Name) and target.id == "DEBUG" for target in node.targets
                )
            ):
                yield node.value, "False"

    return _ast_edits(content, select)


def _patch_crew_code_execution(content: str) -> str:
    return _keyword_patch(content, "allow_code_execution", True, False, {"Agent", "crewai.Agent"})


def _patch_autogen_use_docker(content: str) -> str:
    def select(tree):
        for call in ast.walk(tree):
            if not isinstance(call, ast.Call) or _call_name(call.func).split(".")[-1] not in {
                "UserProxyAgent",
                "ConversableAgent",
                "AssistantAgent",
            }:
                continue
            if any(kw.arg is None for kw in call.keywords):
                continue
            config = next(
                (kw.value for kw in call.keywords if kw.arg == "code_execution_config"), None
            )
            if isinstance(config, ast.Dict) and all(key is not None for key in config.keys):
                for key, value in zip(config.keys, config.values, strict=True):
                    if (
                        isinstance(key, ast.Constant)
                        and key.value == "use_docker"
                        and isinstance(value, ast.Constant)
                        and value.value is False
                    ):
                        yield value, "True"

    return _ast_edits(content, select)


def _patch_autogen_human_input_mode(content: str) -> str:
    return _keyword_patch(
        content,
        "human_input_mode",
        "NEVER",
        "ALWAYS",
        {
            prefix + name
            for prefix in ("", "autogen.", "ag2.")
            for name in ("UserProxyAgent", "AssistantAgent", "ConversableAgent")
        },
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
            p = contained_path(root_path, str(f.metadata["file"]))
            if p.exists() and p.is_file():
                target_files.add(p)

    if not target_files:
        if root_path.is_file() and root_path.suffix == ".py":
            target_files.add(root_path.resolve())
        elif root_path.is_dir():
            target_files.update(contained_path(root_path, p) for p in root_path.glob("**/*.py"))

    actions: list[FixAction] = []

    for file_path in sorted(target_files):
        try:
            content = file_path.read_text(encoding="utf-8")
        except Exception:
            continue

        updated = content
        for f in ast_findings:
            if (
                f.metadata.get("file")
                and contained_path(root_path, str(f.metadata["file"])) != file_path
            ):
                continue
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
