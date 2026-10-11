# agentscan/supply_chain/framework_auditor.py
#
# Static AST-based framework security auditor.
# Inspects Python code for architecture-specific vulnerabilities in:
#   - CrewAI (uncontained code execution, unsafe delegation, unisolated memory)
#   - LangGraph (missing human-in-the-loop interrupts, cyclic amplification, insecure checkpointers)
#   - AutoGen / AG2 (unsandboxed host code execution, unbounded GroupChat loops, human_input_mode='NEVER')
#
# Zero runtime dependencies beyond stdlib ast.
#
# Architecture: Strategy / Dispatcher pattern.
#   Each framework has a dedicated checker function.
#   _check_file_frameworks dispatches to them via FRAMEWORK_CHECKERS.

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from loguru import logger

from agentscan.core.models import Finding, Severity
from agentscan.supply_chain.coverage import collect_inputs, record_coverage

# ── AST Utilities ─────────────────────────────────────────────────────────────


def _get_call_name(call: ast.Call) -> str:
    """Extract the simple or qualified function/class name of a Call node."""
    func = call.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        if isinstance(func.value, ast.Name):
            return f"{func.value.id}.{func.attr}"
        return func.attr
    return ""


def _get_kwarg_constant(call: ast.Call, name: str) -> Any:
    """Return the Python constant value for keyword argument `name`, or None."""
    for kw in call.keywords:
        if kw.arg == name:
            if isinstance(kw.value, ast.Constant):
                return kw.value.value
            if (
                isinstance(kw.value, ast.UnaryOp)
                and isinstance(kw.value.operand, ast.Constant)
                and isinstance(kw.value.op, ast.USub)
                and isinstance(kw.value.operand.value, int | float)
            ):
                return -kw.value.operand.value
    return None


def _has_kwarg(call: ast.Call, name: str) -> bool:
    """Return True if keyword argument `name` is present in call."""
    return any(kw.arg == name for kw in call.keywords)


def _get_kwarg_node(call: ast.Call, name: str) -> ast.AST | None:
    """Return the AST node for keyword argument `name`."""
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return None


def _parse_dict_constants(dict_node: ast.Dict) -> dict[str, Any]:
    """Extract string keys and constant values from an ast.Dict node."""
    result: dict[str, Any] = {}
    for k, v in zip(dict_node.keys, dict_node.values, strict=False):
        if isinstance(k, ast.Constant) and isinstance(k.value, str):
            if isinstance(v, ast.Constant):
                result[k.value] = v.value
            elif isinstance(v, ast.Dict):
                result[k.value] = _parse_dict_constants(v)
            else:
                result[k.value] = None
    return result


def _detect_framework_imports(tree: ast.AST) -> tuple[bool, bool, bool]:
    """
    Return (has_crewai, has_langgraph, has_autogen) based on import statements
    or direct framework class references in the module.
    """
    has_crew = False
    has_lg = False
    has_auto = False

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.name.lower()
                if "crewai" in name:
                    has_crew = True
                elif "langgraph" in name:
                    has_lg = True
                elif "autogen" in name or "ag2" in name:
                    has_auto = True
        elif isinstance(node, ast.ImportFrom):
            mod = (node.module or "").lower()
            if "crewai" in mod:
                has_crew = True
            elif "langgraph" in mod:
                has_lg = True
            elif "autogen" in mod or "ag2" in mod:
                has_auto = True

    return has_crew, has_lg, has_auto


# ── Per-Framework Checker State ───────────────────────────────────────────────


class _LangGraphState:
    """Mutable accumulation state threaded across all AST nodes for LangGraph."""

    def __init__(self) -> None:
        self.has_tool_or_state_node: bool = False
        self.edges: list[tuple[str, str, int]] = []


# ── Per-Framework Checkers ────────────────────────────────────────────────────


def _check_crewai(
    node: ast.Call,
    call_name: str,
    simple_name: str,
    filepath: Path,
    has_crew: bool,
    _lg_state: _LangGraphState,
) -> list[Finding]:
    """Audit a single AST Call node for CrewAI security issues."""
    findings: list[Finding] = []

    if not ((has_crew or simple_name in {"Agent", "Crew"}) and simple_name in {"Agent", "Crew"}):
        return findings

    # SC-FW-CREW-001: Uncontained code execution
    if _get_kwarg_constant(node, "allow_code_execution") is True:
        findings.append(
            Finding(
                attack_id="SC-FW-CREW-001",
                attack_name="CrewAI Uncontained Code Execution",
                severity=Severity.CRITICAL,
                owasp_id="LLM06",
                description=(
                    f"CrewAI '{simple_name}' in '{filepath.name}' is instantiated with "
                    f"allow_code_execution=True. Running arbitrary Python code generated "
                    f"by LLM agents without an isolated Docker sandbox leads to host compromise."
                ),
                evidence=f"file={filepath}, line={node.lineno}",
                remediation=(
                    "Set allow_code_execution=False, or configure a secure containerized "
                    "sandbox executor (e.g. Docker / gVisor) with network egress controls."
                ),
                metadata={
                    "file": str(filepath),
                    "line": node.lineno,
                    "framework": "crewai",
                },
            )
        )

    # SC-FW-CREW-002: Unconstrained delegation with privileged tools
    if _get_kwarg_constant(node, "allow_delegation") is True and _has_kwarg(node, "tools"):
        tools_node = _get_kwarg_node(node, "tools")
        is_risky = False
        if isinstance(tools_node, ast.List | ast.Tuple):
            for elem in tools_node.elts:
                name_repr = ast.unparse(elem).lower() if hasattr(ast, "unparse") else ""
                if any(
                    k in name_repr
                    for k in ["bash", "exec", "shell", "db", "sql", "delete", "write"]
                ):
                    is_risky = True
                    break
        if is_risky or (isinstance(tools_node, ast.List | ast.Tuple) and len(tools_node.elts) > 0):
            findings.append(
                Finding(
                    attack_id="SC-FW-CREW-002",
                    attack_name="CrewAI Privilege Escalation via Delegation",
                    severity=Severity.HIGH,
                    owasp_id="LLM06",
                    description=(
                        f"CrewAI '{simple_name}' in '{filepath.name}' allows task delegation "
                        f"(allow_delegation=True) while equipped with executable/sensitive tools. "
                        f"Untrusted sub-agents can invoke this agent to escalate privileges."
                    ),
                    evidence=f"file={filepath}, line={node.lineno}",
                    remediation=(
                        "Set allow_delegation=False on agents with access to sensitive tools, "
                        "or segregate privileged tools into dedicated worker agents that cannot delegate."
                    ),
                    metadata={
                        "file": str(filepath),
                        "line": node.lineno,
                        "framework": "crewai",
                    },
                )
            )

    # SC-FW-CREW-003: Unisolated cross-session memory
    if _get_kwarg_constant(node, "memory") is True:
        findings.append(
            Finding(
                attack_id="SC-FW-CREW-003",
                attack_name="CrewAI Unisolated Cross-Session Memory",
                severity=Severity.HIGH,
                owasp_id="LLM03",
                description=(
                    f"CrewAI '{simple_name}' in '{filepath.name}' enables long-term memory (memory=True). "
                    f"Without per-user cryptographic tenant segregation, untrusted user inputs can poison "
                    f"shared vector memory and compromise future interactions."
                ),
                evidence=f"file={filepath}, line={node.lineno}",
                remediation=(
                    "Ensure memory embeddings and vector retrieval partition data strictly by tenant_id, "
                    "or disable shared memory (memory=False) when handling public/unauthenticated inputs."
                ),
                metadata={
                    "file": str(filepath),
                    "line": node.lineno,
                    "framework": "crewai",
                },
            )
        )

    return findings


def _check_langgraph(
    node: ast.Call,
    call_name: str,
    simple_name: str,
    filepath: Path,
    has_lg: bool,
    lg_state: _LangGraphState,
) -> list[Finding]:
    """Audit a single AST Call node for LangGraph security issues, updating shared state."""
    findings: list[Finding] = []

    # Presence of StateGraph/MessageGraph/Graph implies LangGraph context
    if simple_name in {"StateGraph", "MessageGraph", "Graph"}:
        lg_state.has_tool_or_state_node = True  # mark LG context
        # Note: has_lg flag update happens in the main dispatcher

    if not has_lg:
        return findings

    if simple_name in {"add_node", "ToolNode"}:
        lg_state.has_tool_or_state_node = True

    if (
        simple_name == "add_edge"
        and len(node.args) >= 2
        and isinstance(node.args[0], ast.Constant)
        and isinstance(node.args[1], ast.Constant)
    ):
        src = str(node.args[0].value)
        dst = str(node.args[1].value)
        lg_state.edges.append((src, dst, node.lineno))

    # SC-FW-LG-001: Missing human-in-the-loop interrupts on graph compile
    # Ensure this is a graph.compile(), NOT re.compile()
    is_regex_compile = (
        isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id in {"re", "regex", "pattern"}
    )
    if simple_name == "compile" and not is_regex_compile and lg_state.has_tool_or_state_node:
        has_interrupt = _has_kwarg(node, "interrupt_before") or _has_kwarg(node, "interrupt_after")
        interrupt_before_val = _get_kwarg_node(node, "interrupt_before")
        is_empty_interrupt = (
            isinstance(interrupt_before_val, ast.List | ast.Tuple)
            and len(interrupt_before_val.elts) == 0
        )

        if not has_interrupt or is_empty_interrupt:
            findings.append(
                Finding(
                    attack_id="SC-FW-LG-001",
                    attack_name="LangGraph Missing Human-in-the-Loop Interrupt",
                    severity=Severity.CRITICAL,
                    owasp_id="LLM06",
                    description=(
                        f"LangGraph workflow in '{filepath.name}' compiled without human-in-the-loop "
                        f"approval checkpoints (missing interrupt_before / interrupt_after). Tool "
                        f"executions with external side-effects run autonomously without human verification."
                    ),
                    evidence=f"file={filepath}, line={node.lineno}",
                    remediation=(
                        "Specify interrupt_before=['tools'] or interrupt_after on sensitive nodes "
                        "when compiling the state graph: graph.compile(interrupt_before=['tools'])."
                    ),
                    metadata={
                        "file": str(filepath),
                        "line": node.lineno,
                        "framework": "langgraph",
                    },
                )
            )

    # SC-FW-LG-004: Insecure in-memory persistence in production
    if simple_name == "MemorySaver":
        findings.append(
            Finding(
                attack_id="SC-FW-LG-004",
                attack_name="LangGraph Insecure In-Memory Checkpointer",
                severity=Severity.MEDIUM,
                owasp_id="LLM06",
                description=(
                    f"LangGraph 'MemorySaver' instantiated in '{filepath.name}'. In-memory checkpointers "
                    f"lack persistence, access boundaries, and encryption at rest for multi-tenant state."
                ),
                evidence=f"file={filepath}, line={node.lineno}",
                remediation=(
                    "Use encrypted durable checkpointers (e.g. PostgresSaver / MongoSaver with TLS and "
                    "tenant isolation) for production multi-user state machines."
                ),
                metadata={
                    "file": str(filepath),
                    "line": node.lineno,
                    "framework": "langgraph",
                },
            )
        )

    return findings


def _check_autogen(
    node: ast.Call,
    call_name: str,
    simple_name: str,
    filepath: Path,
    _has_auto: bool,
    _lg_state: _LangGraphState,
) -> list[Finding]:
    """Audit a single AST Call node for AutoGen / AG2 security issues."""
    findings: list[Finding] = []

    if simple_name in {"UserProxyAgent", "ConversableAgent", "AssistantAgent"}:
        config_node = _get_kwarg_node(node, "code_execution_config")

        # SC-FW-AUTO-001: Host code execution without Docker
        if config_node is not None:
            is_docker_disabled = False
            if isinstance(config_node, ast.Dict):
                parsed_dict = _parse_dict_constants(config_node)
                if parsed_dict.get("use_docker") is False or "use_docker" not in parsed_dict:
                    is_docker_disabled = True
            elif isinstance(config_node, ast.Constant) and config_node.value is not False:
                is_docker_disabled = True

            if is_docker_disabled:
                findings.append(
                    Finding(
                        attack_id="SC-FW-AUTO-001",
                        attack_name="AutoGen Unsandboxed Host Code Execution",
                        severity=Severity.CRITICAL,
                        owasp_id="LLM05",
                        description=(
                            f"AutoGen '{simple_name}' in '{filepath.name}' configures code execution "
                            f"without Docker containment (use_docker=False or omitted). LLM-generated code "
                            f"will execute directly on the host system."
                        ),
                        evidence=f"file={filepath}, line={node.lineno}",
                        remediation=(
                            "Set code_execution_config={'use_docker': True} or execute code via an "
                            "isolated containerized execution environment."
                        ),
                        metadata={
                            "file": str(filepath),
                            "line": node.lineno,
                            "framework": "autogen",
                        },
                    )
                )

            # SC-FW-AUTO-003: Fully autonomous mode with code execution or tools
            if _get_kwarg_constant(node, "human_input_mode") == "NEVER" and config_node is not None:
                findings.append(
                    Finding(
                        attack_id="SC-FW-AUTO-003",
                        attack_name="AutoGen Unattended Autonomous Execution",
                        severity=Severity.HIGH,
                        owasp_id="LLM06",
                        description=(
                            f"AutoGen '{simple_name}' in '{filepath.name}' is set to human_input_mode='NEVER' "
                            f"while configured with code execution. An attacker exploiting prompt injection "
                            f"can achieve unhindered code execution without human confirmation."
                        ),
                        evidence=f"file={filepath}, line={node.lineno}",
                        remediation=(
                            "Set human_input_mode='ALWAYS' or 'TERMINATE' for agents equipped with "
                            "code execution capabilities."
                        ),
                        metadata={
                            "file": str(filepath),
                            "line": node.lineno,
                            "framework": "autogen",
                        },
                    )
                )

    if simple_name in {"GroupChat", "GroupChatManager"}:
        # SC-FW-AUTO-002: Unbounded conversation rounds (DoS)
        max_round = _get_kwarg_constant(node, "max_round")
        if max_round is None or (isinstance(max_round, int | float) and max_round > 50):
            findings.append(
                Finding(
                    attack_id="SC-FW-AUTO-002",
                    attack_name="AutoGen Unbounded Multi-Agent GroupChat (DoS)",
                    severity=Severity.HIGH,
                    owasp_id="LLM10",
                    description=(
                        f"AutoGen '{simple_name}' in '{filepath.name}' has no max_round limit or "
                        f"an excessive limit ({max_round}). Unconstrained multi-agent dialogue loops "
                        f"can cause runaway API token consumption and application denial of service."
                    ),
                    evidence=f"file={filepath}, line={node.lineno}",
                    remediation=(
                        "Define a strict max_round limit (e.g. max_round=10 or 15) and verify "
                        "that termination conditions are clearly implemented."
                    ),
                    metadata={
                        "file": str(filepath),
                        "line": node.lineno,
                        "framework": "autogen",
                    },
                )
            )

    return findings


# ── Checker Dispatcher Registry ───────────────────────────────────────────────
#
# Maps a framework key to its checker function.
# Signature: (node, call_name, simple_name, filepath, has_framework_flag, lg_state) -> list[Finding]
#
# To add a new framework (e.g. LlamaIndex, Semantic Kernel):
#   1. Write _check_<framework>(node, call_name, simple_name, filepath, has_flag, lg_state)
#   2. Add it to FRAMEWORK_CHECKERS below
#   3. Update _detect_framework_imports to detect its imports

FRAMEWORK_CHECKERS = {
    "crewai": _check_crewai,
    "langgraph": _check_langgraph,
    "autogen": _check_autogen,
}


# ── File-Level Framework Auditor ──────────────────────────────────────────────


def _check_file_frameworks(filepath: Path, issues: list[str] | None = None) -> list[Finding]:
    """Parse a single Python file and inspect for agent framework security issues."""
    findings: list[Finding] = []
    try:
        source = filepath.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(filepath))
    except SyntaxError as e:
        if issues is not None:
            issues.append(f"{filepath.name}: SyntaxError")
        logger.warning(f"Skipping {filepath}: syntax error — {e}")
        return findings
    except Exception as e:
        if issues is not None:
            issues.append(f"{filepath.name}: {type(e).__name__}")
        logger.error(f"Failed to read {filepath}: {e}")
        return findings

    has_crew, has_lg, has_auto = _detect_framework_imports(tree)

    # Shared mutable state for LangGraph — threaded across all call nodes
    lg_state = _LangGraphState()

    framework_flags = {
        "crewai": has_crew,
        "langgraph": has_lg,
        "autogen": has_auto,
    }

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        call_name = _get_call_name(node)
        simple_name = call_name.split(".")[-1]

        # LangGraph: StateGraph/MessageGraph/Graph usage implies LG context
        if simple_name in {"StateGraph", "MessageGraph", "Graph"}:
            framework_flags["langgraph"] = True

        # Dispatch to each framework checker
        for fw_key, checker_fn in FRAMEWORK_CHECKERS.items():
            findings.extend(
                checker_fn(
                    node,
                    call_name,
                    simple_name,
                    filepath,
                    framework_flags[fw_key],
                    lg_state,
                )
            )

    # Post-walk: check for LangGraph cyclic edges (SC-FW-LG-002)
    edge_pairs = {(src, dst): lineno for src, dst, lineno in lg_state.edges}
    for (src, dst), lineno in list(edge_pairs.items()):
        if (dst, src) in edge_pairs and src != dst:
            findings.append(
                Finding(
                    attack_id="SC-FW-LG-002",
                    attack_name="LangGraph Unbounded Cyclic Edge Loop",
                    severity=Severity.HIGH,
                    owasp_id="LLM10",
                    description=(
                        f"LangGraph cycle detected between nodes '{src}' and '{dst}' in '{filepath.name}'. "
                        f"Cycles in multi-agent state machines can cause conversational lockup and prompt "
                        f"injection amplification unless strict recursion limits or conditional breaks are applied."
                    ),
                    evidence=f"file={filepath}, line={lineno}",
                    remediation=(
                        "Ensure conditional edges have termination predicates and invoke the graph with "
                        "a defensive recursion_limit (e.g. config={'recursion_limit': 10})."
                    ),
                    metadata={"file": str(filepath), "line": lineno, "framework": "langgraph"},
                )
            )
            del edge_pairs[(src, dst)]
            if (dst, src) in edge_pairs:
                del edge_pairs[(dst, src)]

    return findings


# ── Public Scanner ────────────────────────────────────────────────────────────


def scan_frameworks(path: str, *, coverage: list[dict] | None = None) -> tuple[list[Finding], int]:
    """
    Walk all .py files under `path` and check for agent framework security vulnerabilities.

    Supported Frameworks:
      - CrewAI (Agent, Crew)
      - LangGraph (StateGraph, compile, edges)
      - AutoGen / AG2 (UserProxyAgent, GroupChat, GroupChatManager)

    Returns:
        (findings, checks_run) where checks_run = number of .py files parsed.
    """
    issues: list[str] = []
    root = Path(path)
    filtered_files = collect_inputs(
        root,
        "*.py",
        issues,
        ignored_dirs={
            "__pycache__",
            "venv",
            "env",
            "site-packages",
            "node_modules",
            "build",
            "dist",
        },
        skip_hidden_dirs=True,
    )
    checks_run = len(filtered_files)

    all_findings: list[Finding] = []
    for py_file in filtered_files:
        previous_errors = len(issues)
        all_findings.extend(_check_file_frameworks(py_file, issues))
        if len(issues) > previous_errors:
            checks_run -= 1
    record_coverage(
        coverage,
        "frameworks",
        checks_run,
        source="python_ast",
        issues=issues,
        selected=len(filtered_files),
    )
    return all_findings, checks_run
