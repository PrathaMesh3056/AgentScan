# tests/test_supply_chain/test_transitive_graph.py
#
# Tests for lockfile dependency graph construction and transitive traceback.

from __future__ import annotations

from pathlib import Path

import networkx as nx

from agentscan.supply_chain.dep_scanner import (
    build_dependency_graph,
    find_dependency_chain,
    format_dependency_chain,
    scan_dependencies,
)

_SAMPLE_UV_LOCK = """version = 1
revision = 1
requires-python = ">=3.12"

[[package]]
name = "myapp"
version = "1.0.0"
source = { editable = "." }
dependencies = [
    { name = "framework-core" },
    { name = "direct-util" },
]

[[package]]
name = "framework-core"
version = "0.5.0"
dependencies = [
    { name = "vulnerable-lib" },
]

[[package]]
name = "vulnerable-lib"
version = "0.1.16"
dependencies = []

[[package]]
name = "direct-util"
version = "2.0.0"
dependencies = []
"""

_SAMPLE_POETRY_LOCK = """[[package]]
name = "myapp"
version = "1.0.0"

[package.dependencies]
framework-core = "*"

[[package]]
name = "framework-core"
version = "0.5.0"

[package.dependencies]
vulnerable-lib = "*"

[[package]]
name = "vulnerable-lib"
version = "0.1.16"
"""


class TestTransitiveGraph:
    def test_build_dependency_graph_from_uv_lock(self, tmp_path: Path) -> None:
        lock_file = tmp_path / "uv.lock"
        lock_file.write_text(_SAMPLE_UV_LOCK, encoding="utf-8")

        graph = build_dependency_graph(tmp_path)
        assert isinstance(graph, nx.DiGraph)
        assert "myapp" in graph
        assert "framework-core" in graph
        assert "vulnerable-lib" in graph
        assert "direct-util" in graph
        assert graph.nodes["myapp"]["version"] == "1.0.0"
        assert graph.nodes["myapp"]["is_root"] is True
        assert graph.has_edge("myapp", "framework-core")
        assert graph.has_edge("framework-core", "vulnerable-lib")

    def test_build_dependency_graph_from_poetry_lock(self, tmp_path: Path) -> None:
        lock_file = tmp_path / "poetry.lock"
        lock_file.write_text(_SAMPLE_POETRY_LOCK, encoding="utf-8")

        graph = build_dependency_graph(tmp_path)
        assert isinstance(graph, nx.DiGraph)
        assert "myapp" in graph
        assert graph.has_edge("myapp", "framework-core")
        assert graph.has_edge("framework-core", "vulnerable-lib")

    def test_find_dependency_chain_shortest_path(self, tmp_path: Path) -> None:
        lock_file = tmp_path / "uv.lock"
        lock_file.write_text(_SAMPLE_UV_LOCK, encoding="utf-8")
        graph = build_dependency_graph(tmp_path)

        chain = find_dependency_chain(graph, "vulnerable-lib")
        assert chain == ["myapp", "framework-core", "vulnerable-lib"]

        direct_chain = find_dependency_chain(graph, "direct-util")
        assert direct_chain == ["myapp", "direct-util"]

        assert find_dependency_chain(graph, "nonexistent-package") is None

    def test_format_dependency_chain(self, tmp_path: Path) -> None:
        lock_file = tmp_path / "uv.lock"
        lock_file.write_text(_SAMPLE_UV_LOCK, encoding="utf-8")
        graph = build_dependency_graph(tmp_path)

        chain = ["myapp", "framework-core", "vulnerable-lib"]
        formatted = format_dependency_chain(graph, chain)
        assert formatted == "myapp==1.0.0 -> framework-core==0.5.0 -> vulnerable-lib==0.1.16"

    def test_scan_dependencies_with_show_transitive(self, tmp_path: Path) -> None:
        # Create uv.lock containing langchain==0.1.16 (known CVE-2024-21513)
        uv_lock = tmp_path / "uv.lock"
        uv_lock.write_text(
            """version = 1
[[package]]
name = "my-ai-service"
version = "0.1.0"
source = { editable = "." }
dependencies = [
    { name = "agent-wrapper" },
]

[[package]]
name = "agent-wrapper"
version = "1.2.0"
dependencies = [
    { name = "langchain" },
]

[[package]]
name = "langchain"
version = "0.1.16"
dependencies = []
""",
            encoding="utf-8",
        )

        findings, checks = scan_dependencies(str(tmp_path), offline=True, show_transitive=True)
        assert len(findings) >= 1
        langchain_finding = next(f for f in findings if f.metadata.get("package") == "langchain")
        assert langchain_finding.metadata.get("transitive_chain") == [
            "my-ai-service",
            "agent-wrapper",
            "langchain",
        ]
        assert (
            "chain: my-ai-service==0.1.0 -> agent-wrapper==1.2.0 -> langchain==0.1.16"
            in langchain_finding.evidence
        )
