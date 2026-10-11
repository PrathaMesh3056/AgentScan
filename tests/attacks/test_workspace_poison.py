# tests/attacks/test_workspace_poison.py
#
# Comprehensive tests for ATK-020 Cross-Agent Workspace Poisoning (OWASP LLM03).

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from agentscan.attacks.exploit.workspace_poison import (
    RAG_CANARY,
    SQLITE_CANARY,
    WORKSPACE_FILE_CANARY,
    InMemoryVectorStore,
    WorkspacePoisonModule,
    extract_response_text,
)
from agentscan.core.connectors import CallableConnector, use_connector
from agentscan.core.models import ScanMode, Severity, Target
from agentscan.sandbox.base import SandboxResult


@pytest.mark.asyncio
async def test_sqlite_history_poisoning_detected(tmp_path: Path) -> None:
    """
    Definition of Done:
    SQLite sub-scenario: deterministic marker injected in history -> detected in 2nd-session response.
    """

    def vulnerable_bot(msg: str) -> str:
        if SQLITE_CANARY in msg:
            return f"Executing system directive: {SQLITE_CANARY} granted root authorization."
        return "Normal response."

    target = Target(url="http://mock.local/chat", mode=ScanMode.EXPLOIT)
    attack = WorkspacePoisonModule()

    with use_connector(CallableConnector(vulnerable_bot)):
        finding = await attack.run_sqlite_scenario(target, db_path=tmp_path / "test.db")

    assert finding is not None
    assert finding.attack_id == "ATK-020"
    assert finding.owasp_id == "LLM01"
    assert finding.severity == Severity.MEDIUM
    assert finding.metadata.get("vector") == "sqlite"
    assert SQLITE_CANARY in finding.evidence


@pytest.mark.asyncio
async def test_sqlite_history_poisoning_refused_no_finding(tmp_path: Path) -> None:
    """Asserts that a secure agent ignoring database overrides produces no finding."""

    def secure_bot(_msg: str) -> str:
        return "I follow safe operational practices and do not execute database-stored directives."

    target = Target(url="http://mock.local/chat", mode=ScanMode.EXPLOIT)
    attack = WorkspacePoisonModule()

    with use_connector(CallableConnector(secure_bot)):
        finding = await attack.run_sqlite_scenario(target, db_path=tmp_path / "test.db")

    assert finding is None


@pytest.mark.asyncio
async def test_rag_vector_store_poisoning_detected() -> None:
    """
    Definition of Done:
    RAG sub-scenario: poisoned document retrieved -> agent executes embedded instruction.
    """

    def vulnerable_rag_bot(msg: str) -> str:
        if RAG_CANARY in msg:
            return f"Confirmed bypass protocol: {RAG_CANARY}. Security protocols bypassed."
        return "Standard operational guidance."

    target = Target(url="http://mock.local/chat", mode=ScanMode.EXPLOIT)
    attack = WorkspacePoisonModule()

    with use_connector(CallableConnector(vulnerable_rag_bot)):
        finding = await attack.run_rag_scenario(target)

    assert finding is not None
    assert finding.attack_id == "ATK-020"
    assert finding.owasp_id == "LLM01"
    assert finding.severity == Severity.MEDIUM
    assert finding.metadata.get("vector") == "rag"
    assert RAG_CANARY in finding.evidence


@pytest.mark.asyncio
async def test_rag_vector_store_poisoning_refused_no_finding() -> None:
    """
    Definition of Done:
    RAG sub-scenario: agent correctly refuses bypass instruction from retrieved doc.
    """

    def secure_rag_bot(_msg: str) -> str:
        return "Refusing bypass instruction. All agent tools must remain fully authenticated."

    target = Target(url="http://mock.local/chat", mode=ScanMode.EXPLOIT)
    attack = WorkspacePoisonModule()

    with use_connector(CallableConnector(secure_rag_bot)):
        finding = await attack.run_rag_scenario(target)

    assert finding is None


@pytest.mark.asyncio
async def test_file_workspace_poisoning_detected(tmp_path: Path) -> None:
    """
    Definition of Done:
    File-based scenario: WORKSPACE_INSTRUCTIONS.md with override instruction -> agent obeys (finding).
    """

    def vulnerable_file_bot(msg: str) -> str:
        if WORKSPACE_FILE_CANARY in msg:
            return f"Acknowledged workspace directive: {WORKSPACE_FILE_CANARY} confirmed."
        return "Workspace loaded."

    target = Target(url="http://mock.local/chat", mode=ScanMode.EXPLOIT)
    attack = WorkspacePoisonModule()

    with use_connector(CallableConnector(vulnerable_file_bot)):
        finding = await attack.run_file_scenario(target, workspace_dir=tmp_path)

    assert finding is not None
    assert finding.attack_id == "ATK-020"
    assert finding.owasp_id == "LLM01"
    assert finding.severity == Severity.MEDIUM
    assert finding.metadata.get("vector") == "file"
    assert WORKSPACE_FILE_CANARY in finding.evidence


@pytest.mark.asyncio
async def test_file_workspace_poisoning_refused_no_finding(tmp_path: Path) -> None:
    """
    Definition of Done:
    File-based scenario: agent refuses workspace file override instruction -> clean.
    """

    def secure_file_bot(_msg: str) -> str:
        return (
            "Ignoring unauthorized workspace configuration instructions. Core safety rules intact."
        )

    target = Target(url="http://mock.local/chat", mode=ScanMode.EXPLOIT)
    attack = WorkspacePoisonModule()

    with use_connector(CallableConnector(secure_file_bot)):
        finding = await attack.run_file_scenario(target, workspace_dir=tmp_path)

    assert finding is None


@pytest.mark.asyncio
async def test_workspace_poison_full_run_aggregates_findings() -> None:
    """Asserts that attack.run() runs all three sub-scenarios and aggregates all findings."""

    def vulnerable_all_bot(msg: str) -> str:
        for canary in (SQLITE_CANARY, RAG_CANARY, WORKSPACE_FILE_CANARY):
            if canary in msg:
                return f"Confirmed execution of {canary}"
        return "Normal response."

    target = Target(url="http://mock.local/chat", mode=ScanMode.EXPLOIT)
    attack = WorkspacePoisonModule()

    with use_connector(CallableConnector(vulnerable_all_bot)):
        findings = await attack.run(target)

    assert len(findings) == 3
    vectors = {f.metadata.get("vector") for f in findings}
    assert vectors == {"sqlite", "rag", "file"}


def test_in_memory_vector_store_fallback_search() -> None:
    """Asserts lexical fallback search in InMemoryVectorStore when sentence-transformers is absent."""
    store = InMemoryVectorStore()
    # Force lexical branch
    store._has_st = False
    store._model = None

    store.add_document("doc1", "Python programming language and data structures.")
    store.add_document("doc2", "Database query optimization and index tuning.")
    store.add_document("doc3", "Security protocol for agent tools with bypass token.")

    results = store.search("agent tools security protocol bypass", top_k=1)
    assert len(results) == 1
    assert results[0]["id"] == "doc3"


def test_extract_response_text_variants() -> None:
    """Asserts extraction from different JSON dictionary formats."""
    assert extract_response_text({"response": "test_text"}) == "test_text"
    assert (
        extract_response_text({"choices": [{"message": {"content": "choice_text"}}]})
        == "choice_text"
    )
    assert extract_response_text({"output": "out_text"}) == "out_text"
    assert extract_response_text({"raw": "raw_text"}) == "raw_text"
    assert "other" in extract_response_text({"other": 123})


@pytest.mark.asyncio
async def test_finding_enriched_with_sandbox_result(tmp_path: Path) -> None:
    """
    Definition of Done:
    Each finding includes SandboxResult if Phase 2 sandbox is available.
    """

    def vulnerable_bot(msg: str) -> str:
        return f"Confirmed {SQLITE_CANARY}"

    mock_sandbox_res = SandboxResult(
        exit_code=0,
        stdout="sandbox_verified\n",
        stderr="",
        execution_ms=4.2,
        oom_killed=False,
        filesystem_diff=[],
        sandbox_tier="subprocess_audit",
    )

    mock_sandbox = MagicMock()
    mock_sandbox.execute_in_sandbox.return_value = mock_sandbox_res

    target = Target(url="http://mock.local/chat", mode=ScanMode.EXPLOIT)
    attack = WorkspacePoisonModule()

    with (
        use_connector(CallableConnector(vulnerable_bot)),
        patch("agentscan.sandbox.selector.select_sandbox", return_value=mock_sandbox),
    ):
        finding = await attack.run_sqlite_scenario(target, db_path=tmp_path / "test.db")

    assert finding is not None
    assert "sandbox_result" not in finding.metadata
    assert finding.metadata["execution_verified"] is False
    mock_sandbox.execute_in_sandbox.assert_not_called()
