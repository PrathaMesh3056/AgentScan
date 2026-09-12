# tests/test_supply_chain/test_expanded_cves.py
#
# Tests for expanded offline AI/ML CVE database and specifier range matching.

from __future__ import annotations

from pathlib import Path

from agentscan.supply_chain.dep_scanner import (
    _load_vuln_db,
    _scan_offline,
    _scan_range_dependencies,
    scan_dependencies,
)


class TestExpandedCVEs:
    def test_database_has_expanded_coverage(self) -> None:
        db = _load_vuln_db()
        assert len(db) >= 15
        packages = {str(entry["package"]).lower() for entry in db}
        expected_pkgs = {
            "langchain",
            "transformers",
            "huggingface-hub",
            "chromadb",
            "llama-index",
            "openai",
            "gradio",
            "llama-cpp-python",
            "litellm",
            "python-multipart",
            "onnx",
            "torch",
        }
        for pkg in expected_pkgs:
            assert pkg in packages, f"Expected {pkg} in offline CVE database"

    def test_all_entries_valid_schema(self) -> None:
        db = _load_vuln_db()
        valid_sevs = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        for entry in db:
            assert "package" in entry
            assert "bad_version" in entry
            assert "cve_id" in entry
            assert str(entry["cve_id"]).startswith("CVE-")
            assert str(entry["severity"]).upper() in valid_sevs
            assert "fix_version" in entry
            assert "description" in entry
            assert len(str(entry["description"]).strip()) > 10

    def test_exact_pin_matching_new_cves(self) -> None:
        deps = [
            ("gradio", "4.18.0"),
            ("llama-cpp-python", "0.2.25"),
            ("litellm", "1.27.14"),
            ("onnx", "1.15.0"),
            ("torch", "2.1.2"),
        ]
        findings = _scan_offline(deps)
        cves = {f.metadata.get("cve_id") for f in findings}
        assert "CVE-2024-1561" in cves  # gradio
        assert "CVE-2024-34359" in cves  # llama-cpp-python
        assert "CVE-2024-39701" in cves  # litellm
        assert "CVE-2024-27318" in cves  # onnx
        assert "CVE-2024-27758" in cves  # torch

    def test_range_specifier_matching_new_cves(self) -> None:
        range_deps = [
            ("gradio", "<4.19.0"),
            ("torch", ">=2.0.0,<2.2.0"),
            ("litellm", "<=1.27.14"),
        ]
        findings = _scan_range_dependencies(range_deps)
        assert len(findings) >= 3
        cves = {f.metadata.get("cve_id") for f in findings}
        assert "CVE-2024-1561" in cves
        assert "CVE-2024-27758" in cves
        assert "CVE-2024-39701" in cves

    def test_safe_range_specifiers_do_not_match(self) -> None:
        safe_range_deps = [
            ("gradio", ">=4.19.0"),
            ("torch", ">=2.2.0"),
            ("litellm", ">=1.28.0"),
            ("llama-cpp-python", ">=0.2.26"),
        ]
        findings = _scan_range_dependencies(safe_range_deps)
        assert len(findings) == 0

    def test_offline_scan_dependencies_from_file(self, tmp_path: Path) -> None:
        req_file = tmp_path / "requirements.txt"
        req_file.write_text(
            "gradio==4.18.0\ntorch<2.2.0\nrequests>=2.31.0\n",
            encoding="utf-8",
        )
        findings, score = scan_dependencies(str(tmp_path), offline=True)
        assert len(findings) >= 2
        cves = {f.metadata.get("cve_id") for f in findings}
        assert "CVE-2024-1561" in cves
        assert "CVE-2024-27758" in cves
