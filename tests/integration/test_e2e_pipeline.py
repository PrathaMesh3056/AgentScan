# tests/integration/test_e2e_pipeline.py
#
# End-to-end integration test validating the full lifecycle:
# Scan Target -> Find Vulnerability -> Fix via Remediation -> Rescan to Verify Resolution.

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest
from typer.testing import CliRunner

from agentscan._cli import app
from agentscan.remediation.git_pr import GitPRAutomator
from agentscan.supply_chain.dep_scanner import scan_dependencies


@pytest.fixture
def target_repo(tmp_path: Path) -> Path:
    """Initialize a disposable repository with a synthetic advisory and unsafe code."""
    subprocess.run(["git", "init"], cwd=str(tmp_path), check=True, capture_output=True)
    subprocess.run(
        ["git", "config", "user.email", "ci-bot@agentscan.dev"],
        cwd=str(tmp_path),
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "AgentScan CI"],
        cwd=str(tmp_path),
        check=True,
        capture_output=True,
    )

    # This package is test data, not an installed dependency or a real advisory.
    reqs_file = tmp_path / "requirements.txt"
    reqs_file.write_text("agentscan-e2e-demo==0.1.0\n", encoding="utf-8")

    # Insecure AST code: torch.load without weights_only triggers SC-011
    code_file = tmp_path / "agent.py"
    code_file.write_text("import torch\ntorch.load('weights.pt')\n", encoding="utf-8")

    subprocess.run(["git", "add", "."], cwd=str(tmp_path), check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "initial: vulnerable agent repository"],
        cwd=str(tmp_path),
        check=True,
        capture_output=True,
    )
    return tmp_path


def test_full_e2e_pipeline_scan_find_fix_rescan(target_repo: Path, respx_mock) -> None:
    """
    Phase 6 Integration DoD:
    Executes full pipeline: scan target -> find vulnerability -> fix -> verify fix eliminates
    the finding on rescan.
    """
    runner = CliRunner()

    # Mock only the advisory HTTP boundary; run parsing, assessment, remediation
    # and Git automation normally. Unmatched requests are blocked by respx.
    advisory_id = "OSV-TEST-E2E-001"

    def advisory_batch(request):
        assert json.loads(request.content) == {
            "queries": [
                {
                    "package": {"name": "agentscan-e2e-demo", "ecosystem": "PyPI"},
                    "version": "0.1.0",
                }
            ]
        }
        return httpx.Response(200, json={"results": [{"vulns": [{"id": advisory_id}]}]})

    batch_route = respx_mock.post("https://api.osv.dev/v1/querybatch").mock(
        side_effect=advisory_batch
    )
    respx_mock.get(f"https://api.osv.dev/v1/vulns/{advisory_id}").respond(
        200,
        json={
            "id": advisory_id,
            "summary": "Synthetic vulnerable dependency for the integration test.",
            "database_specific": {"severity": "HIGH"},
            "affected": [
                {
                    "package": {"name": "agentscan-e2e-demo", "ecosystem": "PyPI"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "0"}, {"fixed": "0.1.1"}],
                        }
                    ],
                }
            ],
        },
    )

    # Step 1: Initial Scan & Audit - confirm vulnerabilities exist
    initial_findings, _ = scan_dependencies(str(target_repo))
    sc001_initial = [f for f in initial_findings if f.attack_id == "SC-001"]
    assert len(sc001_initial) >= 1, "Expected SC-001 vulnerable dependency finding before fix"

    # Step 2: Apply Remediation via CLI with Git PR Automation
    with patch.object(
        GitPRAutomator,
        "create_pr",
        return_value="https://github.com/agentscan/demo-agent/pull/101",
    ):
        fix_result = runner.invoke(
            app,
            [
                "fix",
                str(target_repo),
                "--apply",
                "--pr",
                "--branch",
                "fix/automated-e2e-patch",
            ],
        )

        assert fix_result.exit_code == 0, f"Fix failed: {fix_result.stdout}"
        assert "Successfully applied" in fix_result.stdout

    # Verify Git branch was created and committed
    branch_proc = subprocess.run(
        ["git", "rev-parse", "--abbrev-ref", "HEAD"],
        cwd=str(target_repo),
        capture_output=True,
        text=True,
        check=True,
    )
    assert branch_proc.stdout.strip() == "fix/automated-e2e-patch"

    # Verify file content modified
    reqs_after = (target_repo / "requirements.txt").read_text(encoding="utf-8")
    assert reqs_after.strip() == "agentscan-e2e-demo>=0.1.1"

    # Step 3: Rescan to confirm vulnerability is eliminated
    rescan_findings, _ = scan_dependencies(str(target_repo))
    sc001_after = [f for f in rescan_findings if f.attack_id == "SC-001"]
    assert len(sc001_after) == 0, (
        f"Expected zero SC-001 findings after remediation, but found: {sc001_after}"
    )
    # Initial assessment and the CLI each queried the exact vulnerable pin.
    # The resulting range is assessed against the bundled database on rescan.
    assert batch_route.call_count == 2
