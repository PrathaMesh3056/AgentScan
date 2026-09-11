# tests/test_supply_chain/test_semgrep_auditor.py
#
# Semgrep auditor tests mock the binary so CI does not require semgrep.

from __future__ import annotations

import json
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

from agentscan.supply_chain.semgrep_auditor import default_rules_path, scan_semgrep

_FIXTURE = Path("tests/fixtures/supply_chain")

_MOCK_JSON = {
    "paths": {"scanned": ["semgrep_samples.py"]},
    "results": [
        {
            "check_id": "agentscan.unsafe-pickle-loads",
            "path": "semgrep_samples.py",
            "start": {"line": 12},
            "extra": {
                "severity": "ERROR",
                "message": "pickle.loads() can execute arbitrary code from untrusted bytes.",
                "metadata": {"agentscan_id": "SC-015", "owasp_id": "LLM05"},
            },
        },
        {
            "check_id": "agentscan.unsafe-torch-load",
            "path": "semgrep_samples.py",
            "start": {"line": 16},
            "extra": {
                "severity": "ERROR",
                "message": "torch.load() without weights_only=True is unsafe pickle.",
                "metadata": {"agentscan_id": "SC-011", "owasp_id": "LLM05"},
            },
        },
        {
            "check_id": "agentscan.subprocess-popen-shell",
            "path": "semgrep_samples.py",
            "start": {"line": 20},
            "extra": {
                "severity": "ERROR",
                "message": "subprocess.Popen(..., shell=True) is unsafe.",
                "metadata": {"agentscan_id": "SC-016", "owasp_id": "LLM05"},
            },
        },
        {
            "check_id": "agentscan.os-system",
            "path": "semgrep_samples.py",
            "start": {"line": 21},
            "extra": {
                "severity": "ERROR",
                "message": "os.system() invokes a shell unsafely.",
                "metadata": {"agentscan_id": "SC-016", "owasp_id": "LLM05"},
            },
        },
        {
            "check_id": "agentscan.prompt-fstring-user-input",
            "path": "semgrep_samples.py",
            "start": {"line": 25},
            "extra": {
                "severity": "WARNING",
                "message": "f-string interpolates user_input into a prompt.",
                "metadata": {"agentscan_id": "SC-017", "owasp_id": "LLM01"},
            },
        },
    ],
}


class TestSemgrepAuditor:
    def test_rules_file_exists(self) -> None:
        assert default_rules_path().is_file()

    def test_skips_when_semgrep_missing(self) -> None:
        with patch("agentscan.supply_chain.semgrep_auditor.shutil.which", return_value=None):
            findings, checks = scan_semgrep(str(_FIXTURE))
        assert findings == []
        assert checks == 0

    def test_parses_mocked_semgrep_json(self) -> None:
        completed = CompletedProcess(
            args=["semgrep"],
            returncode=1,
            stdout=json.dumps(_MOCK_JSON),
            stderr="",
        )
        with (
            patch("agentscan.supply_chain.semgrep_auditor.shutil.which", return_value="semgrep"),
            patch("agentscan.supply_chain.semgrep_auditor.subprocess.run", return_value=completed),
        ):
            findings, checks = scan_semgrep(str(_FIXTURE))

        assert checks == 1
        ids = {f.attack_id for f in findings}
        assert "SC-015" in ids
        assert "SC-011" in ids
        assert "SC-016" in ids
        assert "SC-017" in ids
        pickle_hit = next(f for f in findings if f.attack_id == "SC-015")
        assert pickle_hit.metadata["semgrep_check_id"] == "agentscan.unsafe-pickle-loads"
        assert pickle_hit.severity.value == "CRITICAL"

    def test_skips_on_semgrep_error_exit(self) -> None:
        completed = CompletedProcess(args=["semgrep"], returncode=2, stdout="", stderr="boom")
        with (
            patch("agentscan.supply_chain.semgrep_auditor.shutil.which", return_value="semgrep"),
            patch("agentscan.supply_chain.semgrep_auditor.subprocess.run", return_value=completed),
        ):
            findings, checks = scan_semgrep(str(_FIXTURE))
        assert findings == []
        assert checks == 0
