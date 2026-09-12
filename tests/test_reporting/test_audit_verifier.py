# tests/test_reporting/test_audit_verifier.py
#
# Test suite for Cryptographic Audit Verification (SHA-256 canonical hashing + HMAC certificates).

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from agentscan.cli import app
from agentscan.reporting.audit_verifier import (
    canonicalize_report,
    sign_audit_report,
    verify_audit_certificate,
)

runner = CliRunner()


def test_canonicalize_report_deterministic():
    data1 = {"b": 2, "a": 1, "nested": {"z": 10, "y": 20}}
    data2 = {"nested": {"y": 20, "z": 10}, "a": 1, "b": 2}
    # Should produce identical canonical bytes
    assert canonicalize_report(data1) == canonicalize_report(data2)

    # Should ignore certificate field
    data1_with_cert = dict(data1)
    data1_with_cert["certificate"] = {"signature": "abc"}
    assert canonicalize_report(data1_with_cert) == canonicalize_report(data1)


def test_sign_and_verify_valid():
    report = {
        "target": "http://localhost:8000",
        "score": 88.5,
        "status": "PASS",
        "findings": [
            {"attack_id": "SC-001", "severity": "MEDIUM", "description": "Minor pin issue"}
        ],
    }
    cert = sign_audit_report(report, secret_key="super-secret-key")
    assert cert["algorithm"] == "HMAC-SHA256"
    assert "report_sha256" in cert
    assert "signature" in cert

    is_valid, reason = verify_audit_certificate(report, cert, secret_key="super-secret-key")
    assert is_valid is True
    assert "Certificate valid" in reason


def test_verify_detects_content_tampering():
    report = {
        "target": "http://localhost:8000",
        "score": 42.0,
        "findings": [{"attack_id": "ATK-001", "severity": "CRITICAL"}],
    }
    cert = sign_audit_report(report)

    # Adversary tampers with score to pretend system is secure
    tampered_report = dict(report)
    tampered_report["score"] = 99.0

    is_valid, reason = verify_audit_certificate(tampered_report, cert)
    assert is_valid is False
    assert "Digest mismatch" in reason


def test_verify_detects_invalid_hmac_secret():
    report = {"score": 90.0, "findings": []}
    cert = sign_audit_report(report, secret_key="correct-key")

    # Verifier uses wrong secret key
    is_valid, reason = verify_audit_certificate(report, cert, secret_key="wrong-key")
    assert is_valid is False
    assert "HMAC signature mismatch" in reason


def test_cli_verify_sign_and_check(tmp_path: Path):
    report_file = tmp_path / "report.json"
    report_data = {
        "target": "https://agent.example.com",
        "score": 75.0,
        "findings": [],
    }
    report_file.write_text(json.dumps(report_data), encoding="utf-8")

    # 1. Sign the report via CLI
    sign_res = runner.invoke(
        app, ["verify", str(report_file), "--sign", "--key", "audit-secret-123"]
    )
    assert sign_res.exit_code == 0
    assert "Report Cryptographically Certified" in sign_res.output

    # Verify certificate was embedded
    updated_data = json.loads(report_file.read_text(encoding="utf-8"))
    assert "certificate" in updated_data
    assert updated_data["certificate"]["algorithm"] == "HMAC-SHA256"

    # 2. Verify legitimate report
    verify_res = runner.invoke(app, ["verify", str(report_file), "--key", "audit-secret-123"])
    assert verify_res.exit_code == 0
    assert "CRYPTOGRAPHIC AUDIT VERIFICATION PASSED" in verify_res.output

    # 3. Tamper with report file
    updated_data["score"] = 100.0
    report_file.write_text(json.dumps(updated_data), encoding="utf-8")

    # 4. Verification should now fail
    fail_res = runner.invoke(app, ["verify", str(report_file), "--key", "audit-secret-123"])
    assert fail_res.exit_code == 1
    assert "CRYPTOGRAPHIC AUDIT VERIFICATION FAILED" in fail_res.output
