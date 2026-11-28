# tests/test_reporting/test_certificate_envelope.py
#
# Regression tests for QA-084: certificate metadata must be covered by a
# signed canonical envelope and must match the report content.

from __future__ import annotations

import copy
import hashlib
import hmac
import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from agentscan.cli import app
from agentscan.reporting.audit_verifier import (
    canonicalize_certificate_envelope,
    sign_audit_report,
    verify_audit_certificate,
)

KEY = "synthetic-certificate-envelope-key-32-bytes"
runner = CliRunner()


def _report() -> dict[str, Any]:
    return {
        "target": "http://127.0.0.1:9999",
        "score": 49,
        "status": "HIGH RISK",
        "findings": [
            {"attack_id": "ATK-001", "severity": "HIGH"},
            {"attack_id": "ATK-002", "severity": "MEDIUM"},
        ],
    }


def _set_path(certificate: dict[str, Any], path: tuple[str, ...], value: Any) -> None:
    target: Any = certificate
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = value


def _resign_envelope(certificate: dict[str, Any]) -> None:
    certificate["envelope_signature"] = hmac.new(
        KEY.encode("utf-8"),
        canonicalize_certificate_envelope(certificate),
        hashlib.sha256,
    ).hexdigest()


def _write_report(path: Path, certificate: dict[str, Any] | None = None) -> None:
    report = _report()
    if certificate is not None:
        report["certificate"] = certificate
    path.write_text(json.dumps(report), encoding="utf-8")


def test_newly_signed_certificate_verifies() -> None:
    report = _report()
    certificate = sign_audit_report(report, secret_key=KEY)

    is_valid, reason = verify_audit_certificate(report, certificate, secret_key=KEY)

    assert is_valid is True
    assert "Certificate valid" in reason
    assert certificate["certificate_version"] == "2.0"
    assert "envelope_signature" in certificate


def test_reproduction_forged_summary_issued_at_and_issuer_are_rejected() -> None:
    report = _report()
    certificate = sign_audit_report(report, secret_key=KEY)
    assert verify_audit_certificate(report, certificate, secret_key=KEY)[0] is True

    forged = copy.deepcopy(certificate)
    forged["summary"] = {"score": 100, "findings_count": 0, "status": "SAFE"}
    forged["issued_at"] = "1999-01-01T00:00:00+00:00"
    forged["issuer"] = "Totally Different Issuer"

    is_valid, reason = verify_audit_certificate(report, forged, secret_key=KEY)

    assert is_valid is False
    assert "envelope signature mismatch" in reason
    assert "1999-01-01T00:00:00+00:00" not in reason


@pytest.mark.parametrize(
    ("path", "value"),
    [
        pytest.param(("summary", "score"), 100, id="summary-score"),
        pytest.param(("summary", "findings_count"), 0, id="summary-findings-count"),
        pytest.param(("summary", "status"), "SAFE", id="summary-status"),
        pytest.param(
            ("summary",),
            {"score": 100, "findings_count": 0, "status": "SAFE"},
            id="summary-object",
        ),
        pytest.param(("issued_at",), "1999-01-01T00:00:00+00:00", id="issued-at"),
        pytest.param(("issuer",), "Totally Different Issuer", id="issuer"),
        pytest.param(("algorithm",), "none", id="algorithm"),
        pytest.param(("certificate_version",), "1.0", id="certificate-version-downgrade"),
        pytest.param(("report_sha256",), "0" * 64, id="report-digest"),
        pytest.param(("signature",), "0" * 64, id="report-signature"),
        pytest.param(("envelope_signature",), "0" * 64, id="envelope-signature"),
        pytest.param(("forged_field",), True, id="unknown-envelope-field"),
    ],
)
def test_each_certificate_metadata_field_is_authenticated(
    path: tuple[str, ...], value: Any
) -> None:
    report = _report()
    certificate = sign_audit_report(report, secret_key=KEY)
    assert verify_audit_certificate(report, certificate, secret_key=KEY)[0] is True

    tampered = copy.deepcopy(certificate)
    _set_path(tampered, path, value)

    is_valid, reason = verify_audit_certificate(report, tampered, secret_key=KEY)

    assert is_valid is False
    assert reason


def test_summary_schema_is_closed() -> None:
    report = _report()
    certificate = sign_audit_report(report, secret_key=KEY)
    certificate["summary"]["unexpected"] = "field"

    is_valid, reason = verify_audit_certificate(report, certificate, secret_key=KEY)

    assert is_valid is False
    assert "summary must contain exactly" in reason


def test_findings_count_must_be_a_non_negative_integer() -> None:
    report = _report()
    certificate = sign_audit_report(report, secret_key=KEY)
    certificate["summary"]["findings_count"] = True

    is_valid, reason = verify_audit_certificate(report, certificate, secret_key=KEY)

    assert is_valid is False
    assert "non-negative integer" in reason


@pytest.mark.parametrize(
    ("field", "value"),
    [
        pytest.param("score", 100, id="score"),
        pytest.param("findings_count", 0, id="findings-count"),
        pytest.param("status", "SAFE", id="status"),
    ],
)
def test_summary_must_match_report_even_with_valid_envelope_signature(
    field: str, value: Any
) -> None:
    report = _report()
    certificate = sign_audit_report(report, secret_key=KEY)
    certificate["summary"][field] = value
    # A signing key holder (or a buggy signer) can produce a valid envelope over
    # a summary that does not describe the report. The consistency check must
    # still reject it.
    _resign_envelope(certificate)

    is_valid, reason = verify_audit_certificate(report, certificate, secret_key=KEY)

    assert is_valid is False
    assert "summary does not match" in reason


@pytest.mark.parametrize(
    "issued_at",
    [
        pytest.param("not-a-date", id="not-a-date"),
        pytest.param("1999-01-01T00:00:00", id="no-timezone"),
    ],
)
def test_issued_at_must_be_iso8601_with_timezone(issued_at: str) -> None:
    report = _report()
    certificate = sign_audit_report(report, secret_key=KEY)
    certificate["issued_at"] = issued_at
    _resign_envelope(certificate)

    is_valid, reason = verify_audit_certificate(report, certificate, secret_key=KEY)

    assert is_valid is False
    assert "issued_at" in reason


def test_non_canonical_envelope_is_rejected_without_crashing() -> None:
    report = _report()
    certificate = sign_audit_report(report, secret_key=KEY)
    certificate["summary"]["score"] = float("nan")

    is_valid, reason = verify_audit_certificate(report, certificate, secret_key=KEY)

    assert is_valid is False
    assert "canonical JSON" in reason


def test_legacy_certificate_is_reported_as_legacy_unverified() -> None:
    report = _report()
    legacy = sign_audit_report(report, secret_key=KEY)
    legacy["certificate_version"] = "1.0"
    legacy.pop("envelope_signature")

    is_valid, reason = verify_audit_certificate(report, legacy, secret_key=KEY)

    assert is_valid is False
    assert "Legacy certificate" in reason
    assert "unverified" in reason


def test_legacy_certificate_metadata_is_never_reported_as_verified() -> None:
    report = _report()
    legacy = sign_audit_report(report, secret_key=KEY)
    legacy["certificate_version"] = "1.0"
    legacy.pop("envelope_signature")
    # v1.0 never signed this metadata, so a forger can change it freely.
    legacy["issued_at"] = "1999-01-01T00:00:00+00:00"
    legacy["issuer"] = "Totally Different Issuer"
    legacy["summary"] = {"score": 100, "findings_count": 0, "status": "SAFE"}

    is_valid, reason = verify_audit_certificate(report, legacy, secret_key=KEY)

    assert is_valid is False
    assert "Legacy certificate" in reason
    assert "unverified" in reason


def test_legacy_certificate_cannot_smuggle_an_envelope_signature() -> None:
    report = _report()
    certificate = sign_audit_report(report, secret_key=KEY)
    certificate["certificate_version"] = "1.0"

    is_valid, reason = verify_audit_certificate(report, certificate, secret_key=KEY)

    assert is_valid is False
    assert "must not contain an envelope signature" in reason


def test_certificate_field_order_does_not_affect_verification() -> None:
    report = _report()
    certificate = sign_audit_report(report, secret_key=KEY)
    reordered = dict(reversed(list(certificate.items())))
    reordered["summary"] = dict(reversed(list(reordered["summary"].items())))

    assert verify_audit_certificate(report, reordered, secret_key=KEY)[0] is True
    assert (
        verify_audit_certificate(report, json.loads(json.dumps(certificate)), secret_key=KEY)[0]
        is True
    )


def test_canonical_envelope_is_deterministic_and_closed() -> None:
    certificate = sign_audit_report(_report(), secret_key=KEY)
    reordered = dict(reversed(list(certificate.items())))
    reordered["summary"] = dict(reversed(list(reordered["summary"].items())))

    assert canonicalize_certificate_envelope(certificate) == canonicalize_certificate_envelope(
        reordered
    )

    with pytest.raises(ValueError, match="unsupported field"):
        canonicalize_certificate_envelope({**certificate, "extra": "value"})

    incomplete = dict(certificate)
    incomplete.pop("issuer")
    with pytest.raises(ValueError, match="missing required field"):
        canonicalize_certificate_envelope(incomplete)


def test_cli_embedded_certificate_rejects_forged_metadata(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    report = _report()
    certificate = sign_audit_report(report, secret_key=KEY)
    _write_report(report_path, certificate)

    valid = runner.invoke(app, ["verify", str(report_path), "--key", KEY])
    assert valid.exit_code == 0
    assert "CRYPTOGRAPHIC AUDIT VERIFICATION PASSED" in valid.output
    assert certificate["issued_at"] in valid.output

    forged = copy.deepcopy(certificate)
    forged["summary"] = {"score": 100, "findings_count": 0, "status": "SAFE"}
    forged["issued_at"] = "1999-01-01T00:00:00+00:00"
    forged["issuer"] = "Totally Different Issuer"
    _write_report(report_path, forged)

    result = runner.invoke(app, ["verify", str(report_path), "--key", KEY])

    assert result.exit_code == 1
    assert "CRYPTOGRAPHIC AUDIT VERIFICATION FAILED" in result.output
    assert "CRYPTOGRAPHIC AUDIT VERIFICATION PASSED" not in result.output
    assert "1999-01-01T00:00:00+00:00" not in result.output


def test_cli_external_certificate_rejects_forged_metadata(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    certificate_path = tmp_path / "report.cert"
    _write_report(report_path)
    certificate = sign_audit_report(_report(), secret_key=KEY)
    certificate_path.write_text(json.dumps(certificate), encoding="utf-8")

    valid = runner.invoke(
        app,
        ["verify", str(report_path), "--certificate", str(certificate_path), "--key", KEY],
    )
    assert valid.exit_code == 0
    assert "CRYPTOGRAPHIC AUDIT VERIFICATION PASSED" in valid.output

    forged = copy.deepcopy(certificate)
    forged["summary"] = {"score": 100, "findings_count": 0, "status": "SAFE"}
    forged["issued_at"] = "1999-01-01T00:00:00+00:00"
    forged["issuer"] = "Totally Different Issuer"
    certificate_path.write_text(json.dumps(forged), encoding="utf-8")

    result = runner.invoke(
        app,
        ["verify", str(report_path), "--certificate", str(certificate_path), "--key", KEY],
    )

    assert result.exit_code == 1
    assert "CRYPTOGRAPHIC AUDIT VERIFICATION FAILED" in result.output
    assert "CRYPTOGRAPHIC AUDIT VERIFICATION PASSED" not in result.output
    assert "1999-01-01T00:00:00+00:00" not in result.output


def test_cli_legacy_certificate_is_not_displayed_as_verified(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    report = _report()
    legacy = sign_audit_report(report, secret_key=KEY)
    legacy["certificate_version"] = "1.0"
    legacy.pop("envelope_signature")
    legacy["issued_at"] = "1999-01-01T00:00:00+00:00"
    _write_report(report_path, legacy)

    result = runner.invoke(app, ["verify", str(report_path), "--key", KEY])

    assert result.exit_code == 1
    assert "CRYPTOGRAPHIC AUDIT VERIFICATION FAILED" in result.output
    assert "Legacy certificate" in result.output
    assert "CRYPTOGRAPHIC AUDIT VERIFICATION PASSED" not in result.output
    assert "1999-01-01T00:00:00+00:00" not in result.output
