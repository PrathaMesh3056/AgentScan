# agentscan/reporting/audit_verifier.py
#
# Cryptographic Audit Verification Engine.
# Generates and verifies tamper-evident cryptographic certificates
# for AgentScan scan and audit reports (SHA-256 canonical hashing + HMAC signatures).
#
# Certificate format v2.0 signs two related payloads with HMAC-SHA256:
#   1. the canonical report bytes (`signature`), and
#   2. a canonical certificate envelope (`envelope_signature`) containing
#      certificate_version, algorithm, report_sha256, signature, issued_at,
#      issuer, and summary.
# The envelope signature binds the certificate metadata to the report digest and
# report signature, so changing either the report or any certificate metadata is
# detected. The signed envelope field set is closed: unknown fields are rejected
# during verification.
#
# Version 1.0 certificates (report signature only) are still parsed, but are
# reported as legacy/unverified because their metadata was never authenticated.

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
from datetime import UTC, datetime
from typing import Any

_CERTIFICATE_VERSION = "2.0"
_LEGACY_CERTIFICATE_VERSION = "1.0"
_ALGORITHM = "HMAC-SHA256"
_ENVELOPE_SIGNATURE_FIELD = "envelope_signature"

# Closed canonical set for the signed envelope. `envelope_signature` itself is
# excluded because it is the signature over these fields.
_ENVELOPE_FIELDS = (
    "certificate_version",
    "algorithm",
    "report_sha256",
    "signature",
    "issued_at",
    "issuer",
    "summary",
)
_ENVELOPE_FIELD_SET = frozenset(_ENVELOPE_FIELDS)
_CERTIFICATE_FIELD_SET = _ENVELOPE_FIELD_SET | {_ENVELOPE_SIGNATURE_FIELD}
_SUMMARY_FIELDS = ("findings_count", "score", "status")
_SUMMARY_FIELD_SET = frozenset(_SUMMARY_FIELDS)

_HEX_SHA256 = re.compile(r"[0-9a-f]{64}")
_ENVELOPE_DOMAIN = b"agentscan-audit-certificate-envelope-v2\x00"
_ISSUER = "AgentScan Cryptographic Verification Engine"


def _signing_key(explicit: str | None) -> str:
    key = explicit if explicit is not None else os.environ.get("AGENTSCAN_HMAC_KEY")
    if not key or len(key.encode("utf-8")) < 32 or key == "agentscan-audit-verification-key":
        raise ValueError("Configure an independent AGENTSCAN_HMAC_KEY of at least 32 bytes")
    return key


def canonicalize_report(report_data: dict[str, Any]) -> bytes:
    """
    Produce a deterministic canonical byte representation of a report dictionary.
    Excludes volatile certificate metadata if nested.
    """
    # Create clean copy without any existing certificate field
    clean_data = {k: v for k, v in report_data.items() if k != "certificate"}
    return json.dumps(clean_data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


def canonicalize_certificate_envelope(certificate: dict[str, Any]) -> bytes:
    """
    Produce deterministic canonical bytes for the signed portion of a certificate.

    The canonical set is exactly: certificate_version, algorithm, report_sha256,
    signature, issued_at, issuer, and summary. `envelope_signature` is excluded
    because it is the signature over these fields. Unknown fields are rejected.
    """
    if not isinstance(certificate, dict):
        raise TypeError("Certificate envelope must be a JSON object.")
    missing = _ENVELOPE_FIELD_SET.difference(certificate)
    if missing:
        raise ValueError(
            "Certificate envelope missing required field(s): "
            + ", ".join(sorted(map(str, missing)))
        )
    unknown = set(certificate).difference(_CERTIFICATE_FIELD_SET)
    if unknown:
        raise ValueError(
            "Certificate envelope contains unsupported field(s): "
            + ", ".join(sorted(map(str, unknown)))
        )

    unsigned = {field: certificate[field] for field in _ENVELOPE_FIELDS}
    try:
        encoded = json.dumps(
            unsigned,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Certificate envelope is not canonical JSON: {exc}") from exc
    return _ENVELOPE_DOMAIN + encoded


def _compute_envelope_signature(key: str, certificate: dict[str, Any]) -> str:
    return hmac.new(
        key.encode("utf-8"),
        canonicalize_certificate_envelope(certificate),
        hashlib.sha256,
    ).hexdigest()


def _report_summary(report_data: dict[str, Any]) -> dict[str, Any]:
    """Return the certificate summary that must match the report content."""
    findings = report_data.get("findings", [])
    findings_count = len(findings) if isinstance(findings, list) else 0
    return {
        "score": report_data.get("score"),
        "findings_count": findings_count,
        "status": report_data.get("status") or report_data.get("ssp_class"),
    }


def _is_hex_sha256(value: Any) -> bool:
    return isinstance(value, str) and _HEX_SHA256.fullmatch(value) is not None


def _json_scalar_equal(expected: Any, actual: Any) -> bool:
    # bool is an int subclass; never let True compare equal to 1.
    if isinstance(expected, bool) or isinstance(actual, bool):
        return isinstance(expected, bool) and isinstance(actual, bool) and expected == actual
    if isinstance(expected, (int, float)) and isinstance(actual, (int, float)):
        return expected == actual
    return type(expected) is type(actual) and expected == actual


def _summary_matches(expected: dict[str, Any], actual: dict[str, Any]) -> bool:
    return all(_json_scalar_equal(expected[field], actual.get(field)) for field in _SUMMARY_FIELDS)


def sign_audit_report(
    report_data: dict[str, Any],
    secret_key: str | None = None,
) -> dict[str, Any]:
    """
    Generate a cryptographic verification certificate for a report dictionary.

    Returns:
        dict containing certificate metadata, SHA-256 payload digest, an HMAC
        signature over the report bytes, and an HMAC signature over the
        canonical certificate envelope.
    """
    canonical_bytes = canonicalize_report(report_data)
    report_sha256 = hashlib.sha256(canonical_bytes).hexdigest()

    key = _signing_key(secret_key)
    signature = hmac.new(key.encode("utf-8"), canonical_bytes, hashlib.sha256).hexdigest()

    certificate = {
        "certificate_version": _CERTIFICATE_VERSION,
        "algorithm": _ALGORITHM,
        "report_sha256": report_sha256,
        "signature": signature,
        "issued_at": datetime.now(UTC).isoformat(),
        "issuer": _ISSUER,
        "summary": _report_summary(report_data),
    }
    certificate[_ENVELOPE_SIGNATURE_FIELD] = _compute_envelope_signature(key, certificate)
    return certificate


def _verify_legacy_certificate(
    report_data: dict[str, Any],
    certificate: dict[str, Any],
    secret_key: str | None,
) -> tuple[bool, str]:
    """Verify v1.0 report integrity, but never claim its metadata is authentic."""
    if _ENVELOPE_SIGNATURE_FIELD in certificate:
        return False, (
            "Invalid legacy certificate: version 1.0 must not contain an envelope signature. "
            "Re-sign the report with a current AgentScan release."
        )

    expected_sha256 = certificate.get("report_sha256")
    if not _is_hex_sha256(expected_sha256):
        return False, "Certificate missing required 'report_sha256' field."

    canonical_bytes = canonicalize_report(report_data)
    actual_sha256 = hashlib.sha256(canonical_bytes).hexdigest()
    if not hmac.compare_digest(actual_sha256, expected_sha256):
        return (
            False,
            "Digest mismatch! Report content has been tampered with or modified post-certification.\n"
            f"Expected SHA-256: {expected_sha256}\n"
            f"Computed SHA-256: {actual_sha256}",
        )

    expected_sig = certificate.get("signature")
    if not _is_hex_sha256(expected_sig):
        return False, "Certificate missing a valid HMAC signature."
    try:
        key = _signing_key(secret_key)
    except ValueError as exc:
        return False, str(exc)
    computed_sig = hmac.new(key.encode("utf-8"), canonical_bytes, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(computed_sig, expected_sig):
        return False, "Cryptographic HMAC signature mismatch! Key incorrect or signature forged."

    return False, (
        "Legacy certificate (version 1.0): the report content digest and HMAC signature are valid, "
        "but certificate metadata (issued_at, issuer, summary) is unverified because version 1.0 "
        "did not sign an envelope. Re-sign the report with a current AgentScan release."
    )


def _verify_envelope_certificate(
    report_data: dict[str, Any],
    certificate: dict[str, Any],
    secret_key: str | None,
) -> tuple[bool, str]:
    fields = set(certificate)
    missing = _CERTIFICATE_FIELD_SET.difference(fields)
    if missing:
        return False, (
            "Certificate is missing required envelope field(s): "
            + ", ".join(sorted(map(str, missing)))
        )
    unknown = fields.difference(_CERTIFICATE_FIELD_SET)
    if unknown:
        return False, (
            "Certificate contains unsupported envelope field(s): "
            + ", ".join(sorted(map(str, unknown)))
        )

    if not _is_hex_sha256(certificate.get(_ENVELOPE_SIGNATURE_FIELD)):
        return False, "Certificate missing a valid envelope signature."

    issued_at = certificate.get("issued_at")
    if not isinstance(issued_at, str) or not issued_at.strip():
        return False, "Certificate 'issued_at' must be a non-empty ISO-8601 timestamp."
    try:
        parsed_issued_at = datetime.fromisoformat(issued_at)
    except ValueError:
        return False, "Certificate 'issued_at' must be a valid ISO-8601 timestamp."
    if parsed_issued_at.tzinfo is None:
        return False, "Certificate 'issued_at' must include a timezone offset."

    issuer = certificate.get("issuer")
    if not isinstance(issuer, str) or not issuer.strip():
        return False, "Certificate 'issuer' must be a non-empty string."

    summary = certificate.get("summary")
    if not isinstance(summary, dict) or set(summary) != _SUMMARY_FIELD_SET:
        return False, "Certificate summary must contain exactly: findings_count, score, status."
    findings_count = summary.get("findings_count")
    if (
        isinstance(findings_count, bool)
        or not isinstance(findings_count, int)
        or findings_count < 0
    ):
        return False, "Certificate summary 'findings_count' must be a non-negative integer."

    expected_sha256 = certificate.get("report_sha256")
    if not _is_hex_sha256(expected_sha256):
        return False, "Certificate missing required 'report_sha256' field."

    canonical_bytes = canonicalize_report(report_data)
    actual_sha256 = hashlib.sha256(canonical_bytes).hexdigest()
    if not hmac.compare_digest(actual_sha256, expected_sha256):
        return (
            False,
            "Digest mismatch! Report content has been tampered with or modified post-certification.\n"
            f"Expected SHA-256: {expected_sha256}\n"
            f"Computed SHA-256: {actual_sha256}",
        )

    expected_sig = certificate.get("signature")
    if not _is_hex_sha256(expected_sig):
        return False, "Certificate missing a valid HMAC signature."
    try:
        key = _signing_key(secret_key)
    except ValueError as exc:
        return False, str(exc)
    computed_sig = hmac.new(key.encode("utf-8"), canonical_bytes, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(computed_sig, expected_sig):
        return False, "Cryptographic HMAC signature mismatch! Key incorrect or signature forged."

    try:
        computed_envelope_sig = _compute_envelope_signature(key, certificate)
    except (TypeError, ValueError):
        return False, "Certificate envelope is not canonical JSON and cannot be verified."
    if not hmac.compare_digest(computed_envelope_sig, certificate[_ENVELOPE_SIGNATURE_FIELD]):
        return False, (
            "Certificate envelope signature mismatch! Certificate metadata "
            "(issued_at, issuer, summary) was forged or modified after certification."
        )

    expected_summary = _report_summary(report_data)
    if not _summary_matches(expected_summary, summary):
        return False, (
            "Certificate summary does not match the report content "
            "(score, findings_count, or status)."
        )

    return True, (
        "Certificate valid: report cryptographic integrity, signed envelope, and summary verified."
    )


def verify_audit_certificate(
    report_data: dict[str, Any],
    certificate: dict[str, Any],
    secret_key: str | None = None,
) -> tuple[bool, str]:
    """
    Verify the cryptographic integrity and authenticity of a report against its certificate.

    A valid v2.0 certificate requires a matching report digest, a valid report
    HMAC signature, a valid signature over the canonical certificate envelope,
    and a summary that matches the report content. v1.0 certificates only prove
    report content integrity; they are returned as legacy/unverified rather than
    silently accepted.

    Returns:
        (is_valid: bool, reason: str)
    """
    if not isinstance(certificate, dict):
        return False, "Invalid certificate format: expected JSON dictionary."

    algorithm = certificate.get("algorithm")
    version = certificate.get("certificate_version")
    if algorithm != _ALGORITHM or version not in (
        _CERTIFICATE_VERSION,
        _LEGACY_CERTIFICATE_VERSION,
    ):
        return False, "Unsupported or missing certificate algorithm/version."

    if version == _LEGACY_CERTIFICATE_VERSION:
        return _verify_legacy_certificate(report_data, certificate, secret_key)
    return _verify_envelope_certificate(report_data, certificate, secret_key)


def issue_keypair_token() -> str:
    """Generate a high-entropy secret token for HMAC signing."""
    return secrets.token_hex(32)
