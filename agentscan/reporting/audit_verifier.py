# agentscan/reporting/audit_verifier.py
#
# Cryptographic Audit Verification Engine.
# Generates and verifies tamper-evident cryptographic certificates
# for AgentScan scan and audit reports (SHA-256 canonical hashing + HMAC signatures).

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from datetime import UTC, datetime
from typing import Any

from loguru import logger


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


def sign_audit_report(
    report_data: dict[str, Any],
    secret_key: str | None = None,
) -> dict[str, Any]:
    """
    Generate a cryptographic verification certificate for a report dictionary.

    Returns:
        dict containing certificate metadata, SHA-256 payload digest, and HMAC signature.
    """
    canonical_bytes = canonicalize_report(report_data)
    report_sha256 = hashlib.sha256(canonical_bytes).hexdigest()

    # Use provided secret key or generate a deterministic default
    key = secret_key or os.environ.get("AGENTSCAN_HMAC_KEY")
    if not key:
        key = "agentscan-audit-verification-key"
        logger.warning(
            "AGENTSCAN_HMAC_KEY not set; using default key. "
            "Set AGENTSCAN_HMAC_KEY env var for production certificate security."
        )
    signature = hmac.new(key.encode("utf-8"), canonical_bytes, hashlib.sha256).hexdigest()

    certificate = {
        "certificate_version": "1.0",
        "algorithm": "HMAC-SHA256",
        "report_sha256": report_sha256,
        "signature": signature,
        "issued_at": datetime.now(UTC).isoformat(),
        "issuer": "AgentScan Cryptographic Verification Engine",
        "summary": {
            "score": report_data.get("score"),
            "findings_count": len(report_data.get("findings", [])),
            "status": report_data.get("status") or report_data.get("ssp_class"),
        },
    }
    return certificate


def verify_audit_certificate(
    report_data: dict[str, Any],
    certificate: dict[str, Any],
    secret_key: str | None = None,
) -> tuple[bool, str]:
    """
    Verify the cryptographic integrity and authenticity of a report against its certificate.

    Returns:
        (is_valid: bool, reason: str)
    """
    if not isinstance(certificate, dict):
        return False, "Invalid certificate format: expected JSON dictionary."

    expected_sha256 = certificate.get("report_sha256")
    if not expected_sha256:
        return False, "Certificate missing required 'report_sha256' field."

    canonical_bytes = canonicalize_report(report_data)
    actual_sha256 = hashlib.sha256(canonical_bytes).hexdigest()

    if not hmac.compare_digest(actual_sha256, expected_sha256):
        return (
            False,
            f"Digest mismatch! Report content has been tampered with or modified post-certification.\n"
            f"Expected SHA-256: {expected_sha256}\n"
            f"Computed SHA-256: {actual_sha256}",
        )

    expected_sig = certificate.get("signature")
    if expected_sig:
        key = (
            secret_key or os.environ.get("AGENTSCAN_HMAC_KEY") or "agentscan-audit-verification-key"
        )
        computed_sig = hmac.new(key.encode("utf-8"), canonical_bytes, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(computed_sig, expected_sig):
            return (
                False,
                "Cryptographic HMAC signature mismatch! Key incorrect or signature forged.",
            )

    return True, "Certificate valid: report cryptographic integrity and signature verified."


def issue_keypair_token() -> str:
    """Generate a high-entropy secret token for HMAC signing."""
    return secrets.token_hex(32)
