"""Clock-injection regression tests for signed policy bundles (issue #42, QA-017).

The gateway fixtures pin absolute issued_at/expires_at values. Signing validated those
against the process clock, so once the fixture window passed every signing test failed
with "policy bundle has expired" regardless of the code under test. These tests freeze
the process clock past the window: signing with an injected instant must still work, and
signing without one must still be rejected.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import agentscan.gateway.policy as policy_module
from agentscan.gateway.policy import PolicyError, sign_policy, verify_policy_bundle

NOW = datetime(2026, 11, 10, 12, 0, tzinfo=UTC)
ISSUED_AT = "2026-11-10T00:00:00Z"
EXPIRES_AT = "2026-12-10T00:00:00Z"


class _FrozenDatetime(datetime):
    """A real datetime whose now() ignores the host clock."""

    @classmethod
    def now(cls, tz=None):  # noqa: ANN206 - mirrors datetime.now
        frozen = datetime(2027, 6, 1, 0, 0, tzinfo=UTC)
        return frozen if tz is not None else frozen.replace(tzinfo=None)


@pytest.fixture
def frozen_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    """Freeze the policy module clock past EXPIRES_AT for the whole test."""
    monkeypatch.setattr(policy_module, "datetime", _FrozenDatetime)


def _policy() -> dict[str, Any]:
    return {
        "version": 1,
        "policy_id": "clock-policy",
        "tenant": "tenant-demo",
        "default": "deny",
        "tools": {
            "delete_customer_record": {
                "server": "crm-mcp",
                "risk": "high",
                "enforcement": "inline",
                "schema_hash": "sha256:" + "a" * 64,
                "resource_tenant_enforced": "upstream",
                "rules": [
                    {"id": "allow-support", "principal_role": "support", "decision": "allow"}
                ],
            }
        },
    }


def _private_pem(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _public_pem(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _sign(key: Ed25519PrivateKey, **overrides: Any) -> dict[str, Any]:
    kwargs: dict[str, Any] = {
        "bundle_id": "bundle-test",
        "tenant": "tenant-demo",
        "issued_at": ISSUED_AT,
        "expires_at": EXPIRES_AT,
    }
    kwargs.update(overrides)
    return sign_policy(_policy(), _private_pem(key), **kwargs)


def test_injected_clock_signs_while_the_process_clock_is_past_expiry(
    frozen_clock: None,
) -> None:
    private = Ed25519PrivateKey.generate()
    envelope = _sign(private, now=NOW)
    verified = verify_policy_bundle(
        yaml.safe_dump(envelope).encode("utf-8"), _public_pem(private), now=NOW
    )
    assert verified.policy.policy_id == "clock-policy"


def test_signing_without_an_injected_clock_still_enforces_expiry(frozen_clock: None) -> None:
    private = Ed25519PrivateKey.generate()
    with pytest.raises(PolicyError, match="policy bundle has expired"):
        _sign(private)


def test_injected_clock_rejects_a_window_that_is_already_expired() -> None:
    private = Ed25519PrivateKey.generate()
    issued_at = NOW.strftime("%Y-%m-%dT%H:%M:%SZ")
    expires_at = (NOW - timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    with pytest.raises(PolicyError, match="expires_at must be later than issued_at"):
        _sign(private, issued_at=issued_at, expires_at=expires_at, now=NOW)


def test_signing_defaults_to_the_process_clock() -> None:
    """The seam must not disable the guard when no instant is supplied."""
    private = Ed25519PrivateKey.generate()
    issued_at = (datetime.now(UTC) - timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    expires_at = (datetime.now(UTC) + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    envelope = _sign(private, issued_at=issued_at, expires_at=expires_at)
    assert envelope["format"] == "agentscan-policy-bundle/v1"
