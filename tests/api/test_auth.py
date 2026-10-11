# tests/api/test_auth.py
#
# Unit and integration tests for Ed25519TokenManager and API auth dependencies.

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import MagicMock

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi import HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials

from agentscan.api.auth import (
    ISSUER,
    Ed25519TokenManager,
    create_token,
    get_current_tenant,
)


def test_ed25519_token_creation_and_verification() -> None:
    """Validate creating a token with private key and verifying with public key."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    manager = Ed25519TokenManager(private_key=private_key, public_key=public_key)
    token = manager.create_token(tenant_id="tenant-alpha-1", sub="agent-scanner", ttl_hours=2)

    assert isinstance(token, str)

    # Verification using manager with public key only
    verifier = Ed25519TokenManager(public_key=public_key)
    claims = verifier.verify_token(token)

    assert claims["iss"] == ISSUER
    assert claims["tenant_id"] == "tenant-alpha-1"
    assert claims["sub"] == "agent-scanner"
    assert "exp" in claims
    assert "iat" in claims
    assert "nbf" in claims


def test_public_key_only_manager_cannot_create_token() -> None:
    """Validate that verifier-only token managers cannot sign tokens."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    verifier = Ed25519TokenManager(public_key=private_key.public_key())

    with pytest.raises(PermissionError, match="Private key required"):
        verifier.create_token(tenant_id="tenant-1")


def test_initialization_requires_at_least_one_key() -> None:
    """Validate that Ed25519TokenManager rejects empty key initialization."""
    with pytest.raises(ValueError, match="Ed25519 public key required"):
        Ed25519TokenManager(private_key=None, public_key=None)


def test_expired_token_raises_unauthorized() -> None:
    """Validate that expired tokens raise HTTPException 401."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    manager = Ed25519TokenManager(private_key=private_key)

    past = datetime.now(UTC) - timedelta(hours=2)
    payload: dict[str, Any] = {
        "iss": ISSUER,
        "sub": "api",
        "tenant_id": "tenant-expired",
        "iat": past - timedelta(hours=1),
        "nbf": past - timedelta(hours=1),
        "exp": past,
    }
    expired_token = jwt.encode(payload, private_key, algorithm="EdDSA")

    with pytest.raises(HTTPException) as exc_info:
        manager.verify_token(expired_token)

    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert "verification failed" in exc_info.value.detail.lower()


def test_untrusted_signature_raises_unauthorized() -> None:
    """Validate that tokens signed with an unmatching private key fail verification."""
    priv1 = ed25519.Ed25519PrivateKey.generate()
    priv2 = ed25519.Ed25519PrivateKey.generate()

    mgr1 = Ed25519TokenManager(private_key=priv1)
    mgr2 = Ed25519TokenManager(private_key=priv2)

    token = mgr1.create_token(tenant_id="tenant-untrusted")

    with pytest.raises(HTTPException) as exc_info:
        mgr2.verify_token(token)

    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED


def test_tampered_payload_raises_unauthorized() -> None:
    """Validate that tampering with JWT payload bytes invalidates signature."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    manager = Ed25519TokenManager(private_key=private_key)

    token = manager.create_token(tenant_id="tenant-original")
    parts = token.split(".")
    # Tamper with the payload part
    tampered_token = f"{parts[0]}.eyJ0ZW5hbnRfaWQiOiAiaGFja2VkIn0.{parts[2]}"

    with pytest.raises(HTTPException) as exc_info:
        manager.verify_token(tampered_token)

    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED


def test_missing_required_claims_raises_unauthorized() -> None:
    """Validate that token missing required claims (e.g. tenant_id) is rejected."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    manager = Ed25519TokenManager(private_key=private_key)

    now = datetime.now(UTC)
    payload: dict[str, Any] = {
        "iss": ISSUER,
        "sub": "api",
        # missing tenant_id
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(hours=1),
    }
    incomplete_token = jwt.encode(payload, private_key, algorithm="EdDSA")

    with pytest.raises(HTTPException) as exc_info:
        manager.verify_token(incomplete_token)

    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.asyncio
async def test_get_current_tenant_dependency() -> None:
    """Validate FastAPI dependency extracts tenant_id from bearer credentials."""
    token = create_token(tenant_id="enterprise-tenant-42")
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)

    tenant = await get_current_tenant(creds)
    assert tenant == "enterprise-tenant-42"


@pytest.mark.asyncio
async def test_get_current_tenant_dependency_missing_claim() -> None:
    """Validate FastAPI dependency raises 401 if tenant_id claim is empty."""

    # Mock verify_token to return payload without tenant_id
    mock_manager = MagicMock()
    mock_manager.verify_token.return_value = {"sub": "api"}

    from unittest.mock import patch

    with patch("agentscan.api.auth.default_token_manager", mock_manager):
        creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials="valid.token.here")
        with pytest.raises(HTTPException) as exc_info:
            await get_current_tenant(creds)

        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
        assert "Token missing tenant_id" in exc_info.value.detail
