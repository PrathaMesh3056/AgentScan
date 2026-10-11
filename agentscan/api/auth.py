"""Configured Ed25519 identity and tenant-bound enrollment credentials."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

_bearer = HTTPBearer(auto_error=True)
ISSUER = "agentscan-auth-service"
AUDIENCE = "agentscan-api"
DEFAULT_TOKEN_TTL_HOURS = 1


class Ed25519TokenManager:
    """Sign and verify with an explicitly supplied, stable Ed25519 identity."""

    def __init__(
        self,
        private_key: ed25519.Ed25519PrivateKey | None = None,
        public_key: ed25519.Ed25519PublicKey | None = None,
    ) -> None:
        self._private_key = private_key
        self._public_key = public_key or (private_key.public_key() if private_key else None)
        if self._public_key is None:
            raise ValueError("Ed25519 public key required for verification.")
        raw = self._public_key.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self.key_id = hashlib.sha256(raw).hexdigest()[:16]

    def create_token(
        self, tenant_id: str, sub: str = "api", ttl_hours: int = DEFAULT_TOKEN_TTL_HOURS
    ) -> str:
        if self._private_key is None:
            raise PermissionError("Private key required for token generation.")
        if not tenant_id or not isinstance(tenant_id, str) or ttl_hours <= 0:
            raise ValueError("A nonempty tenant and positive token lifetime are required.")
        now = datetime.now(UTC)
        payload: dict[str, Any] = {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": sub,
            "tenant_id": tenant_id,
            "iat": now,
            "nbf": now,
            "exp": now + timedelta(hours=ttl_hours),
        }
        return jwt.encode(
            payload, self._private_key, algorithm="EdDSA", headers={"kid": self.key_id}
        )

    def verify_token(self, token: str) -> dict[str, Any]:
        public_key = self._public_key
        if public_key is None:
            raise RuntimeError("Token verifier has no configured public key.")
        try:
            if jwt.get_unverified_header(token).get("kid") != self.key_id:
                raise jwt.InvalidTokenError("Untrusted signing identity.")
            payload = jwt.decode(
                token,
                public_key,
                algorithms=["EdDSA"],
                issuer=ISSUER,
                audience=AUDIENCE,
                options={"require": ["iss", "aud", "exp", "iat", "nbf", "tenant_id", "sub"]},
            )
            if not isinstance(payload.get("tenant_id"), str) or not payload["tenant_id"]:
                raise jwt.InvalidTokenError("Invalid tenant identity.")
            return payload
        except jwt.PyJWTError as exc:
            raise HTTPException(
                status_code=401, detail="Cryptographic token verification failed."
            ) from exc


default_token_manager: Ed25519TokenManager | None = None
_tenant_credentials: dict[str, str] = {}


def configure_auth() -> None:
    """Load identity at startup. Never silently create an ephemeral signing key."""
    global default_token_manager, _tenant_credentials
    default_token_manager = None
    _tenant_credentials = {}
    filename = os.environ.get("AGENTSCAN_JWT_PRIVATE_KEY_FILE")
    pem = os.environ.get("AGENTSCAN_JWT_PRIVATE_KEY")
    if bool(filename) == bool(pem):
        raise RuntimeError(
            "Configure exactly one of AGENTSCAN_JWT_PRIVATE_KEY_FILE or AGENTSCAN_JWT_PRIVATE_KEY "
            "with an Ed25519 PEM private key shared by all API replicas."
        )
    try:
        material = Path(filename).read_bytes() if filename else (pem or "").encode()
        key = serialization.load_pem_private_key(material, password=None)
    except (OSError, ValueError, TypeError) as exc:
        raise RuntimeError("Unable to load the configured Ed25519 PEM signing key.") from exc
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise RuntimeError("The configured API signing key must be Ed25519.")
    try:
        credentials = json.loads(os.environ.get("AGENTSCAN_TENANT_CREDENTIALS_JSON", "{}"))
        if not isinstance(credentials, dict):
            raise ValueError("Expected an object.")
        for tenant, secret in credentials.items():
            if (
                not isinstance(tenant, str)
                or not tenant.strip()
                or not isinstance(secret, str)
                or len(secret) < 32
                or secret.lower().startswith(("dev-", "change_me", "changeme"))
            ):
                raise ValueError("Invalid tenant enrollment credential.")
    except (ValueError, TypeError) as exc:
        raise RuntimeError(
            "AGENTSCAN_TENANT_CREDENTIALS_JSON must map tenant IDs to unique secrets of at least "
            "32 characters; omit it to disable /token."
        ) from exc
    if len(set(credentials.values())) != len(credentials):
        raise RuntimeError("Each tenant enrollment credential must be unique.")
    default_token_manager = Ed25519TokenManager(private_key=key)
    _tenant_credentials = credentials


def issue_enrollment_token(tenant_id: str, secret: str) -> str:
    """A credential grants access only to its enrolled tenant."""
    if not _tenant_credentials:
        raise HTTPException(status_code=404, detail="Token enrollment is disabled.")
    expected = _tenant_credentials.get(tenant_id)
    if expected is None or not hmac.compare_digest(secret.encode(), expected.encode()):
        raise HTTPException(status_code=403, detail="Invalid enrollment credentials.")
    return create_token(tenant_id)


def create_token(tenant_id: str, sub: str = "api", ttl_hours: int = DEFAULT_TOKEN_TTL_HOURS) -> str:
    if default_token_manager is None:
        raise RuntimeError(
            "API signing identity is not configured; run configure_auth() at startup."
        )
    return default_token_manager.create_token(tenant_id, sub=sub, ttl_hours=ttl_hours)


def _decode_token(token: str) -> dict[str, Any]:
    if default_token_manager is None:
        raise HTTPException(status_code=503, detail="API signing identity is unavailable.")
    return default_token_manager.verify_token(token)


async def get_current_tenant(creds: HTTPAuthorizationCredentials = Depends(_bearer)) -> str:  # noqa: B008
    payload = _decode_token(creds.credentials)
    tenant_id = payload.get("tenant_id")
    if not isinstance(tenant_id, str) or not tenant_id:
        raise HTTPException(status_code=401, detail="Token missing tenant_id claim.")
    return tenant_id
