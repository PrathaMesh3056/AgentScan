# agentscan/api/auth.py
#
# JWT bearer token authentication for the AgentScan REST API.
# Tokens are signed HS256. For production, rotate AGENTSCAN_JWT_SECRET.

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

JWT_SECRET = os.environ.get("AGENTSCAN_JWT_SECRET", "dev-secret-change-in-production")
JWT_ALGO = "HS256"
TOKEN_TTL_H = int(os.environ.get("AGENTSCAN_JWT_TTL_HOURS", "24"))

_bearer = HTTPBearer(auto_error=True)


def create_token(tenant_id: str, sub: str = "api") -> str:
    """Create a signed JWT for a tenant."""
    from jose import jwt

    payload = {
        "sub": sub,
        "tenant_id": tenant_id,
        "iat": datetime.now(UTC),
        "exp": datetime.now(UTC) + timedelta(hours=TOKEN_TTL_H),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)


def _decode_token(token: str) -> dict[str, Any]:
    from jose import JWTError, jwt

    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid or expired token: {exc}",
        ) from exc


async def get_current_tenant(
    creds: HTTPAuthorizationCredentials = Depends(_bearer),  # noqa: B008
) -> str:
    """FastAPI dependency — returns tenant_id from validated Bearer token."""
    payload = _decode_token(creds.credentials)
    tenant_id: str | None = payload.get("tenant_id")
    if not tenant_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token missing tenant_id claim.",
        )
    return tenant_id
