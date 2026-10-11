from __future__ import annotations

from datetime import UTC, datetime, timedelta

import jwt
import pytest
from fastapi import HTTPException

from agentscan.api import auth


def test_configured_key_survives_reconfiguration(configured_api_auth):
    token = auth.create_token("tenant-a")
    first_kid = auth.default_token_manager.key_id
    auth.configure_auth()
    assert auth.default_token_manager.key_id == first_kid
    assert auth.default_token_manager.verify_token(token)["tenant_id"] == "tenant-a"


def test_missing_key_fails_without_ephemeral_fallback(monkeypatch):
    monkeypatch.delenv("AGENTSCAN_JWT_PRIVATE_KEY_FILE")
    with pytest.raises(RuntimeError, match="Configure exactly one"):
        auth.configure_auth()
    assert auth.default_token_manager is None


def test_invalid_key_is_useful_startup_error(monkeypatch):
    monkeypatch.delenv("AGENTSCAN_JWT_PRIVATE_KEY_FILE")
    monkeypatch.setenv("AGENTSCAN_JWT_PRIVATE_KEY", "not-a-key")
    with pytest.raises(RuntimeError, match="configured Ed25519 PEM"):
        auth.configure_auth()


def test_credential_cannot_issue_other_tenant():
    token = auth.issue_enrollment_token("tenant-a", "a" * 40)
    assert auth.default_token_manager.verify_token(token)["tenant_id"] == "tenant-a"
    for tenant in ("tenant-b", "arbitrary-tenant"):
        with pytest.raises(HTTPException) as exc:
            auth.issue_enrollment_token(tenant, "a" * 40)
        assert exc.value.status_code == 403


def test_token_endpoint_disabled_without_enrollment(monkeypatch):
    monkeypatch.delenv("AGENTSCAN_TENANT_CREDENTIALS_JSON")
    auth.configure_auth()
    with pytest.raises(HTTPException) as exc:
        auth.issue_enrollment_token("tenant-a", "dev-psk")
    assert exc.value.status_code == 404


@pytest.mark.parametrize(
    "credentials", ['{"a":"dev-psk"}', '{"a":"' + "x" * 40 + '","b":"' + "x" * 40 + '"}', "[]"]
)
def test_insecure_credentials_fail_startup(monkeypatch, credentials):
    monkeypatch.setenv("AGENTSCAN_TENANT_CREDENTIALS_JSON", credentials)
    with pytest.raises(RuntimeError):
        auth.configure_auth()


def test_wrong_audience_and_signing_id_rejected(configured_api_auth):
    now = datetime.now(UTC)
    payload = {
        "iss": auth.ISSUER,
        "aud": "another-service",
        "sub": "api",
        "tenant_id": "tenant-a",
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(hours=1),
    }
    token = jwt.encode(
        payload,
        configured_api_auth,
        algorithm="EdDSA",
        headers={"kid": auth.default_token_manager.key_id},
    )
    with pytest.raises(HTTPException):
        auth.default_token_manager.verify_token(token)
    payload["aud"] = auth.AUDIENCE
    token = jwt.encode(
        payload, configured_api_auth, algorithm="EdDSA", headers={"kid": "untrusted"}
    )
    with pytest.raises(HTTPException):
        auth.default_token_manager.verify_token(token)
