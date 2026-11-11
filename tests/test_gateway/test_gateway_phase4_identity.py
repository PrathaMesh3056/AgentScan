from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agentscan.gateway.identity import (
    IdentityError,
    IdentityVerifier,
    UnverifiedIdentity,
    load_trust_keys,
)


@pytest.fixture
def keys() -> tuple[Ed25519PrivateKey, bytes]:
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private, public


def _token(private: Ed25519PrivateKey, claims: dict[str, Any], *, kid: str = "key-1") -> str:
    return jwt.encode(claims, private, algorithm="EdDSA", headers={"kid": kid})


def _principal(**changes: Any) -> dict[str, Any]:
    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": "issuer-a",
        "sub": "principal-a",
        "aud": "agentscan",
        "exp": now + 300,
        "iat": now,
        "tenant": "tenant-a",
        "agent": "agent-a",
        "role": "operator",
        "scope": ["tools/read", "tools/write"],
    }
    claims.update(changes)
    return claims


def _verifier(public: bytes) -> IdentityVerifier:
    return IdentityVerifier(
        trusted_issuer="issuer-a",
        audience="agentscan",
        tenant="tenant-a",
        trust_keys={"key-1": public},
    )


def test_principal_token_verifies_and_identity_hash_is_stable(
    keys: tuple[Ed25519PrivateKey, bytes],
) -> None:
    private, public = keys
    token = _token(private, _principal())
    identity = _verifier(public).verify(token)
    assert (identity.principal, identity.agent, identity.tenant, identity.role) == (
        "principal-a",
        "agent-a",
        "tenant-a",
        "operator",
    )
    assert identity.scope == identity.token_scope == ("tools/read", "tools/write")
    assert identity.expires_at > int(time.time())
    assert identity.allows_tool("tools/read") and not identity.allows_tool("missing")
    assert "tools/call" not in identity.scope
    assert token not in repr(identity)
    assert identity.session_identity_hash == _verifier(public).verify(token).session_identity_hash


@pytest.mark.parametrize(
    "claim,value,reason",
    [
        ("exp", int(time.time()) - 60, "expired"),
        ("nbf", int(time.time()) + 500, "not_yet_valid"),
        ("iss", "other", "wrong_issuer"),
        ("aud", "other", "wrong_audience"),
        ("tenant", "other", "wrong_tenant"),
        ("scope", "tools/read", "bad_scope"),
        ("scope", ["ok", 2], "bad_scope"),
        ("scope", [""], "bad_scope"),
    ],
)
def test_invalid_principal_claims_are_bounded(
    keys: tuple[Ed25519PrivateKey, bytes], claim: str, value: Any, reason: str
) -> None:
    private, public = keys
    with pytest.raises(IdentityError) as error:
        _verifier(public).verify(_token(private, _principal(**{claim: value})))
    assert error.value.reason == reason
    assert "eyJ" not in str(error.value)


@pytest.mark.parametrize("claim", ["sub", "agent", "role", "scope", "tenant"])
def test_missing_required_claims_deny(keys: tuple[Ed25519PrivateKey, bytes], claim: str) -> None:
    private, public = keys
    claims = _principal()
    del claims[claim]
    with pytest.raises(IdentityError):
        _verifier(public).verify(_token(private, claims))


def test_bad_alg_kid_and_malformed_token_deny(keys: tuple[Ed25519PrivateKey, bytes]) -> None:
    private, public = keys
    verifier = _verifier(public)
    with pytest.raises(IdentityError):
        verifier.verify("not.a.jwt")
    with pytest.raises(IdentityError):
        verifier.verify(
            jwt.encode(_principal(), private, algorithm="EdDSA", headers={"kid": "unknown"})
        )
    with pytest.raises(IdentityError):
        verifier.verify("Bearer " + _token(private, _principal()))


def test_delegation_intersects_scope_and_redacts_compact_jwt(
    keys: tuple[Ed25519PrivateKey, bytes],
) -> None:
    private, public = keys
    hop = _token(
        private,
        {
            "iss": "issuer-a",
            "sub": "principal-a",
            "aud": "agent-a",
            "exp": int(time.time()) + 200,
            "iat": int(time.time()),
            "tenant": "tenant-a",
            "scope": ["tools/read"],
        },
    )
    identity = _verifier(public).verify(_token(private, _principal(delegation=[hop])))
    assert identity.scope == ("tools/read",)
    assert identity.delegation_chain == (hop,)
    assert identity.expires_at < int(time.time()) + 250
    assert hop not in repr(identity)


def test_delegation_without_scope_inherits_and_broken_link_denies(
    keys: tuple[Ed25519PrivateKey, bytes],
) -> None:
    private, public = keys
    now = int(time.time())
    hop = _token(
        private,
        {
            "iss": "issuer-a",
            "sub": "principal-a",
            "aud": "agent-a",
            "exp": now + 200,
            "iat": now,
            "tenant": "tenant-a",
        },
    )
    identity = _verifier(public).verify(_token(private, _principal(delegation=[hop])))
    assert identity.scope == ("tools/read", "tools/write")
    broken = _token(
        private,
        {
            "iss": "issuer-a",
            "sub": "someone-else",
            "aud": "agent-a",
            "exp": now + 200,
            "iat": now,
            "tenant": "tenant-a",
        },
    )
    with pytest.raises(IdentityError):
        _verifier(public).verify(_token(private, _principal(delegation=[broken])))


def test_delegation_depth_and_bad_hop_deny(keys: tuple[Ed25519PrivateKey, bytes]) -> None:
    private, public = keys
    with pytest.raises(IdentityError) as error:
        _verifier(public).verify(_token(private, _principal(delegation=["bad"] * 4)))
    assert error.value.reason == "delegation_depth"
    with pytest.raises(IdentityError):
        _verifier(public).verify(_token(private, _principal(delegation=["bad"])))


def test_trust_key_loader_requires_ed25519_public_keys(
    tmp_path: Path, keys: tuple[Ed25519PrivateKey, bytes]
) -> None:
    private, public = keys
    path = tmp_path / "keys.json"
    path.write_text(json.dumps({"keys": {"key-1": public.decode()}}), encoding="utf-8")
    assert load_trust_keys(path) == {"key-1": public}
    path.write_text('{"keys":{"a":"x"},"extra":true}', encoding="utf-8")
    with pytest.raises(IdentityError):
        load_trust_keys(path)
    private_pem = private.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()
    path.write_text(json.dumps({"keys": {"a": private_pem}}), encoding="utf-8")
    with pytest.raises(IdentityError):
        load_trust_keys(path)
    path.write_text('{"keys":{"a":"x","a":"y"}}', encoding="utf-8")
    with pytest.raises(IdentityError):
        load_trust_keys(path)


def test_unverified_identity_is_explicit() -> None:
    value = UnverifiedIdentity(
        "UNVERIFIED", "UNVERIFIED", "tenant-a", None, (), True, "missing_token"
    )
    assert value.principal == "UNVERIFIED" and value.would_deny
