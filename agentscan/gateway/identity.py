"""JWT and delegation verification for gateway-authenticated identities."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from agentscan.gateway.canonical import canonical_json, loads_json
from agentscan.gateway.models import ErrorCode

_REASON_RE = re.compile(r"^[a-z][a-z0-9_]{0,47}$")


class IdentityStatus(StrEnum):
    VERIFIED = "verified"
    UNVERIFIED = "unverified"


class IdentityError(Exception):
    """Non-secret, bounded identity verification failure."""

    code = ErrorCode.IDENTITY_MISSING

    def __init__(self, reason: str) -> None:
        self.reason = reason if _REASON_RE.fullmatch(reason) else "malformed_token"
        super().__init__(self.reason)


@dataclass(frozen=True, slots=True)
class VerifiedIdentity:
    principal: str
    agent: str
    tenant: str
    role: str
    scope: tuple[str, ...]
    token_scope: tuple[str, ...]
    delegation_chain: tuple[str, ...] = field(repr=False)
    issuer: str
    audience: str
    expires_at: int
    issued_at: int
    session_identity_hash: str

    @property
    def status(self) -> IdentityStatus:
        return IdentityStatus.VERIFIED

    def allows_tool(self, tool_name: str) -> bool:
        return tool_name in self.scope


@dataclass(frozen=True, slots=True)
class UnverifiedIdentity:
    principal: str
    agent: str
    tenant: str
    role: None
    scope: tuple[str, ...]
    would_deny: bool
    reason: str
    status: IdentityStatus = IdentityStatus.UNVERIFIED

    def __post_init__(self) -> None:
        if self.principal != "UNVERIFIED" or self.agent != "UNVERIFIED":
            raise ValueError("unverified identity labels must be fixed")
        if not self.would_deny:
            raise ValueError("unverified identity must be marked would_deny")
        if not _REASON_RE.fullmatch(self.reason):
            object.__setattr__(self, "reason", "identity_missing")


def _identity_error(reason: str) -> IdentityError:
    return IdentityError(reason)


def load_trust_keys(path: str | Path) -> dict[str, bytes]:
    """Load a JSON mapping of key IDs to Ed25519 public PEMs."""
    try:
        document = loads_json(Path(path).read_bytes())
    except Exception as exc:
        raise _identity_error("bad_trust_keys") from exc
    if not isinstance(document, dict) or set(document) != {"keys"}:
        raise _identity_error("bad_trust_keys")
    keys = document.get("keys")
    if not isinstance(keys, dict) or not keys:
        raise _identity_error("bad_trust_keys")
    result: dict[str, bytes] = {}
    for kid, pem in keys.items():
        if not isinstance(kid, str) or not kid or not isinstance(pem, str) or not pem:
            raise _identity_error("bad_trust_keys")
        encoded = pem.encode("utf-8")
        if b"PRIVATE KEY" in encoded:
            raise _identity_error("bad_trust_keys")
        try:
            public_key = serialization.load_pem_public_key(encoded)
        except (TypeError, ValueError) as exc:
            raise _identity_error("bad_trust_keys") from exc
        if not isinstance(public_key, Ed25519PublicKey):
            raise _identity_error("bad_trust_keys")
        result[kid] = encoded
    return dict(result)


def _scope_claim(value: object, *, optional: bool = False) -> tuple[str, ...] | None:
    if optional and value is None:
        return None
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise _identity_error("bad_scope")
    return tuple(dict.fromkeys(value))


def _required_string(claims: Mapping[str, Any], name: str) -> str:
    value = claims.get(name)
    if not isinstance(value, str) or not value:
        raise _identity_error("missing_claim")
    return value


def _integer_claim(claims: Mapping[str, Any], name: str) -> int:
    value = claims.get(name)
    if type(value) is not int:
        raise _identity_error("missing_claim")
    return value


class IdentityVerifier:
    """Verify EdDSA principal JWTs and their bounded delegation chain."""

    def __init__(
        self,
        *,
        trusted_issuer: str,
        audience: str,
        tenant: str,
        trust_keys: Mapping[str, bytes | str],
        clock_skew_seconds: int = 30,
    ) -> None:
        self.trusted_issuer = trusted_issuer
        self.audience = audience
        self.tenant = tenant
        self._trust_keys = dict(trust_keys)
        self.clock_skew_seconds = clock_skew_seconds

    def _header_and_key(self, token: str) -> tuple[dict[str, Any], bytes | str]:
        if not isinstance(token, str) or not token or token.lower().startswith("bearer "):
            raise _identity_error("malformed_token")
        try:
            header = jwt.get_unverified_header(token)
        except Exception as exc:
            raise _identity_error("malformed_token") from exc
        if not isinstance(header, dict) or header.get("alg") != "EdDSA":
            raise _identity_error("bad_alg")
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise _identity_error("unknown_kid")
        key = self._trust_keys.get(kid)
        if key is None:
            raise _identity_error("unknown_kid")
        return header, key

    def _decode_principal(self, token: str) -> dict[str, Any]:
        _header, key = self._header_and_key(token)
        try:
            claims = jwt.decode(
                token,
                key=key,
                algorithms=["EdDSA"],
                audience=self.audience,
                issuer=self.trusted_issuer,
                leeway=self.clock_skew_seconds,
                options={
                    "require": [
                        "iss",
                        "sub",
                        "aud",
                        "exp",
                        "iat",
                        "tenant",
                        "agent",
                        "role",
                        "scope",
                    ]
                },
            )
        except jwt.ExpiredSignatureError as exc:
            raise _identity_error("expired") from exc
        except jwt.ImmatureSignatureError as exc:
            raise _identity_error("not_yet_valid") from exc
        except jwt.InvalidIssuerError as exc:
            raise _identity_error("wrong_issuer") from exc
        except jwt.InvalidAudienceError as exc:
            raise _identity_error("wrong_audience") from exc
        except jwt.MissingRequiredClaimError as exc:
            raise _identity_error("missing_claim") from exc
        except jwt.InvalidSignatureError as exc:
            raise _identity_error("bad_signature") from exc
        except jwt.PyJWTError as exc:
            raise _identity_error("malformed_token") from exc
        if not isinstance(claims, dict):
            raise _identity_error("malformed_token")
        return claims

    def _decode_hop(self, token: str) -> dict[str, Any]:
        _header, key = self._header_and_key(token)
        try:
            claims = jwt.decode(
                token,
                key=key,
                algorithms=["EdDSA"],
                issuer=self.trusted_issuer,
                leeway=self.clock_skew_seconds,
                options={
                    "verify_aud": False,
                    "require": ["iss", "sub", "aud", "exp", "iat", "tenant"],
                },
            )
        except jwt.ExpiredSignatureError as exc:
            raise _identity_error("delegation_expired") from exc
        except jwt.ImmatureSignatureError as exc:
            raise _identity_error("delegation_expired") from exc
        except jwt.InvalidIssuerError as exc:
            raise _identity_error("wrong_issuer") from exc
        except jwt.MissingRequiredClaimError as exc:
            raise _identity_error("missing_claim") from exc
        except jwt.InvalidSignatureError as exc:
            raise _identity_error("bad_signature") from exc
        except jwt.PyJWTError as exc:
            raise _identity_error("delegation_broken") from exc
        if not isinstance(claims, dict):
            raise _identity_error("delegation_broken")
        return claims

    def verify(self, token: str) -> VerifiedIdentity:
        claims = self._decode_principal(token)
        issuer = _required_string(claims, "iss")
        principal = _required_string(claims, "sub")
        agent = _required_string(claims, "agent")
        role = _required_string(claims, "role")
        tenant = _required_string(claims, "tenant")
        audience = claims.get("aud")
        if issuer != self.trusted_issuer:
            raise _identity_error("wrong_issuer")
        if not isinstance(audience, str) or audience != self.audience:
            raise _identity_error("wrong_audience")
        if tenant != self.tenant:
            raise _identity_error("wrong_tenant")
        token_scope = _scope_claim(claims.get("scope"))
        assert token_scope is not None
        expiry = _integer_claim(claims, "exp")
        issued_at = _integer_claim(claims, "iat")

        raw_delegation = claims.get("delegation", [])
        if not isinstance(raw_delegation, list):
            raise _identity_error("delegation_broken")
        if len(raw_delegation) > 3:
            raise _identity_error("delegation_depth")
        if any(not isinstance(hop, str) or not hop for hop in raw_delegation):
            raise _identity_error("delegation_broken")

        effective_scope = token_scope
        earliest_expiry = expiry
        decoded_hops: list[dict[str, Any]] = []
        for compact_hop in raw_delegation:
            hop = self._decode_hop(compact_hop)
            hop_issuer = _required_string(hop, "iss")
            hop_sub = _required_string(hop, "sub")
            _required_string(hop, "aud")
            hop_tenant = _required_string(hop, "tenant")
            hop_expiry = _integer_claim(hop, "exp")
            _integer_claim(hop, "iat")
            if hop_issuer != self.trusted_issuer:
                raise _identity_error("wrong_issuer")
            if hop_tenant != self.tenant:
                raise _identity_error("wrong_tenant")
            if not decoded_hops and hop_sub != principal:
                raise _identity_error("delegation_broken")
            if decoded_hops and decoded_hops[-1]["aud"] != hop_sub:
                raise _identity_error("delegation_broken")
            hop_scope = _scope_claim(hop.get("scope"), optional=True)
            if hop_scope is not None:
                allowed = set(hop_scope)
                effective_scope = tuple(name for name in effective_scope if name in allowed)
            earliest_expiry = min(earliest_expiry, hop_expiry)
            decoded_hops.append(hop)
        if decoded_hops and decoded_hops[-1]["aud"] != agent:
            raise _identity_error("delegation_broken")
        delegation_chain = tuple(raw_delegation)
        session_hash = (
            "sha256:"
            + hashlib.sha256(
                canonical_json(
                    {
                        "principal": principal,
                        "agent": agent,
                        "tenant": tenant,
                        "delegation": list(delegation_chain),
                    }
                )
            ).hexdigest()
        )
        return VerifiedIdentity(
            principal=principal,
            agent=agent,
            tenant=tenant,
            role=role,
            scope=tuple(effective_scope),
            token_scope=tuple(token_scope),
            delegation_chain=delegation_chain,
            issuer=issuer,
            audience=audience,
            expires_at=earliest_expiry,
            issued_at=issued_at,
            session_identity_hash=session_hash,
        )
