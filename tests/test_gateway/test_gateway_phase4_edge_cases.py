"""Phase 4 polish: missing edge-case coverage called out by the Phase 4 prompt."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.provider import AccessToken
from pydantic import ValidationError

from agentscan.gateway.config import GatewaySettings
from agentscan.gateway.identity import (
    IdentityError,
    IdentityVerifier,
    VerifiedIdentity,
    load_trust_keys,
)
from agentscan.gateway.middleware import McpGuardMiddleware
from agentscan.gateway.models import ErrorCode
from agentscan.gateway.sessions import PINNED_PROTOCOL_VERSION, SessionNotFound, SessionRegistry


def _gateway_values(**changes: object) -> dict[str, object]:
    values: dict[str, object] = {
        "tenant": "tenant-a",
        "gateway_id": "gw-a",
        "chain_id": "chain/a",
        "writer_id": "writer-a",
        "audience": "agentscan",
        "trusted_issuer": "issuer-a",
        "listen_host": "127.0.0.1",
        "listen_port": 8765,
        "upstream_url": "http://127.0.0.1:9999",
        "upstream_server_id": "mock",
        "upstream_credential_env": "MOCK_TOKEN",
        "policy_bundle": "policy.yaml",
        "policy_public_key": "policy.pub",
        "trust_keys": "trust.json",
        "receipt_dir": "receipts",
    }
    values.update(changes)
    return values


def _settings(**changes: object) -> GatewaySettings:
    return GatewaySettings.model_validate(_gateway_values(**changes))


# ── Configuration edge cases ───────────────────────────────────────────────────


def test_empty_allowlists_are_rejected() -> None:
    with pytest.raises(ValidationError):
        _settings(allowed_hosts=[], allowed_origins=[])


@pytest.mark.parametrize(
    "changes",
    [
        {"allowed_hosts": ["user:pass@127.0.0.1:8765"]},
        {"allowed_hosts": ["127.0.0.1:8765?probe=1"]},
        {"allowed_hosts": ["127.0.0.1:8765#probe"]},
        {"allowed_origins": ["https://user:pass@127.0.0.1:8765"]},
        {"allowed_origins": ["http://127.0.0.1:8765/?probe=1"]},
        {"allowed_origins": ["http://127.0.0.1:8765/#probe"]},
        {"tenant": "tenant\\a"},
        {"chain_id": "chain id"},
        {"upstream_timeout_seconds": -1.0},
    ],
)
def test_unsafe_or_edge_configuration_is_rejected(changes: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        _settings(**changes)


@pytest.mark.parametrize("clock_skew_seconds", [0, 300])
def test_clock_skew_boundaries_are_accepted(clock_skew_seconds: int) -> None:
    assert _settings(clock_skew_seconds=clock_skew_seconds).clock_skew_seconds == clock_skew_seconds


@pytest.mark.parametrize(
    "field",
    ["retention_days", "session_idle_timeout_seconds", "max_idempotency_key_bytes"],
)
def test_strict_integer_fields_reject_booleans(field: str) -> None:
    with pytest.raises(ValidationError):
        _settings(**{field: True})


# ── Identity edge cases ───────────────────────────────────────────────────────


def _key_pair() -> tuple[Ed25519PrivateKey, bytes]:
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private, public


def _compact(private: Ed25519PrivateKey, claims: dict[str, Any], *, kid: str = "key-1") -> str:
    return jwt.encode(claims, private, algorithm="EdDSA", headers={"kid": kid})


def _verifier(public: bytes) -> IdentityVerifier:
    return IdentityVerifier(
        trusted_issuer="issuer-a",
        audience="agentscan",
        tenant="tenant-a",
        trust_keys={"key-1": public},
    )


def _principal_token(
    private: Ed25519PrivateKey, *, delegation: list[str] | None = None, **changes: Any
) -> str:
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
    if delegation is not None:
        claims["delegation"] = delegation
    claims.update(changes)
    return _compact(private, claims)


def _hop_token(
    private: Ed25519PrivateKey,
    *,
    sub: str,
    aud: str,
    scope: list[str] | None,
    now: int,
    **changes: Any,
) -> str:
    claims: dict[str, Any] = {
        "iss": "issuer-a",
        "sub": sub,
        "aud": aud,
        "exp": now + 300,
        "iat": now,
        "tenant": "tenant-a",
    }
    if scope is not None:
        claims["scope"] = scope
    claims.update(changes)
    return _compact(private, claims)


@pytest.mark.parametrize("algorithm", ["none", "HS256", "RS256", "ES256"])
def test_non_ed25519_algorithms_are_rejected(algorithm: str) -> None:
    private, public = _key_pair()
    now = int(time.time())
    base_claims: dict[str, Any] = {
        "iss": "issuer-a",
        "sub": "principal-a",
        "aud": "agentscan",
        "exp": now + 300,
        "iat": now,
        "tenant": "tenant-a",
        "agent": "agent-a",
        "role": "operator",
        "scope": ["tools/read"],
    }
    if algorithm == "HS256":
        token = jwt.encode(
            base_claims,
            "test-secret-value-1234567890abcdef",
            algorithm="HS256",
            headers={"kid": "key-1"},
        )
    elif algorithm == "RS256":
        token = jwt.encode(
            base_claims,
            rsa.generate_private_key(public_exponent=65537, key_size=2048),
            algorithm="RS256",
            headers={"kid": "key-1"},
        )
    elif algorithm == "ES256":
        token = jwt.encode(
            base_claims,
            ec.generate_private_key(ec.SECP256R1()),
            algorithm="ES256",
            headers={"kid": "key-1"},
        )
    else:
        token = jwt.encode(base_claims, key="", algorithm="none", headers={"kid": "key-1"})
    with pytest.raises(IdentityError) as error:
        _verifier(public).verify(token)
    assert error.value.reason == "bad_alg"


def test_two_and_three_hop_delegation_chains_verify() -> None:
    private, public = _key_pair()
    verifier = _verifier(public)
    now = int(time.time())

    two_hop = verifier.verify(
        _principal_token(
            private,
            delegation=[
                _hop_token(private, sub="principal-a", aud="agent-a", scope=["tools/read"], now=now)
            ],
        )
    )
    assert two_hop.scope == ("tools/read",)
    assert len(two_hop.delegation_chain) == 1

    three_hops = verifier.verify(
        _principal_token(
            private,
            delegation=[
                _hop_token(private, sub="principal-a", aud="mid-1", scope=["tools/read"], now=now),
                _hop_token(private, sub="mid-1", aud="mid-2", scope=None, now=now),
                _hop_token(private, sub="mid-2", aud="agent-a", scope=None, now=now),
            ],
        )
    )
    assert three_hops.scope == ("tools/read",)
    assert len(three_hops.delegation_chain) == 3


def test_delegation_audience_link_mismatches_deny() -> None:
    private, public = _key_pair()
    verifier = _verifier(public)
    now = int(time.time())

    middle_mismatch = _hop_token(private, sub="principal-a", aud="wrong-agent", scope=None, now=now)
    with pytest.raises(IdentityError) as error:
        verifier.verify(_principal_token(private, delegation=[middle_mismatch]))
    assert error.value.reason == "delegation_broken"

    final_mismatch = _hop_token(private, sub="principal-a", aud="agent-b", scope=None, now=now)
    with pytest.raises(IdentityError) as error:
        verifier.verify(_principal_token(private, delegation=[final_mismatch]))
    assert error.value.reason == "delegation_broken"


def test_unknown_delegation_hop_key_is_rejected() -> None:
    private, public = _key_pair()
    now = int(time.time())
    hop = _hop_token(private, sub="principal-a", aud="agent-a", scope=None, now=now)
    hop = jwt.encode(
        jwt.decode(hop, options={"verify_signature": False}),
        private,
        algorithm="EdDSA",
        headers={"kid": "unknown"},
    )
    with pytest.raises(IdentityError) as error:
        _verifier(public).verify(_principal_token(private, delegation=[hop]))
    assert error.value.reason == "unknown_kid"


@pytest.mark.parametrize(
    ("hop_changes", "reason"),
    [
        ({"exp": int(time.time()) - 60}, "delegation_expired"),
        ({"tenant": "other"}, "wrong_tenant"),
        ({"iss": "other"}, "wrong_issuer"),
    ],
)
def test_delegation_hop_failures_are_bounded(hop_changes: dict[str, Any], reason: str) -> None:
    private, public = _key_pair()
    now = int(time.time())
    hop = _hop_token(private, sub="principal-a", aud="agent-a", scope=None, now=now)
    hop = jwt.encode(
        {**jwt.decode(hop, options={"verify_signature": False}), **hop_changes},
        private,
        algorithm="EdDSA",
        headers={"kid": "key-1"},
    )
    with pytest.raises(IdentityError) as error:
        _verifier(public).verify(_principal_token(private, delegation=[hop]))
    assert error.value.reason == reason


def test_non_string_delegation_entry_and_hop_scope_intersection() -> None:
    private, public = _key_pair()
    now = int(time.time())
    with pytest.raises(IdentityError) as error:
        _verifier(public).verify(_principal_token(private, delegation=[123]))  # type: ignore[list-item]
    assert error.value.reason == "delegation_broken"

    identity = _verifier(public).verify(
        _principal_token(
            private,
            delegation=[
                _hop_token(
                    private, sub="principal-a", aud="agent-a", scope=["tools/read"], now=now
                ),
                _hop_token(private, sub="agent-a", aud="agent-a", scope=["tools/write"], now=now),
            ],
        )
    )
    assert identity.scope == ()


def test_session_identity_hash_changes_with_identity_fields() -> None:
    private, public = _key_pair()
    verifier = _verifier(public)
    now = int(time.time())
    plain = verifier.verify(_principal_token(private))
    delegated = verifier.verify(
        _principal_token(
            private,
            delegation=[_hop_token(private, sub="principal-a", aud="agent-a", scope=None, now=now)],
        )
    )
    assert plain.session_identity_hash != delegated.session_identity_hash
    assert (
        verifier.verify(_principal_token(private, sub="principal-b")).session_identity_hash
        != plain.session_identity_hash
    )
    assert (
        verifier.verify(_principal_token(private, agent="agent-b")).session_identity_hash
        != plain.session_identity_hash
    )
    other_tenant = IdentityVerifier(
        trusted_issuer="issuer-a",
        audience="agentscan",
        tenant="tenant-b",
        trust_keys={"key-1": public},
    )
    assert (
        other_tenant.verify(_principal_token(private, tenant="tenant-b")).session_identity_hash
        != plain.session_identity_hash
    )


def test_trust_key_loader_rejects_empty_and_non_ed25519_keys(tmp_path: Path) -> None:
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_pem = (
        rsa_key.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    path = tmp_path / "keys.json"
    path.write_text(json.dumps({"keys": {}}), encoding="utf-8")
    with pytest.raises(IdentityError):
        load_trust_keys(path)
    path.write_text(json.dumps({"keys": {"k": rsa_pem}}), encoding="utf-8")
    with pytest.raises(IdentityError):
        load_trust_keys(path)


# ── Session edge cases ─────────────────────────────────────────────────────────


def _session_identity(**changes: object) -> VerifiedIdentity:
    values: dict[str, object] = {
        "principal": "principal-a",
        "agent": "agent-a",
        "tenant": "tenant-a",
        "role": "operator",
        "scope": ("tools/read",),
        "token_scope": ("tools/read",),
        "delegation_chain": ("eyJ.test.jwt",),
        "issuer": "issuer-a",
        "audience": "agentscan",
        "expires_at": 10_000,
        "issued_at": 100,
        "session_identity_hash": "sha256:abc",
    }
    values.update(changes)
    return VerifiedIdentity(**values)  # type: ignore[arg-type]


def test_prune_expired_removes_only_expired_entries() -> None:
    now = [100.0]
    registry = SessionRegistry(
        idle_timeout_seconds=20, max_lifetime_seconds=60, clock=lambda: now[0]
    )
    registry.bind(
        "expired", _session_identity(expires_at=90), protocol_version=PINNED_PROTOCOL_VERSION
    )
    registry.bind(
        "fresh", _session_identity(expires_at=10_000), protocol_version=PINNED_PROTOCOL_VERSION
    )
    assert registry.prune_expired(now=100) == 1
    assert len(registry) == 1
    with pytest.raises(SessionNotFound):
        registry.validate("expired", _session_identity(expires_at=90), now=100)
    assert registry.validate("fresh", _session_identity(expires_at=10_000), now=100) is not None


def test_validate_returns_copies_of_the_bound_record() -> None:
    registry = SessionRegistry(
        idle_timeout_seconds=20, max_lifetime_seconds=60, clock=lambda: 100.0
    )
    registry.bind("s", _session_identity(), protocol_version=PINNED_PROTOCOL_VERSION)
    first = registry.validate("s", _session_identity(), now=100)
    second = registry.validate("s", _session_identity(), now=100)
    assert first is not second
    assert first == second
    assert second.last_seen_at == 100


# ── Middleware edge cases ──────────────────────────────────────────────────────


def _guard_identity(principal: str = "p") -> VerifiedIdentity:
    return VerifiedIdentity(
        principal,
        "agent",
        "tenant",
        "operator",
        ("tool",),
        ("tool",),
        (),
        "iss",
        "aud",
        9_999_999_999,
        1,
        f"hash:{principal}",
    )


def _guard_user(identity_value: VerifiedIdentity) -> AuthenticatedUser:
    return AuthenticatedUser(
        AccessToken(
            token="fake-token",
            client_id=identity_value.principal,
            subject=identity_value.principal,
            scopes=list(identity_value.scope),
            expires_at=identity_value.expires_at,
            claims={"iss": identity_value.issuer},
        )
    )


async def _guard(
    payload: Any,
    *,
    method: str = "POST",
    headers: list[tuple[bytes, bytes]] | None = None,
    body: bytes | None = None,
    authenticated: bool = True,
    downstream_response: tuple[int, list[tuple[bytes, bytes]], bytes] | None = None,
    registry: SessionRegistry | None = None,
    identity_value: VerifiedIdentity | None = None,
) -> tuple[list[dict[str, Any]], list[bool]]:
    resolved = identity_value if identity_value is not None else _guard_identity()
    if body is None:
        body = json.dumps(payload, separators=(",", ":")).encode() if payload is not None else b""
    request_messages: list[dict[str, Any]] = [
        {"type": "http.request", "body": body, "more_body": False}
    ]
    scope: dict[str, Any] = {
        "type": "http",
        "path": "/mcp",
        "method": method,
        "headers": headers or [],
        "state": {"verified_identity": resolved},
    }
    if authenticated:
        scope["user"] = _guard_user(resolved)
    responses: list[dict[str, Any]] = []
    reached: list[bool] = []

    async def receive() -> dict[str, Any]:
        return request_messages.pop(0) if request_messages else {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        responses.append(message)

    async def app(_scope: dict[str, Any], _receive: Any, send_: Any) -> None:
        reached.append(True)
        if downstream_response is not None:
            status, response_headers, response_body = downstream_response
            await send_(
                {"type": "http.response.start", "status": status, "headers": response_headers}
            )
            await send_({"type": "http.response.body", "body": response_body, "more_body": False})

    resolved_registry = (
        registry
        if registry is not None
        else SessionRegistry(idle_timeout_seconds=20, max_lifetime_seconds=60)
    )
    guard = McpGuardMiddleware(app, sessions=resolved_registry, max_request_bytes=4096)
    await guard(scope, receive, send)
    return responses, reached


async def test_missing_session_header_is_rejected_before_downstream() -> None:
    responses, reached = await _guard(
        {"jsonrpc": "2.0", "method": "ping", "id": 1},
        headers=[(b"mcp-protocol-version", PINNED_PROTOCOL_VERSION.encode())],
    )
    assert responses[0]["status"] == 400
    assert json.loads(responses[1]["body"])["agentscan_code"] == ErrorCode.IDENTITY_MISSING.value
    assert not reached


async def test_changed_identity_is_rejected_without_rebind() -> None:
    registry = SessionRegistry(idle_timeout_seconds=20, max_lifetime_seconds=60)
    registry.bind("s", _guard_identity("p"), protocol_version=PINNED_PROTOCOL_VERSION)
    responses, reached = await _guard(
        {"jsonrpc": "2.0", "method": "ping", "id": 1},
        headers=[
            (b"mcp-session-id", b"s"),
            (b"mcp-protocol-version", PINNED_PROTOCOL_VERSION.encode()),
        ],
        registry=registry,
        identity_value=_guard_identity("q"),
    )
    assert responses[0]["status"] == 403
    assert json.loads(responses[1]["body"])["agentscan_code"] == ErrorCode.IDENTITY_MISMATCH.value
    assert not reached


async def test_successful_delete_removes_bound_session() -> None:
    registry = SessionRegistry(idle_timeout_seconds=20, max_lifetime_seconds=60)
    registry.bind("s", _guard_identity("p"), protocol_version=PINNED_PROTOCOL_VERSION)
    responses, _reached = await _guard(
        None,
        method="DELETE",
        headers=[
            (b"mcp-session-id", b"s"),
            (b"mcp-protocol-version", PINNED_PROTOCOL_VERSION.encode()),
        ],
        registry=registry,
        downstream_response=(200, [(b"content-type", b"application/json")], b"{}"),
    )
    assert responses[0]["status"] == 200
    assert len(registry) == 0


async def test_initialize_binds_only_after_successful_initialize_response() -> None:
    registry = SessionRegistry(idle_timeout_seconds=20, max_lifetime_seconds=60)
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2024-11-05"}}
    ).encode()
    responses, _reached = await _guard(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2024-11-05", "clientInfo": {"name": "test"}},
        },
        downstream_response=(
            200,
            [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
                (b"mcp-session-id", b"session-a"),
            ],
            body,
        ),
        registry=registry,
    )
    assert responses[0]["status"] == 200
    assert len(registry) == 1
    assert json.loads(responses[-1]["body"])["result"]["protocolVersion"] == PINNED_PROTOCOL_VERSION


async def test_failed_initialize_does_not_bind_session() -> None:
    registry = SessionRegistry(idle_timeout_seconds=20, max_lifetime_seconds=60)
    responses, _reached = await _guard(
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        downstream_response=(
            400,
            [(b"content-type", b"application/json")],
            b'{"jsonrpc":"2.0","id":1,"error":{"code":-32600}}',
        ),
        registry=registry,
    )
    assert responses[0]["status"] == 400
    assert len(registry) == 0


async def test_initialize_without_session_id_header_does_not_bind() -> None:
    registry = SessionRegistry(idle_timeout_seconds=20, max_lifetime_seconds=60)
    responses, _reached = await _guard(
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        downstream_response=(
            200,
            [(b"content-type", b"application/json")],
            b'{"jsonrpc":"2.0","id":1,"result":{}}',
        ),
        registry=registry,
    )
    assert responses[0]["status"] == 200
    assert len(registry) == 0


async def test_header_names_are_case_insensitive() -> None:
    registry = SessionRegistry(idle_timeout_seconds=20, max_lifetime_seconds=60)
    registry.bind("S", _guard_identity("p"), protocol_version=PINNED_PROTOCOL_VERSION)
    responses, reached = await _guard(
        {"jsonrpc": "2.0", "method": "ping", "id": 1},
        headers=[
            (b"MCP-Protocol-Version", PINNED_PROTOCOL_VERSION.encode()),
            (b"MCP-Session-Id", b"S"),
        ],
        registry=registry,
        downstream_response=(200, [(b"content-type", b"application/json")], b"{}"),
    )
    assert reached
    assert responses[0]["status"] == 200


async def test_oversize_post_returns_413_without_downstream_call() -> None:
    registry = SessionRegistry(idle_timeout_seconds=20, max_lifetime_seconds=60)
    responses, reached = await _guard(
        None,
        body=b'{"jsonrpc":"2.0","method":"ping","id":1,"params":{"pad":"' + b"x" * 5000 + b'"}}',
        registry=registry,
    )
    assert responses[0]["status"] == 413
    assert json.loads(responses[1]["body"])["agentscan_code"] == ErrorCode.GATEWAY_UNAVAILABLE.value
    assert not reached
