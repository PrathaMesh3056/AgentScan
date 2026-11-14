from __future__ import annotations

import pytest

from agentscan.gateway.identity import VerifiedIdentity
from agentscan.gateway.sessions import (
    PINNED_PROTOCOL_VERSION,
    SessionExpired,
    SessionIdentityMismatch,
    SessionNotFound,
    SessionRegistry,
)

JWT = "eyJ.test.jwt"


def identity(**changes: object) -> VerifiedIdentity:
    values: dict[str, object] = {
        "principal": "principal-a",
        "agent": "agent-a",
        "tenant": "tenant-a",
        "role": "operator",
        "scope": ("tools/read",),
        "token_scope": ("tools/read",),
        "delegation_chain": (JWT,),
        "issuer": "issuer-a",
        "audience": "agentscan",
        "expires_at": 10_000,
        "issued_at": 100,
        "session_identity_hash": "sha256:abc",
    }
    values.update(changes)
    return VerifiedIdentity(**values)  # type: ignore[arg-type]


def test_bind_validate_updates_activity_and_redacts_jwt() -> None:
    now = [100.0]
    registry = SessionRegistry(
        idle_timeout_seconds=20, max_lifetime_seconds=60, clock=lambda: now[0]
    )
    record = registry.bind(
        "session-a",
        identity(),
        client_info={"name": "x" * 140, "version": "1", "extra": JWT},
        protocol_version=PINNED_PROTOCOL_VERSION,
    )
    assert len(record.client_name or "") == 128
    assert record.client_version == "1"
    assert JWT not in repr(record)
    now[0] = 110
    validated = registry.validate("session-a", identity())
    assert validated.last_seen_at == 110 and validated.created_at == 100


@pytest.mark.parametrize(
    "changes",
    [
        {"principal": "other"},
        {"agent": "other"},
        {"tenant": "other"},
        {"role": "admin"},
        {"delegation_chain": ("different",)},
    ],
)
def test_tuple_change_is_rejected(changes: dict[str, object]) -> None:
    registry = SessionRegistry(idle_timeout_seconds=20, max_lifetime_seconds=60, clock=lambda: 100)
    registry.bind("s", identity(), protocol_version=PINNED_PROTOCOL_VERSION)
    with pytest.raises(SessionIdentityMismatch):
        registry.validate("s", identity(**changes))


@pytest.mark.parametrize("now", [111, 121, 161])
def test_token_idle_and_lifetime_expiry_remove_session(now: float) -> None:
    clock = [100.0]
    registry = SessionRegistry(
        idle_timeout_seconds=20, max_lifetime_seconds=60, clock=lambda: clock[0]
    )
    expires = 110 if now == 111 else 10_000
    registry.bind("s", identity(expires_at=expires), protocol_version=PINNED_PROTOCOL_VERSION)
    with pytest.raises(SessionExpired):
        registry.validate("s", identity(expires_at=expires), now=now)
    assert len(registry) == 0


def test_duplicate_unknown_protocol_copy_and_prune() -> None:
    now = [100.0]
    registry = SessionRegistry(
        idle_timeout_seconds=20, max_lifetime_seconds=60, clock=lambda: now[0]
    )
    with pytest.raises(ValueError):
        registry.bind("x", identity(), protocol_version="2024-11-05")
    record = registry.bind("x", identity(), protocol_version=PINNED_PROTOCOL_VERSION)
    with pytest.raises(ValueError):
        registry.bind("x", identity(), protocol_version=PINNED_PROTOCOL_VERSION)
    assert record is not registry.validate("x", identity())
    with pytest.raises(SessionNotFound):
        registry.validate("missing", identity())
    registry.bind("y", identity(), protocol_version=PINNED_PROTOCOL_VERSION)
    assert registry.prune_expired(now=121) == 2
    assert len(registry) == 0
