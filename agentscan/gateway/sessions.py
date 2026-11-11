"""Gateway-owned binding of MCP sessions to verified identities."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from typing import Any

from agentscan.gateway.identity import VerifiedIdentity

PINNED_PROTOCOL_VERSION = "2025-11-25"


class SessionError(Exception):
    pass


class SessionNotFound(SessionError):
    pass


class SessionExpired(SessionError):
    pass


class SessionIdentityMismatch(SessionError):
    pass


@dataclass(frozen=True, slots=True)
class SessionRecord:
    session_id: str
    principal: str
    agent: str
    tenant: str
    role: str
    delegation_chain: tuple[str, ...] = field(repr=False)
    session_identity_hash: str
    client_name: str | None
    client_version: str | None
    protocol_version: str
    token_expires_at: int
    created_at: float
    last_seen_at: float


class SessionRegistry:
    def __init__(
        self,
        *,
        idle_timeout_seconds: float,
        max_lifetime_seconds: float,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if idle_timeout_seconds <= 0 or max_lifetime_seconds <= idle_timeout_seconds:
            raise ValueError("invalid session lifetimes")
        self.idle_timeout_seconds = idle_timeout_seconds
        self.max_lifetime_seconds = max_lifetime_seconds
        self._clock = clock
        self._records: dict[str, SessionRecord] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _client_value(client_info: Mapping[str, Any] | None, key: str) -> str | None:
        value = client_info.get(key) if client_info is not None else None
        return value[:128] if isinstance(value, str) else None

    def bind(
        self,
        session_id: str,
        identity: VerifiedIdentity,
        *,
        client_info: Mapping[str, Any] | None = None,
        protocol_version: str,
    ) -> SessionRecord:
        if not session_id or protocol_version != PINNED_PROTOCOL_VERSION:
            raise ValueError("invalid session binding")
        now = self._clock()
        record = SessionRecord(
            session_id=session_id,
            principal=identity.principal,
            agent=identity.agent,
            tenant=identity.tenant,
            role=identity.role,
            delegation_chain=tuple(identity.delegation_chain),
            session_identity_hash=identity.session_identity_hash,
            client_name=self._client_value(client_info, "name"),
            client_version=self._client_value(client_info, "version"),
            protocol_version=protocol_version,
            token_expires_at=identity.expires_at,
            created_at=now,
            last_seen_at=now,
        )
        with self._lock:
            if session_id in self._records:
                raise ValueError("session already bound")
            self._records[session_id] = record
        return replace(record)

    def _expired(self, record: SessionRecord, now: float) -> bool:
        return (
            now >= record.token_expires_at
            or now - record.last_seen_at >= self.idle_timeout_seconds
            or now - record.created_at >= self.max_lifetime_seconds
        )

    def validate(
        self, session_id: str, identity: VerifiedIdentity, *, now: float | None = None
    ) -> SessionRecord:
        current = self._clock() if now is None else now
        with self._lock:
            record = self._records.get(session_id)
            if record is None:
                raise SessionNotFound("session not found")
            if self._expired(record, current):
                del self._records[session_id]
                raise SessionExpired("session expired")
            # Role is stricter defense in depth; it is not in the canonical identity hash.
            if (
                record.principal != identity.principal
                or record.agent != identity.agent
                or record.tenant != identity.tenant
                or record.role != identity.role
                or record.delegation_chain != identity.delegation_chain
                or record.session_identity_hash != identity.session_identity_hash
            ):
                raise SessionIdentityMismatch("session identity mismatch")
            updated = replace(record, last_seen_at=current)
            self._records[session_id] = updated
            return replace(updated)

    def remove(self, session_id: str) -> None:
        with self._lock:
            self._records.pop(session_id, None)

    def prune_expired(self, *, now: float | None = None) -> int:
        current = self._clock() if now is None else now
        with self._lock:
            expired = [key for key, value in self._records.items() if self._expired(value, current)]
            for key in expired:
                del self._records[key]
            return len(expired)

    def __len__(self) -> int:
        with self._lock:
            return len(self._records)
