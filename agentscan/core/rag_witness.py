"""Trusted Python evidence from an operator-owned RAG application fixture.

This channel is never deserialized from a Target, model reply or remote receipt.
The producer must inspect the owned application's actual source/answer policy;
an honest producer and independently reviewed fixture remain trust assumptions.
Local lab witnesses do not establish customer-agent or general RAG accuracy.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any

from agentscan.core.context import ScanContext, active_context

RAG_VALIDATION_SCOPES = frozenset({"owned_rag_lab"})
_HASH = re.compile(r"[a-f0-9]{64}\Z")
_PUBLIC_ID = re.compile(r"[A-Za-z0-9_.-]{1,64}\Z")
_NAME = re.compile(r"[ -~]{1,128}\Z")
_EFFECTS = frozenset({"answer_integrity_violation", "citation_policy_violation"})
_PROBE_KEYS = frozenset({"id", "name", "channel", "payload", "user_task", "observation_marker"})


def _utf8_text(value: Any, limit: int) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return len(value.encode("utf-8")) <= limit
    except UnicodeError:
        return False


def _valid_hash(value: Any) -> bool:
    return isinstance(value, str) and _HASH.fullmatch(value) is not None


@dataclass(frozen=True, slots=True)
class RagDelivery:
    nonce: str
    scan_id: str
    variant_id: str
    source_sha256: str
    task_sha256: str


@dataclass(frozen=True, slots=True)
class RagWitness:
    scope: str
    profile: str
    response_sha256: str
    effect: str | None
    disposition: str
    evidence_sha256: str


_collector: ContextVar[RagWitnessCollector | None] = ContextVar("rag_witnesses", default=None)
_delivery: ContextVar[RagDelivery | None] = ContextVar("rag_delivery", default=None)


class RagWitnessCollector:
    """Bind consume-once local witnesses to a scan and an exact delivery.

    A Python producer can lie; this is an in-process instrumentation boundary,
    not independent attestation or a remotely configurable evaluation feature.
    Probe metadata is copied on enrollment and access, and arbitrary extra
    fields cannot silently enter module configuration or exported observations.
    """

    def __init__(
        self, *, profile: str, probes: list[dict[str, Any]], scope: str = "owned_rag_lab"
    ) -> None:
        if scope != "owned_rag_lab":
            raise ValueError("A declared owned RAG lab scope is required.")
        if not isinstance(profile, str) or not _PUBLIC_ID.fullmatch(profile):
            raise ValueError("A bounded public ASCII RAG profile is required.")
        if not isinstance(probes, list) or not 1 <= len(probes) <= 64:
            raise ValueError("Enroll between one and 64 owned RAG probes.")
        copied: list[dict[str, str]] = []
        identifiers: set[str] = set()
        for probe in probes:
            if not isinstance(probe, dict) or set(probe) != _PROBE_KEYS:
                raise ValueError("Use only the documented owned RAG probe fields.")
            identifier = probe["id"]
            name = probe["name"]
            if (
                not isinstance(identifier, str)
                or not _PUBLIC_ID.fullmatch(identifier)
                or identifier in identifiers
                or not isinstance(name, str)
                or not _NAME.fullmatch(name)
                or not name.strip()
                or probe["channel"] != "document"
                or not _utf8_text(probe["payload"], 65_536)
                or not _utf8_text(probe["user_task"], 4096)
                or not _utf8_text(probe["observation_marker"], 128)
            ):
                raise ValueError("Invalid or duplicate owned RAG probe metadata.")
            identifiers.add(identifier)
            copied.append({key: probe[key] for key in _PROBE_KEYS})
        self._scope = scope
        self._profile = profile
        self._probes = tuple(copied)
        self._identifiers = frozenset(identifiers)
        self._probe_hashes = {
            probe["id"]: (
                hashlib.sha256(probe["payload"].encode("utf-8")).hexdigest(),
                hashlib.sha256(probe["user_task"].encode("utf-8")).hexdigest(),
            )
            for probe in copied
        }
        self._pending: dict[str, tuple[RagDelivery, ScanContext]] = {}
        self._witnesses: dict[str, RagWitness] = {}

    @property
    def scope(self) -> str:
        return self._scope

    @property
    def profile(self) -> str:
        return self._profile

    @property
    def probes(self) -> tuple[dict[str, str], ...]:
        return tuple(dict(probe) for probe in self._probes)

    def _owns_current(self, delivery: RagDelivery | None) -> bool:
        context = active_context.get()
        pending = self._pending.get(delivery.nonce) if isinstance(delivery, RagDelivery) else None
        return (
            isinstance(delivery, RagDelivery)
            and context is not None
            and _collector.get() is self
            and _delivery.get() is delivery
            and pending is not None
            and pending[0] is delivery
            and pending[1] is context
            and context.scan_id == delivery.scan_id
        )

    def record(
        self,
        delivery: RagDelivery | None,
        response_text: str,
        *,
        effect: str | None,
        disposition: str,
        healthy: bool = True,
        observation_complete: bool = True,
        evidence_sha256: str,
    ) -> bool:
        """Record only after observing the enrolled application's policy/state."""
        if not self._owns_current(delivery) or delivery is None:
            return False
        if delivery.nonce in self._witnesses:
            return False
        if healthy is not True or observation_complete is not True:
            return False
        if not _valid_hash(evidence_sha256):
            return False
        if not isinstance(disposition, str) or (effect is not None and not isinstance(effect, str)):
            return False
        if disposition == "forbidden_effect":
            if effect not in _EFFECTS:
                return False
        elif disposition in {"assessed_no_effect", "policy_rejected"}:
            if effect is not None:
                return False
        else:
            return False
        try:
            response_hash = hashlib.sha256(response_text.encode("utf-8")).hexdigest()
        except (AttributeError, UnicodeError):
            return False
        self._witnesses[delivery.nonce] = RagWitness(
            self.scope, self.profile, response_hash, effect, disposition, evidence_sha256
        )
        return True

    def consume(self, delivery: RagDelivery | None, response_text: str) -> RagWitness | None:
        """A failed response binding consumes this delivery's pending evidence."""
        if not self._owns_current(delivery) or delivery is None:
            return None
        witness = self._witnesses.pop(delivery.nonce, None)
        self._pending.pop(delivery.nonce, None)
        try:
            response_hash = hashlib.sha256(response_text.encode("utf-8")).hexdigest()
        except (AttributeError, UnicodeError):
            return None
        return witness if witness is not None and witness.response_sha256 == response_hash else None


def active_rag_collector() -> RagWitnessCollector | None:
    return _collector.get()


def current_rag_delivery() -> RagDelivery | None:
    """This local capability is never placed into prompts or network envelopes."""
    return _delivery.get()


@contextmanager
def use_rag_witnesses(collector: RagWitnessCollector) -> Iterator[None]:
    if not isinstance(collector, RagWitnessCollector):
        raise TypeError("A trusted Python RagWitnessCollector is required.")
    token = _collector.set(collector)
    try:
        yield
    finally:
        _collector.reset(token)


@contextmanager
def rag_delivery(
    variant_id: str, source_sha256: str, task_sha256: str
) -> Iterator[RagDelivery | None]:
    if (
        not isinstance(variant_id, str)
        or not _PUBLIC_ID.fullmatch(variant_id)
        or not _valid_hash(source_sha256)
        or not _valid_hash(task_sha256)
    ):
        raise ValueError("A valid RAG variant and exact source/task SHA256 are required.")
    collector = _collector.get()
    context = active_context.get()
    if collector is None or context is None:
        yield None
        return
    if variant_id not in collector._identifiers:
        raise ValueError("The RAG variant is not enrolled in the owned lab profile.")
    if collector._probe_hashes[variant_id] != (source_sha256, task_sha256):
        raise ValueError("The RAG delivery must match the enrolled source and task bytes.")
    delivery = RagDelivery(
        uuid.uuid4().hex, context.scan_id, variant_id, source_sha256, task_sha256
    )
    collector._pending[delivery.nonce] = (delivery, context)
    token = _delivery.set(delivery)
    try:
        yield delivery
    finally:
        collector._pending.pop(delivery.nonce, None)
        collector._witnesses.pop(delivery.nonce, None)
        _delivery.reset(token)
