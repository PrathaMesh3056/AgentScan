"""Operator-owned, in-process evidence from an instrumented output consumer.

This channel is not deserialized from Target, HTTP or model responses. Its
producer must observe the application's actual consumer, not replay output into
an unrelated sink. It is a trusted Python integration, not remote attestation.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass

from agentscan.core.context import active_context

CONSUMER_VALIDATION_SCOPES = frozenset({"owned_synthetic_target", "local_consumer_lab"})
_HASH = re.compile(r"[a-f0-9]{64}\Z")
_EFFECTS = {
    "browser": {"browser_script_executed"},
    "resource": {"resource_request_attempt"},
    "sqlite": {"sql_unauthorized_read", "sql_unauthorized_write"},
}
_BROWSER_CONTEXTS = {
    "html",
    "html_url",
    "html_image",
    "markdown_image",
    "markdown_protocol_relative",
    "css_resource",
}
_CONTEXTS = {
    "browser": _BROWSER_CONTEXTS,
    "resource": _BROWSER_CONTEXTS,
    "sqlite": {"sql"},
}


@dataclass(frozen=True)
class OutputDelivery:
    nonce: str
    scan_id: str
    variant_id: str
    output_context: str


@dataclass(frozen=True)
class OutputWitness:
    scope: str
    profile: str
    response_sha256: str
    consumer_kind: str
    effect: str | None
    disposition: str
    evidence_sha256: str


_collector: ContextVar[OutputWitnessCollector | None] = ContextVar("output_witnesses", default=None)
_delivery: ContextVar[OutputDelivery | None] = ContextVar("output_delivery", default=None)


class OutputWitnessCollector:
    """Consume-once witnesses from trusted instrumentation in an owned fixture.

    These scopes are deliberately excluded from customer target security scores.
    A Python caller can lie about evidence: this API does not make an untrusted
    producer trustworthy. The independent fixture/state audit remains necessary.
    """

    def __init__(self, *, scope: str, profile: str) -> None:
        if scope not in CONSUMER_VALIDATION_SCOPES:
            raise ValueError("A declared local consumer-validation scope is required.")
        if not isinstance(profile, str) or not profile.strip() or len(profile) > 64:
            raise ValueError("A bounded public consumer profile is required.")
        self.scope = scope
        self.profile = profile
        self._pending: dict[str, OutputDelivery] = {}
        self._witnesses: dict[str, OutputWitness] = {}

    def _owns_current(self, delivery: OutputDelivery | None) -> bool:
        context = active_context.get()
        return (
            delivery is not None
            and _collector.get() is self
            and _delivery.get() is delivery
            and self._pending.get(delivery.nonce) is delivery
            and (context is None or context.scan_id == delivery.scan_id)
        )

    def record(
        self,
        delivery: OutputDelivery | None,
        response_text: str,
        *,
        consumer_kind: str,
        effect: str | None,
        disposition: str,
        healthy: bool,
        observation_complete: bool,
        evidence_sha256: str,
    ) -> bool:
        """Record after independent state inspection; never accept model claims."""
        if not self._owns_current(delivery) or delivery is None:
            return False
        if delivery.nonce in self._witnesses:
            return False
        if healthy is not True or observation_complete is not True:
            return False
        if consumer_kind not in _EFFECTS or delivery.output_context not in _CONTEXTS[consumer_kind]:
            return False
        if not isinstance(evidence_sha256, str) or not _HASH.fullmatch(evidence_sha256):
            return False
        if disposition == "forbidden_effect":
            if effect not in _EFFECTS[consumer_kind]:
                return False
        elif disposition in {"consumed_no_effect", "policy_rejected"}:
            if effect is not None:
                return False
        else:
            return False
        try:
            digest = hashlib.sha256(response_text.encode("utf-8")).hexdigest()
        except (AttributeError, UnicodeError):
            return False
        self._witnesses[delivery.nonce] = OutputWitness(
            self.scope, self.profile, digest, consumer_kind, effect, disposition, evidence_sha256
        )
        return True

    def consume(self, delivery: OutputDelivery, response_text: str) -> OutputWitness | None:
        """Even a failed hash check spends the current delivery's evidence."""
        if not self._owns_current(delivery):
            return None
        witness = self._witnesses.pop(delivery.nonce, None)
        self._pending.pop(delivery.nonce, None)
        try:
            digest = hashlib.sha256(response_text.encode("utf-8")).hexdigest()
        except (AttributeError, UnicodeError):
            return None
        return witness if witness is not None and witness.response_sha256 == digest else None


def active_output_collector() -> OutputWitnessCollector | None:
    return _collector.get()


def current_output_delivery() -> OutputDelivery | None:
    """Available only to in-process instrumentation, never inserted in prompts."""
    return _delivery.get()


@contextmanager
def use_output_witnesses(collector: OutputWitnessCollector) -> Iterator[None]:
    token = _collector.set(collector)
    try:
        yield
    finally:
        _collector.reset(token)


@contextmanager
def output_delivery(variant_id: str, output_context: str) -> Iterator[OutputDelivery | None]:
    collector = _collector.get()
    if collector is None:
        yield None
        return
    context = active_context.get()
    delivery = OutputDelivery(
        uuid.uuid4().hex,
        context.scan_id if context else uuid.uuid4().hex,
        variant_id,
        output_context,
    )
    collector._pending[delivery.nonce] = delivery
    token = _delivery.set(delivery)
    try:
        yield delivery
    finally:
        collector._pending.pop(delivery.nonce, None)
        collector._witnesses.pop(delivery.nonce, None)
        _delivery.reset(token)
