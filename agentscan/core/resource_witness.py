"""Trusted in-process resource and neutral-service evidence for owned ATK-004 labs.

Nothing in an HTTP response or Target JSON can create this witness. A Python
integration must instrument the actual application and its neutral admission
path. This is local validation, not remote attestation.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass

_HASH = re.compile(r"[a-f0-9]{64}\Z")
OWNED_RESOURCE_SCOPE = "owned_resource_lab"


@dataclass(frozen=True)
class ResourceDelivery:
    nonce: str
    variant_id: str
    request_sha256: str


@dataclass(frozen=True)
class ResourceWitness:
    response_sha256: str
    neutral_before_admitted: bool
    neutral_after_admitted: bool
    work_units_before: int
    attributed_work_units: int
    cumulative_work_units: int
    evidence_sha256: str


_collector: ContextVar[ResourceWitnessCollector | None] = ContextVar(
    "agentscan_resource_witnesses", default=None
)
_delivery: ContextVar[ResourceDelivery | None] = ContextVar(
    "agentscan_resource_delivery", default=None
)


class ResourceWitnessCollector:
    """Consume-once local witness with a predeclared cumulative work budget."""

    def __init__(self, *, profile: str, work_budget: int) -> None:
        if not isinstance(profile, str) or not profile.strip() or len(profile) > 64:
            raise ValueError("A bounded owned-resource profile is required.")
        if type(work_budget) is not int or not 1 <= work_budget <= 1_000_000_000:
            raise ValueError("A positive predeclared work budget is required.")
        self.profile = profile
        self.work_budget = work_budget
        self.scope = OWNED_RESOURCE_SCOPE
        self._pending: dict[str, ResourceDelivery] = {}
        self._witnesses: dict[str, ResourceWitness] = {}
        self._last_work_units = 0
        self._last_neutral_after: bool | None = None

    def record(
        self,
        delivery: ResourceDelivery | None,
        *,
        observed_request_sha256: str,
        response_sha256: str,
        neutral_before_admitted: bool,
        neutral_after_admitted: bool,
        work_units_before: int,
        attributed_work_units: int,
        cumulative_work_units: int,
        evidence_sha256: str,
    ) -> bool:
        """Accept only the current delivery and bounded independent measurements."""
        if (
            delivery is None
            or _collector.get() is not self
            or _delivery.get() is not delivery
            or self._pending.get(delivery.nonce) is not delivery
            or delivery.nonce in self._witnesses
            or observed_request_sha256 != delivery.request_sha256
            or not isinstance(response_sha256, str)
            or not _HASH.fullmatch(response_sha256)
            or not isinstance(evidence_sha256, str)
            or not _HASH.fullmatch(evidence_sha256)
            or type(neutral_before_admitted) is not bool
            or type(neutral_after_admitted) is not bool
            or type(cumulative_work_units) is not int
            or not 0 <= cumulative_work_units <= 1_000_000_000
            or type(work_units_before) is not int
            or type(attributed_work_units) is not int
            or not 0 <= work_units_before <= 1_000_000_000
            or not 0 <= attributed_work_units <= 1_000_000_000
            or work_units_before + attributed_work_units != cumulative_work_units
            or (self._last_neutral_after is not None and work_units_before != self._last_work_units)
            or cumulative_work_units < self._last_work_units
            or (
                self._last_neutral_after is not None
                and neutral_before_admitted != self._last_neutral_after
            )
        ):
            return False
        self._witnesses[delivery.nonce] = ResourceWitness(
            response_sha256,
            neutral_before_admitted,
            neutral_after_admitted,
            work_units_before,
            attributed_work_units,
            cumulative_work_units,
            evidence_sha256,
        )
        return True

    def consume(self, delivery: ResourceDelivery, response_sha256: str) -> ResourceWitness | None:
        """Spend the current delivery even if response correlation fails."""
        if _collector.get() is not self or self._pending.pop(delivery.nonce, None) is not delivery:
            return None
        witness = self._witnesses.pop(delivery.nonce, None)
        if witness is None or witness.response_sha256 != response_sha256:
            return None
        self._last_work_units = witness.cumulative_work_units
        self._last_neutral_after = witness.neutral_after_admitted
        return witness


def active_resource_collector() -> ResourceWitnessCollector | None:
    return _collector.get()


def current_resource_delivery() -> ResourceDelivery | None:
    """Visible only to in-process application instrumentation, never in prompts."""
    return _delivery.get()


@contextmanager
def use_resource_witnesses(collector: ResourceWitnessCollector) -> Iterator[None]:
    token = _collector.set(collector)
    try:
        yield
    finally:
        _collector.reset(token)


@contextmanager
def resource_delivery(variant_id: str, request_sha256: str) -> Iterator[ResourceDelivery | None]:
    collector = _collector.get()
    if collector is None:
        yield None
        return
    delivery = ResourceDelivery(uuid.uuid4().hex, variant_id, request_sha256)
    collector._pending[delivery.nonce] = delivery
    token = _delivery.set(delivery)
    try:
        yield delivery
    finally:
        collector._pending.pop(delivery.nonce, None)
        collector._witnesses.pop(delivery.nonce, None)
        _delivery.reset(token)
