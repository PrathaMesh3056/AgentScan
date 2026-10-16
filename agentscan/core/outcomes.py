"""Track coverage and failures independently of whether an attack finds a flaw."""

from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any


class ModuleUnavailableError(RuntimeError):
    """A required local dependency or reference model is unavailable."""


class AssessmentInconclusiveError(ModuleUnavailableError):
    """The response was delivered, but available evidence cannot establish a verdict."""


class TargetRequestError(RuntimeError):
    """A target request failed before it could be evaluated."""


@dataclass
class ExecutionLedger:
    errors: list[str] = field(default_factory=list)
    inconclusive_reasons: list[str] = field(default_factory=list)
    evaluated: int | None = None
    selected: int | None = None
    observations: list[dict[str, Any]] = field(default_factory=list)
    assessment_scope: str | None = None


execution_ledger: ContextVar[ExecutionLedger | None] = ContextVar(
    "agentscan_module_execution", default=None
)


def record_execution_error(reason: str) -> None:
    """Preserve a failure even if an older module catches its exception."""
    ledger = execution_ledger.get()
    if ledger is not None and reason not in ledger.errors:
        ledger.errors.append(reason)


def record_inconclusive(reason: str) -> None:
    ledger = execution_ledger.get()
    if ledger is not None and reason not in ledger.inconclusive_reasons:
        ledger.inconclusive_reasons.append(reason)


def record_observation(observation: dict[str, Any]) -> None:
    """Retain bounded metadata separately from findings and evaluated tests.

    Callers supply metadata, never raw confidential output. Copy the record so
    reusing a caller's dictionary cannot rewrite earlier observations.
    """
    ledger = execution_ledger.get()
    if ledger is not None:
        ledger.observations.append(dict(observation))


def record_evaluated_variant() -> None:
    ledger = execution_ledger.get()
    if ledger is not None:
        ledger.evaluated = (ledger.evaluated or 0) + 1
