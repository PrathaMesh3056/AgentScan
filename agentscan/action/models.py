"""Action evidence models used by the action-verification spike."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class ToolIdentity(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    server: str
    schema_hash: str


class Authorization(BaseModel):
    model_config = ConfigDict(frozen=True)

    decision: Literal["allow", "deny"]
    policy_id: str


class ActionResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    status: Literal["success", "denied", "error"]
    summary: str


class ReceiptEvidence(BaseModel):
    model_config = ConfigDict(frozen=True)

    hash: str
    prev_hash: str


class ActionReceipt(BaseModel):
    """Immutable record of one tool authorization decision and its outcome."""

    model_config = ConfigDict(frozen=True)

    trace_id: str
    principal: str
    tool: ToolIdentity
    arguments: dict[str, Any]
    authorization: Authorization
    result: ActionResult
    evidence: ReceiptEvidence
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ActionFinding(BaseModel):
    """Finding for ACT modules; intentionally independent of core Finding."""

    model_config = ConfigDict(frozen=True)

    attack_id: Literal["ACT-001"] = "ACT-001"
    attack_name: str = "Unauthorized tool invocation"
    severity: Literal["HIGH", "MEDIUM", "LOW"] = "HIGH"
    description: str
    evidence: str
    receipt_hash: str
    metadata: dict[str, Any] = Field(default_factory=dict)
