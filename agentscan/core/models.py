# agentscan/core/models.py
#
# The single source of truth for every data structure in AgentScan.
# Every module imports from here. Never define data shapes anywhere else.
#
# Rule: if you are tempted to use a dict, use one of these models instead.

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, field_validator

# ── Enums ─────────────────────────────────────────────────────────────────────


class Severity(StrEnum):
    """
    Severity levels for findings. Inherits from str so it serialises
    to JSON as a plain string ("HIGH") not as {"value": "HIGH"}.
    """

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    PASS = "PASS"


class ScanMode(StrEnum):
    """
    Controls which attack modules run.
    SCAN    = passive detection only
    EXPLOIT = active proof-of-impact (--exploit flag)
    DEEP    = neural internals (--deep flag, open-weight models only)
    """

    SCAN = "SCAN"
    EXPLOIT = "EXPLOIT"
    DEEP = "DEEP"


class Framework(StrEnum):
    """Known agent frameworks. AUTO means AgentScan will try to detect it."""

    LANGCHAIN = "langchain"
    LLAMA_INDEX = "llama_index"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    CREWAI = "crewai"
    AUTO = "auto"
    UNKNOWN = "unknown"


# ── Target ────────────────────────────────────────────────────────────────────


class Target(BaseModel):
    """
    Represents the LLM agent endpoint being scanned.
    This is the input to every attack module.
    """

    url: str = Field(
        ...,
        description="The HTTP endpoint to scan. Must be reachable.",
        examples=["http://localhost:8000/chat", "https://myagent.example.com/api/chat"],
    )

    framework: Framework = Field(
        default=Framework.AUTO,
        description="The agent framework. AUTO = AgentScan detects it.",
    )

    auth_header: str | None = Field(
        default=None,
        description="Full auth header value. e.g. 'Bearer sk-proj-...'",
    )

    system_prompt: str | None = Field(
        default=None,
        description="Known system prompt. Used to verify extraction attacks.",
    )

    timeout: int = Field(
        default=30,
        ge=1,
        le=300,
        description="HTTP timeout in seconds.",
    )

    mode: ScanMode = Field(
        default=ScanMode.SCAN,
        description="Scan mode. SCAN=passive, EXPLOIT=active, DEEP=neural.",
    )

    extra_headers: dict[str, str] = Field(
        default_factory=dict,
        description="Additional HTTP headers to send with every request.",
    )

    @field_validator("url")
    @classmethod
    def url_must_be_http(cls, v: str) -> str:
        if not v.startswith(("http://", "https://")):
            raise ValueError(f"URL must start with http:// or https://. Got: {v!r}")
        return v.rstrip("/")  # normalise — remove trailing slash

    model_config = {"frozen": False}  # allow mutation after creation


# ── Finding ───────────────────────────────────────────────────────────────────


class Finding(BaseModel):
    """
    A single vulnerability discovered by an attack module.
    Immutable after creation — use model_copy() if you need a modified version.
    """

    attack_id: str = Field(
        ...,
        description="Attack module ID. e.g. 'ATK-001'",
        pattern=r"^ATK-[A-Z0-9\-]+$",
    )

    attack_name: str = Field(
        ...,
        min_length=3,
        description="Human-readable attack name.",
    )

    severity: Severity = Field(
        ...,
        description="Severity level of this finding.",
    )

    owasp_id: str = Field(
        ...,
        description="OWASP LLM Top 10 ID. e.g. 'LLM01'",
        pattern=r"^LLM\d{2}$",
    )

    description: str = Field(
        ...,
        min_length=10,
        description="Clear explanation of what was found and why it matters.",
    )

    evidence: str = Field(
        default="",
        description="Captured response fragment or HTTP log proving the finding.",
    )

    remediation: str = Field(
        default="",
        description="Specific steps to fix this vulnerability.",
    )

    payload_used: str | None = Field(
        default=None,
        description="The exact payload that triggered this finding.",
    )

    turn_number: int | None = Field(
        default=None,
        ge=1,
        description="For multi-turn attacks: which turn triggered the finding.",
    )

    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="When this finding was created (UTC).",
    )

    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Extra data specific to the attack module.",
    )

    @field_validator("description")
    @classmethod
    def description_not_generic(cls, v: str) -> str:
        generic = ["test", "finding", "vulnerability"]
        if v.lower().strip() in generic:
            raise ValueError(
                f"Description is too generic: {v!r}. "
                "Write a specific description of what was found."
            )
        return v

    model_config = {"frozen": True}  # findings are immutable


# ── ScanReport ────────────────────────────────────────────────────────────────


class ScanReport(BaseModel):
    """
    The complete output of a scan. Contains all findings and metadata.
    This is what gets serialised to JSON and rendered as HTML/PDF.
    """

    scan_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique identifier for this scan.",
    )

    target_url: str = Field(
        ...,
        description="The URL that was scanned.",
    )

    scan_mode: ScanMode = Field(
        ...,
        description="Which mode was used for this scan.",
    )

    framework: Framework = Field(
        default=Framework.UNKNOWN,
        description="Detected or specified agent framework.",
    )

    started_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
    )

    completed_at: datetime | None = Field(
        default=None,
        description="Set when the scan finishes.",
    )

    findings: list[Finding] = Field(
        default_factory=list,
        description="All findings from this scan.",
    )

    agentscan_version: str = Field(
        default="0.1.0",
        description="Version of AgentScan that produced this report.",
    )

    score: int | None = Field(
        default=None,
        ge=0,
        le=100,
        description="AgentScan Score (0-100). None until scoring is complete.",
    )

    # ── Computed properties ───────────────────────────────────────────────────

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @property
    def passed_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.PASS)

    @property
    def total_tests(self) -> int:
        return len(self.findings)

    @property
    def is_complete(self) -> bool:
        return self.completed_at is not None

    @property
    def duration_seconds(self) -> float | None:
        if self.completed_at is None:
            return None
        return (self.completed_at - self.started_at).total_seconds()

    # ── Methods ───────────────────────────────────────────────────────────────

    def add_finding(self, finding: Finding) -> None:
        """Add a finding to this report."""
        self.findings.append(finding)

    def complete(self, score: int) -> None:
        """Mark this scan as complete with a final score."""
        self.completed_at = datetime.now(UTC)
        self.score = score

    def findings_by_severity(self, severity: Severity) -> list[Finding]:
        """Return all findings with the given severity."""
        return [f for f in self.findings if f.severity == severity]

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a plain dict (for JSON output)."""
        return self.model_dump(mode="json")

    model_config = {"frozen": False}
