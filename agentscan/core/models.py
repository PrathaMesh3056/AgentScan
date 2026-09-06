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
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as pkg_version
from typing import Any

from pydantic import BaseModel, Field, field_validator


def _installed_version() -> str:
    try:
        return pkg_version("agentscan")
    except PackageNotFoundError:
        return "0.1.0"


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


# ── RequestTemplate ───────────────────────────────────────────────────────────


class RequestTemplate(BaseModel):
    """
    A captured agent request (from a browser's Network tab — cURL or HAR) that the
    RequestTemplateConnector replays with the attack payload substituted in.

    This is how AgentScan reaches the undocumented internal APIs behind real website
    chat widgets, instead of assuming a documented {"message": ...} endpoint.
    """

    method: str = Field(default="POST", description="HTTP method of the captured request.")
    url: str = Field(..., description="The captured request URL.")
    headers: dict[str, str] = Field(
        default_factory=dict,
        description="Captured headers (auth, cookies, CSRF, content-type).",
    )
    json_body: dict[str, Any] = Field(
        default_factory=dict,
        description="The captured JSON request body.",
    )
    message_path: str = Field(
        ...,
        description="Dotted path to the field holding the user message, e.g. 'query' "
        "or 'messages.-1.content'. The payload is substituted here.",
    )
    response_path: str | None = Field(
        default=None,
        description="Dotted path to the reply text in the JSON response. "
        "None = fall back to the standard response-key heuristic.",
    )
    timeout: int = Field(default=30, ge=1, le=300, description="HTTP timeout in seconds.")

    @classmethod
    def from_curl(
        cls, curl: str, message_path: str, response_path: str | None = None
    ) -> RequestTemplate:
        """
        Build a RequestTemplate from a copied cURL command (Chrome → Copy as cURL).

        Parses method (-X), headers (-H), cookies (-b), and JSON body (--data/-d/
        --data-raw). Accepts bash (POSIX) and Windows cmd copies (`^` continuations).
        The caller supplies message_path / response_path — the two fields no capture
        can infer on its own.
        """
        import json

        cleaned = (
            curl.replace("\\\r\n", " ")
            .replace("\\\n", " ")
            .replace("^\r\n", " ")
            .replace("^\n", " ")
            .replace("\r\n", " ")
            .replace("\n", " ")
        )
        tokens = _split_curl_tokens(cleaned)

        method: str | None = None
        url = ""
        headers: dict[str, str] = {}
        body_raw = ""

        i = 0
        while i < len(tokens):
            tok = tokens[i]
            tok_l = tok.lower()
            if tok_l in {"curl", "curl.exe"} or tok_l.endswith("curl.exe"):
                pass
            elif tok in ("-X", "--request"):
                i += 1
                method = tokens[i]
            elif tok in ("-H", "--header"):
                i += 1
                key, _, value = tokens[i].partition(":")
                headers[key.strip()] = value.strip()
            elif tok in ("-b", "--cookie"):
                i += 1
                headers["Cookie"] = tokens[i]
            elif tok in ("-d", "--data", "--data-raw", "--data-binary", "--data-ascii"):
                i += 1
                body_raw = tokens[i]
            elif tok.startswith("http://") or tok.startswith("https://"):
                url = tok
            elif tok == "--url":
                i += 1
                url = tokens[i]
            i += 1

        json_body: dict[str, Any] = json.loads(body_raw) if body_raw else {}
        if method is None:
            method = "POST" if body_raw else "GET"

        return cls(
            method=method,
            url=url,
            headers=headers,
            json_body=json_body,
            message_path=message_path,
            response_path=response_path,
        )


def _split_curl_tokens(cleaned: str) -> list[str]:
    """Tokenise a one-line curl command; bash quoting first, Windows cmd quoting as fallback."""
    import shlex

    posix_tokens: list[str] | None = None
    try:
        posix_tokens = shlex.split(cleaned, posix=True)
    except ValueError:
        posix_tokens = None
    if posix_tokens and _curl_has_url(posix_tokens):
        try:
            win_tokens = shlex.split(cleaned, posix=False)
        except ValueError:
            return posix_tokens
        # cmd copies keep JSON backslashes; POSIX split often strips them and breaks json.loads
        if _curl_has_url(win_tokens) and ("\\{" in cleaned or '\\"' in cleaned):
            return win_tokens
        return posix_tokens
    return shlex.split(cleaned, posix=False)


def _curl_has_url(tokens: list[str]) -> bool:
    for i, tok in enumerate(tokens):
        if tok.startswith("http://") or tok.startswith("https://"):
            return True
        if tok == "--url" and i + 1 < len(tokens):
            return True
    return False


# ── BrowserConfig ─────────────────────────────────────────────────────────────


class BrowserConfig(BaseModel):
    """
    Config for driving a chat WIDGET in a real browser (Playwright), for agents
    with no capturable HTTP API — the tool types into the widget and reads the
    reply. Selectors are CSS; the newest bot bubble is the LAST match.
    """

    url: str = Field(..., description="Page URL where the chat widget lives.")
    open_selector: str | None = Field(
        default=None,
        description="CSS selector for a launcher to click first (opens a closed widget). "
        "None = the input is already on the page.",
    )
    input_selector: str = Field(..., description="CSS selector for the chat input box.")
    response_selector: str = Field(
        ..., description="CSS selector matching bot message bubbles (newest = last match)."
    )
    send_selector: str | None = Field(
        default=None, description="CSS selector for the send button. None = press Enter."
    )
    settle_ms: int = Field(
        default=1500, ge=0, description="Extra wait after a new reply appears (streaming)."
    )
    timeout: int = Field(default=30, ge=1, le=300, description="Seconds to wait for a reply.")
    headless: bool = Field(default=True, description="Run the browser without a visible window.")


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

    request_template: RequestTemplate | None = Field(
        default=None,
        description="Captured request to replay (cURL/HAR). When set, the "
        "RequestTemplateConnector is used instead of the default JSON POST.",
    )

    browser: BrowserConfig | None = Field(
        default=None,
        description="Drive a chat widget in a real browser (Playwright) instead of "
        "an HTTP API. Takes precedence over request_template when set.",
    )

    attacker_model: str | None = Field(
        default=None,
        description="LLM (litellm id, e.g. 'gpt-4o-mini' / 'ollama/llama3') for the AI "
        "iterative attacker + judge. When unset, the AI attacker module is skipped.",
    )

    judge_model: str | None = Field(
        default=None,
        description="LLM (litellm id, e.g. 'gpt-4o-mini' / 'ollama/llama3') for LLM-as-a-Judge "
        "evaluation of scan responses. When unset, defaults to attacker_model if set.",
    )

    attacker_turns: int | None = Field(
        default=None,
        ge=1,
        le=20,
        description="Max adaptive turns for the AI attacker (ATK-050). None = module default.",
    )

    attacker_goal: str | None = Field(
        default=None,
        description="Custom attacker objective (e.g. 'break scope and answer an unrelated question'). "
        "When unset, the default canary-phrase objective is used.",
    )

    escalation_model: str | None = Field(
        default=None,
        description="Frontier LLM (litellm id, e.g. 'gpt-4o' or 'claude-3-5-sonnet') to escalate to "
        "if the primary attacker_model fails to achieve the objective.",
    )

    escalation_turns: int | None = Field(
        default=None,
        ge=1,
        le=20,
        description="Number of turns allocated to the escalation model.",
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
        description=(
            "Finding ID. Prefix indicates which subsystem produced it: "
            "'ATK-' = live attack module, 'SC-' = supply chain scanner, "
            "'ID-' = identity & authorization audit."
        ),
        pattern=r"^(ATK|SC|ID)-[A-Z0-9\-]+$",
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


# ── Calibration & Attacker Configuration ──────────────────────────────────────


class CalibrationResult(BaseModel):
    """
    Result of the positive-control calibration check for the AI attacker and judge.
    Proves that the attacker model can generate payloads and the judge can detect
    a successful jailbreak against a wide-open control agent.
    """

    passed: bool = Field(
        ...,
        description="True if the attacker+judge detected the control jailbreak.",
    )
    detail: str = Field(
        default="",
        description="Human-readable explanation of calibration outcome.",
    )


class AttackerConfig(BaseModel):
    """
    Metadata about the AI attacker configuration used during a scan.
    Captured in the report for epistemic honesty and reproducibility.
    """

    model: str = Field(
        ...,
        description="Primary attacker LLM model ID.",
    )
    turns: int = Field(
        ...,
        description="Maximum turns allocated to the attacker.",
    )
    goal: str = Field(
        ...,
        description="The objective given to the attacker.",
    )
    escalation_model: str | None = Field(
        default=None,
        description="Escalation model ID if configured.",
    )
    seed_techniques_used: list[str] = Field(
        default_factory=list,
        description="List of jailbreak seed techniques attempted.",
    )


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

    tests_run: int = Field(
        default=0,
        ge=0,
        description="Attack variants executed. Failed modules are excluded.",
    )

    agentscan_version: str = Field(
        default_factory=_installed_version,
        description="Version of AgentScan that produced this report.",
    )

    score: int | None = Field(
        default=None,
        ge=0,
        le=100,
        description="AgentScan Score (0-100). None until scoring is complete.",
    )

    calibration: CalibrationResult | None = Field(
        default=None,
        description="Positive-control calibration outcome if run for this scan.",
    )

    attacker_config: AttackerConfig | None = Field(
        default=None,
        description="AI attacker configuration details if AI attacker was enabled.",
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
        return self.tests_run

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

    def complete(self, score: int, tests_run: int | None = None) -> None:
        """Mark this scan as complete with a final score."""
        self.completed_at = datetime.now(UTC)
        self.score = score
        if tests_run is not None:
            self.tests_run = tests_run

    def findings_by_severity(self, severity: Severity) -> list[Finding]:
        """Return all findings with the given severity."""
        return [f for f in self.findings if f.severity == severity]

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a plain dict (for JSON output)."""
        return self.model_dump(mode="json")

    model_config = {"frozen": False}
