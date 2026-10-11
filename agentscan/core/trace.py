# agentscan/core/trace.py
#
# Traffic recorder for full-visibility scans.
#
# The findings report answers "what's vulnerable?". This answers "what did the
# scanner actually do?" — every payload sent and every reply received, grouped by
# module. It powers `scan --verbose` (live console) and `scan --transcript <file>`
# (a written record). Disabled by default, so normal scans are unaffected.

from __future__ import annotations

import re
import sys
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from rich.console import Console

from agentscan.core.context import ContextLocal, active_context

_console = Console()

_REDACTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # Bearer tokens
    (re.compile(r"(?i)\b(Bearer\s+)[A-Za-z0-9_\-\.]{10,}"), r"\1[REDACTED]"),
    # OpenAI & generic sk- keys
    (re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}\b"), "[REDACTED]"),
    # Anthropic keys
    (re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b"), "[REDACTED]"),
    # Common JSON / query / header secret fields
    (
        re.compile(
            r'(?i)("?(?:api_key|apikey|secret|password|access_token|refresh_token|auth_token|secret_key)"?\s*[:=]\s*["\']?)[^"\'\s&,;]{6,}(["\']?)'
        ),
        r"\1[REDACTED]\2",
    ),
    # HTTP Authorization header
    (re.compile(r"(?i)(Authorization:\s*)[^\r\n]+"), r"\1[REDACTED]"),
]


def _private_segments(text: str, secret: str) -> list[str | None]:
    """Remove known values and their supported whitespace-separated representation.

    Privacy matching deliberately has no identifier-boundary requirement. Use
    string operations so private values never enter the regular-expression cache.
    Keep replacement markers separate from later short/overlapping values.
    """
    compact_secret = "".join(secret.split())
    if len(secret) < 8 or not compact_secret:
        parts: list[str | None] = []
        for index, part in enumerate(text.split(secret)):
            if index:
                parts.append(None)
            if part:
                parts.append(part)
        return parts
    compact = "".join(text.split())
    found = compact.find(compact_secret)
    if found < 0:
        return [text]
    parts = []
    compact_index = 0
    kept_from = 0
    match_start = 0
    for index, char in enumerate(text):
        if char.isspace():
            continue
        if compact_index == found:
            match_start = index
        if compact_index == found + len(compact_secret) - 1:
            if kept_from < match_start:
                parts.append(text[kept_from:match_start])
            parts.append(None)
            kept_from = index + 1
            found = compact.find(compact_secret, compact_index + 1)
            if found < 0:
                break
        compact_index += 1
    if kept_from < len(text):
        parts.append(text[kept_from:])
    return parts


def redact_sensitive_data(text: str) -> str:
    """
    Redact API keys, tokens, passwords, and authorization headers from text.
    Safe to call with any string; non-matching strings are returned unchanged.
    """
    if not text:
        return text
    result = text
    context = active_context.get()
    if context is not None:
        # Keep inserted markers separate so a later short credential cannot
        # rewrite the marker itself. Splitting avoids caching private values in
        # dynamically compiled regular expressions.
        segments: list[str | None] = []
        for index, initial_segment in enumerate(result.split("[REDACTED]")):
            if index:
                segments.append(None)
            if initial_segment:
                segments.append(initial_segment)
        for secret in sorted(set(context.redaction_secrets), key=len, reverse=True):
            if secret:
                replaced: list[str | None] = []
                for segment in segments:
                    if segment is None:
                        replaced.append(None)
                        continue
                    replaced.extend(_private_segments(segment, secret))
                segments = replaced
        result = "".join("[REDACTED]" if segment is None else segment for segment in segments)
    for pattern, replacement in _REDACTION_PATTERNS:
        result = pattern.sub(replacement, result)
    return result


def _safe(text: str) -> str:
    """
    Make text printable on the current console encoding (e.g. legacy Windows cp1252),
    replacing characters it can't encode. The transcript FILE keeps full UTF-8 — this
    only guards live console printing so a zero-width/emoji payload can't crash the run.
    """
    enc = sys.stdout.encoding or "utf-8"
    return text.encode(enc, "replace").decode(enc, "replace")


_REPLY_KEYS = ("response", "text", "message", "output", "content", "reply", "raw")


def extract_reply_text(resp: dict[str, Any]) -> str:
    """Best-effort human-readable reply text from a connector response dict."""
    for key in _REPLY_KEYS:
        if key in resp:
            return str(resp[key])
    return str(resp)


@dataclass
class TrafficEntry:
    seq: int
    module_id: str
    module_name: str
    kind: str  # "message" | "conversation"
    request: str
    response: str
    timestamp: str


@dataclass
class LLMCall:
    """One call to an attacker/judge LLM: the exact input messages and raw output."""

    seq: int
    model: str
    messages: list[dict[str, str]]  # the input (system + user prompts)
    output: str  # the raw model output (includes any <think> reasoning it emits)
    timestamp: str


class TrafficRecorder:
    """Process-wide singleton (one scan per CLI process). Use the module-level `recorder`."""

    def __init__(self, redact: bool = True) -> None:
        self.enabled = False
        self.live = False
        self.redact = redact
        self.entries: list[TrafficEntry] = []
        self.findings: list[tuple[str, str, str]] = []  # (module_id, severity, description)
        self.llm_calls: list[LLMCall] = []
        self._seq = 0
        self._llm_seq = 0
        self._module_context: ContextVar[tuple[str, str]] = ContextVar(
            "traffic_module", default=("?", "?")
        )

    @property
    def _module(self) -> tuple[str, str]:
        return self._module_context.get()

    @_module.setter
    def _module(self, value: tuple[str, str]) -> None:
        self._module_context.set(value)

    def reset(self) -> None:
        self.entries.clear()
        self.findings.clear()
        self.llm_calls.clear()
        self._seq = 0
        self._llm_seq = 0
        self._module = ("?", "?")

    def set_module(self, module_id: str, module_name: str) -> None:
        self._module = (module_id, module_name)
        if self.live:
            _console.print(f"\n[bold cyan]== {module_id} - {_safe(module_name)} ==[/bold cyan]")

    def record(
        self,
        kind: str,
        request: str,
        response: dict[str, Any],
        redact: bool | None = None,
    ) -> None:
        if not self.enabled:
            return
        self._seq += 1
        do_redact = self.redact if redact is None else redact
        reply = extract_reply_text(response)
        req_text = redact_sensitive_data(request) if do_redact else request
        reply_text = redact_sensitive_data(reply) if do_redact else reply
        entry = TrafficEntry(
            seq=self._seq,
            module_id=self._module[0],
            module_name=self._module[1],
            kind=kind,
            request=req_text,
            response=reply_text,
            timestamp=datetime.now(UTC).isoformat(),
        )
        self.entries.append(entry)
        if self.live:
            _console.print(
                f"[dim][{entry.seq}][/dim] [yellow]>> payload:[/yellow] {_safe(req_text.strip()[:400])}"
            )
            _console.print(
                f"[dim][{entry.seq}][/dim] [green]<< reply  :[/green] {_safe(reply_text.strip()[:400])}"
            )

    def record_finding(
        self,
        module_id: str,
        severity: str,
        description: str,
        redact: bool | None = None,
    ) -> None:
        if not self.enabled:
            return
        do_redact = self.redact if redact is None else redact
        desc = redact_sensitive_data(description) if do_redact else description
        self.findings.append((module_id, severity, desc))
        if self.live:
            _console.print(f"   [bold red]!! FINDING [{severity}][/bold red] {_safe(desc)}")

    def record_llm(
        self,
        model: str,
        messages: list[dict[str, str]],
        output: str,
        redact: bool | None = None,
    ) -> None:
        """Record one attacker/judge LLM call — the input prompts and the raw output."""
        if not self.enabled:
            return
        self._llm_seq += 1
        do_redact = self.redact if redact is None else redact
        if do_redact:
            sanitized_messages = [
                {k: redact_sensitive_data(v) if isinstance(v, str) else v for k, v in m.items()}
                for m in messages
            ]
            sanitized_output = redact_sensitive_data(output)
        else:
            sanitized_messages = [dict(m) for m in messages]
            sanitized_output = output

        call = LLMCall(
            seq=self._llm_seq,
            model=model,
            messages=sanitized_messages,
            output=sanitized_output,
            timestamp=datetime.now(UTC).isoformat(),
        )
        self.llm_calls.append(call)
        if self.live:
            sys = " ".join(
                m.get("content", "") for m in sanitized_messages if m.get("role") == "system"
            )
            role = "attacker" if "red-teamer" in sys else "judge" if "evaluator" in sys else "llm"
            _console.print(
                f"[magenta][LLM {call.seq}] {model} ({role})[/magenta] "
                f"[dim]→[/dim] {_safe(sanitized_output.strip()[:300])}"
            )

    def write_llm_log(self, path: Path) -> None:
        """Write the full LLM interaction log — every prompt in and raw output out."""
        out: list[str] = [
            "# AgentScan — LLM interaction log (attacker / judge)",
            "",
            f"- Generated: {datetime.now(UTC).isoformat()}",
            f"- Model calls: {len(self.llm_calls)}",
            "=" * 72,
        ]
        for c in self.llm_calls:
            out += ["", f"### [{c.seq}] {c.model}   {c.timestamp}"]
            for m in c.messages:
                out += [f"----- INPUT · {m.get('role', '?').upper()} -----", m.get("content", "")]
            out += ["----- OUTPUT · MODEL -----", c.output]
        Path(path).write_text("\n".join(out), encoding="utf-8")

    def write_transcript(self, path: Path, report: Any, redact: bool | None = None) -> None:
        """Write the full transcript (all traffic + a findings summary) to a file."""
        do_redact = self.redact if redact is None else redact
        out: list[str] = [
            "# AgentScan Transcript",
            "",
            f"- Target: {report.target_url}",
            f"- Scan mode: {report.scan_mode}",
            f"- Generated: {datetime.now(UTC).isoformat()}",
            f"- Status: {getattr(report, 'status', 'UNVERIFIED')}",
            f"- Score: {report.score}/100" if report.score is not None else "- Score: unavailable",
            f"- Evaluated tests: {getattr(report, 'tests_run', 0)}/{getattr(report, 'tests_selected', 0)} selected",
            f"- Assessment scope: {getattr(report, 'assessment_scope', 'unverified')}",
            f"- Requests: {len(self.entries)}  |  Findings: {len(report.findings)}",
            "",
            "=" * 72,
            "FULL TRAFFIC — every payload sent and every reply received",
            "=" * 72,
        ]
        current: str | None = None
        for e in self.entries:
            if e.module_id != current:
                current = e.module_id
                out += ["", f"### {e.module_id} — {e.module_name}"]
            out += [
                "",
                f"[{e.seq}] ({e.kind}) {e.timestamp}",
                f"  >> PAYLOAD: {e.request.strip()}",
                f"  << REPLY  : {e.response.strip()}",
            ]

        out += ["", "ASSESSMENT COVERAGE"]
        for outcome in getattr(report, "module_outcomes", []):
            reason = str(outcome.get("reason", ""))
            if do_redact:
                reason = redact_sensitive_data(reason)
            out.append(
                f"- {outcome.get('module_id', '?')}: {outcome.get('status', 'UNVERIFIED')}; "
                f"evaluated {outcome.get('executed_tests', 0)}/{outcome.get('selected_tests', 0)}; {reason}"
            )
        out += ["", "=" * 72, f"FINDINGS ({len(report.findings)})", "=" * 72]
        if report.findings:
            for f in report.findings:
                desc = redact_sensitive_data(f.description) if do_redact else f.description
                out.append(f"- {f.attack_id} [{f.severity}] {f.attack_name}: {desc}")
                if f.evidence:
                    ev = redact_sensitive_data(f.evidence) if do_redact else f.evidence
                    out.append(f"    evidence: {ev}")
        else:
            out.append("(no findings recorded; review evaluated coverage and unavailable criteria)")

        Path(path).write_text("\n".join(out), encoding="utf-8")

    def write_trajectory_log(self, path: Path, report: Any, redact: bool | None = None) -> None:
        """Write structured multi-turn attack execution trajectory as JSON or JSONL."""
        import json

        do_redact = self.redact if redact is None else redact
        trajectories = [
            {
                "seq": entry.seq,
                "module_id": entry.module_id,
                "module_name": entry.module_name,
                "kind": entry.kind,
                "prompt": entry.request,
                "response": entry.response,
                "timestamp": entry.timestamp,
            }
            for entry in self.entries
        ]
        findings_data = []
        for f in getattr(report, "findings", []):
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            desc = redact_sensitive_data(f.description) if do_redact else f.description
            ev = redact_sensitive_data(f.evidence) if (do_redact and f.evidence) else f.evidence
            findings_data.append(
                {
                    "attack_id": f.attack_id,
                    "severity": sev,
                    "description": desc,
                    "evidence": ev,
                }
            )
        data = {
            "target_url": getattr(report, "target_url", ""),
            "score": getattr(report, "score", None),
            "ssp_class": getattr(getattr(report, "ssp_class", None), "value", None),
            "generated_at": datetime.now(UTC).isoformat(),
            "total_turns": len(self.entries),
            "trajectories": trajectories,
            "findings": findings_data,
        }
        ext = Path(path).suffix.lower()
        if ext == ".jsonl":
            with open(path, "w", encoding="utf-8") as fp:
                for t in trajectories:
                    fp.write(json.dumps(t) + "\n")
        else:
            Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")


recorder = ContextLocal("recorder", TrafficRecorder)
