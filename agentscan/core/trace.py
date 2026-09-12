# agentscan/core/trace.py
#
# Traffic recorder for full-visibility scans.
#
# The findings report answers "what's vulnerable?". This answers "what did the
# scanner actually do?" — every payload sent and every reply received, grouped by
# module. It powers `scan --verbose` (live console) and `scan --transcript <file>`
# (a written record). Disabled by default, so normal scans are unaffected.

from __future__ import annotations

import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from rich.console import Console

_console = Console()


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

    def __init__(self) -> None:
        self.enabled = False
        self.live = False
        self.entries: list[TrafficEntry] = []
        self.findings: list[tuple[str, str, str]] = []  # (module_id, severity, description)
        self.llm_calls: list[LLMCall] = []
        self._seq = 0
        self._llm_seq = 0
        self._module = ("?", "?")

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

    def record(self, kind: str, request: str, response: dict[str, Any]) -> None:
        if not self.enabled:
            return
        self._seq += 1
        reply = extract_reply_text(response)
        entry = TrafficEntry(
            seq=self._seq,
            module_id=self._module[0],
            module_name=self._module[1],
            kind=kind,
            request=request,
            response=reply,
            timestamp=datetime.now(UTC).isoformat(),
        )
        self.entries.append(entry)
        if self.live:
            _console.print(
                f"[dim][{entry.seq}][/dim] [yellow]>> payload:[/yellow] {_safe(request.strip()[:400])}"
            )
            _console.print(
                f"[dim][{entry.seq}][/dim] [green]<< reply  :[/green] {_safe(reply.strip()[:400])}"
            )

    def record_finding(self, module_id: str, severity: str, description: str) -> None:
        if not self.enabled:
            return
        self.findings.append((module_id, severity, description))
        if self.live:
            _console.print(f"   [bold red]!! FINDING [{severity}][/bold red] {_safe(description)}")

    def record_llm(self, model: str, messages: list[dict[str, str]], output: str) -> None:
        """Record one attacker/judge LLM call — the input prompts and the raw output."""
        if not self.enabled:
            return
        self._llm_seq += 1
        call = LLMCall(
            seq=self._llm_seq,
            model=model,
            messages=[dict(m) for m in messages],
            output=output,
            timestamp=datetime.now(UTC).isoformat(),
        )
        self.llm_calls.append(call)
        if self.live:
            sys = " ".join(m.get("content", "") for m in messages if m.get("role") == "system")
            role = "attacker" if "red-teamer" in sys else "judge" if "evaluator" in sys else "llm"
            _console.print(
                f"[magenta][LLM {call.seq}] {model} ({role})[/magenta] "
                f"[dim]→[/dim] {_safe(output.strip()[:300])}"
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

    def write_transcript(self, path: Path, report: Any) -> None:
        """Write the full transcript (all traffic + a findings summary) to a file."""
        out: list[str] = [
            "# AgentScan Transcript",
            "",
            f"- Target: {report.target_url}",
            f"- Scan mode: {report.scan_mode}",
            f"- Generated: {datetime.now(UTC).isoformat()}",
            f"- Score: {report.score}/100",
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

        out += ["", "=" * 72, f"FINDINGS ({len(report.findings)})", "=" * 72]
        if report.findings:
            for f in report.findings:
                out.append(f"- {f.attack_id} [{f.severity}] {f.attack_name}: {f.description}")
                if f.evidence:
                    out.append(f"    evidence: {f.evidence}")
        else:
            out.append("(no findings — the target resisted every payload)")

        Path(path).write_text("\n".join(out), encoding="utf-8")

    def write_trajectory_log(self, path: Path, report: Any) -> None:
        """Write structured multi-turn attack execution trajectory as JSON or JSONL."""
        import json

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
        data = {
            "target_url": getattr(report, "target_url", ""),
            "score": getattr(report, "score", None),
            "ssp_class": getattr(getattr(report, "ssp_class", None), "value", None),
            "generated_at": datetime.now(UTC).isoformat(),
            "total_turns": len(self.entries),
            "trajectories": trajectories,
            "findings": [
                {
                    "attack_id": f.attack_id,
                    "severity": f.severity.value
                    if hasattr(f.severity, "value")
                    else str(f.severity),
                    "description": f.description,
                    "evidence": f.evidence,
                }
                for f in getattr(report, "findings", [])
            ],
        }
        ext = Path(path).suffix.lower()
        if ext == ".jsonl":
            with open(path, "w", encoding="utf-8") as fp:
                for t in trajectories:
                    fp.write(json.dumps(t) + "\n")
        else:
            Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")


recorder = TrafficRecorder()
