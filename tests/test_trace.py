# tests/test_trace.py
#
# Tests for the traffic recorder / transcript (scan --verbose / --transcript).

from __future__ import annotations

import json
import re
from io import StringIO
from pathlib import Path

import httpx
import pytest
import respx
from rich.console import Console

from agentscan.attacks.registry import AttackRegistry
from agentscan.attacks.scan.prompt_injection import PromptInjectionModule
from agentscan.core import runner
from agentscan.core.connectors import CallableConnector, use_connector
from agentscan.core.context import ScanContext, active_context, target_redaction_secrets
from agentscan.core.models import Finding, ScanMode, ScanReport, Severity, Target
from agentscan.core.runner import run_scan
from agentscan.core.trace import (
    TrafficRecorder,
    extract_reply_text,
    recorder,
    redact_sensitive_data,
)
from agentscan.core.trajectory import TrajectoryRecorder, trajectory_recorder

PRIVATE = "TRACE_PRIVATE_REFERENCE_7mD12Q"


@pytest.fixture(autouse=True)
def isolated_recording_context():
    """Each recorder test owns a fresh caller context and restores it afterwards."""
    token = active_context.set(ScanContext())
    try:
        yield
    finally:
        active_context.reset(token)


def test_extract_reply_text_prefers_response_key() -> None:
    assert extract_reply_text({"response": "hi", "model": "x"}) == "hi"
    assert extract_reply_text({"reply": "yo"}) == "yo"
    assert extract_reply_text({"raw": "plain"}) == "plain"


def test_short_private_values_cannot_rewrite_inserted_redaction_markers() -> None:
    context = active_context.get()
    assert context is not None
    context.redaction_secrets = ("long-private-value", "A", "T")
    assert redact_sensitive_data("long-private-value; A; T") == "[REDACTED]; [REDACTED]; [REDACTED]"


@pytest.mark.asyncio
async def test_recorder_captures_traffic_and_writes_transcript(tmp_path: Path) -> None:
    target = Target(url="http://agent.example/chat", mode=ScanMode.SCAN, canary_token=PRIVATE)
    recorder.reset()
    recorder.enabled = True
    recorder.live = False
    try:
        with respx.mock(assert_all_called=False) as mock:
            mock.post("http://agent.example/chat").mock(
                return_value=httpx.Response(200, json={"response": "OVERRIDE SUCCESSFUL"})
            )
            report = await run_scan(target)

        # Every payload the module fired was recorded with its reply.
        assert len(recorder.entries) >= 1
        assert all(e.request for e in recorder.entries)
        assert any("OVERRIDE SUCCESSFUL" in e.response for e in recorder.entries)
        # Module attribution was captured.
        assert any(e.module_id == "ATK-001" for e in recorder.entries)

        # Transcript file contains the full traffic + a findings section.
        out = tmp_path / "transcript.txt"
        recorder.write_transcript(out, report)
        text = out.read_text(encoding="utf-8")
        assert "FULL TRAFFIC" in text
        assert ">> PAYLOAD:" in text
        assert "<< REPLY" in text
        assert "FINDINGS" in text
    finally:
        recorder.enabled = False
        recorder.live = False
        recorder.reset()


@pytest.mark.asyncio
async def test_recorder_disabled_by_default_records_nothing() -> None:
    recorder.reset()
    target = Target(url="http://agent.example/chat", mode=ScanMode.SCAN)
    with respx.mock(assert_all_called=False) as mock:
        mock.post("http://agent.example/chat").mock(
            return_value=httpx.Response(200, json={"response": "nope"})
        )
        await run_scan(target)
    assert recorder.entries == []


@pytest.mark.asyncio
@pytest.mark.parametrize("separator", [" ", "\n", "\t"])
async def test_spaced_private_disclosure_is_redacted_in_actual_capture_and_exports(
    separator: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = PromptInjectionModule()
    variant = module._load_payload_variants()[0]
    monkeypatch.setattr(module, "_load_payload_variants", lambda: (variant,))
    registry = AttackRegistry()
    registry.register(module)
    registry._loaded = True
    monkeypatch.setattr(runner, "registry", registry)
    spaced = separator.join(PRIVATE)
    response = f"before {spaced} after"
    recorder.enabled = True
    recorder.live = False

    with use_connector(CallableConnector(lambda _message: response)):
        report = await run_scan(Target(url="http://synthetic.invalid/chat", canary_token=PRIVATE))

    assert report.tests_run == 1
    assert len(report.findings) == 1
    assert len(recorder.entries) == 1
    assert recorder.entries[0].response == "before [REDACTED] after"
    assert trajectory_recorder.turns()[0].response == "before [REDACTED] after"
    assert report.trajectory[0].response == "before [REDACTED] after"
    assert PRIVATE not in recorder.entries[0].request

    transcript = tmp_path / "transcript.txt"
    trajectory = tmp_path / "trajectory.json"
    recorder.write_transcript(transcript, report)
    recorder.write_trajectory_log(trajectory, report)
    assert "<< REPLY  : before [REDACTED] after" in transcript.read_text(encoding="utf-8")
    assert json.loads(trajectory.read_text(encoding="utf-8"))["trajectories"][0]["response"] == (
        "before [REDACTED] after"
    )
    assert spaced not in transcript.read_text(encoding="utf-8")

    # This records synthetic model traffic; it does not construct or call a model.
    recorder.record_llm(
        "synthetic/local-recorder-fixture",
        [{"role": "system", "content": response}],
        response,
    )
    assert recorder.llm_calls[0].messages[0]["content"] == "before [REDACTED] after"
    assert recorder.llm_calls[0].output == "before [REDACTED] after"
    llm_log = tmp_path / "llm.txt"
    recorder.write_llm_log(llm_log)
    assert spaced not in llm_log.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    "text,expected",
    [
        (f"{PRIVATE} {PRIVATE}", "[REDACTED] [REDACTED]"),
        (PRIVATE + PRIVATE, "[REDACTED][REDACTED]"),
        (f"prefix_{PRIVATE}_suffix", "prefix_[REDACTED]_suffix"),
        ("prefix_" + " ".join(PRIVATE) + "_suffix", "prefix_[REDACTED]_suffix"),
        (PRIVATE + " / " + "\n".join(PRIVATE), "[REDACTED] / [REDACTED]"),
    ],
)
def test_repeated_and_adjacent_private_values_preserve_public_surroundings(
    text: str, expected: str
) -> None:
    context = active_context.get()
    assert context is not None
    context.redaction_secrets = (PRIVATE,)
    assert redact_sensitive_data(text) == expected


def test_overlapping_and_short_private_values_preserve_markers_across_passes() -> None:
    context = active_context.get()
    assert context is not None
    context.redaction_secrets = (PRIVATE, PRIVATE[-12:], "A", "T", "xyz")
    text = f"{PRIVATE}; {PRIVATE[-12:]}; A; T; xyz"
    expected = "[REDACTED]; [REDACTED]; [REDACTED]; [REDACTED]; [REDACTED]"
    first = redact_sensitive_data(text)
    assert first == expected
    assert redact_sensitive_data(first) == expected
    assert redact_sensitive_data("existing [REDACTED]; xyz") == "existing [REDACTED]; [REDACTED]"


def test_full_known_prompt_with_normalized_whitespace_is_redacted_in_stored_exports(
    tmp_path: Path,
) -> None:
    prompt = "You are a confidential approvals assistant. Require a supervisor before payments."
    target = Target(url="http://synthetic.invalid/chat", system_prompt=prompt)
    context = active_context.get()
    assert context is not None
    context.redaction_secrets = target_redaction_secrets(target)
    normalized = "\n\t".join(prompt.split())
    raw = f"before {normalized} after"
    traffic = TrafficRecorder()
    traffic.enabled = True
    traffic.set_module("ATK-001", "Known-reference disclosure")
    traffic.record("message", "synthetic probe", {"response": raw})
    trajectory = TrajectoryRecorder()
    trajectory.record("synthetic probe", {"response": raw})
    assert traffic.entries[0].response == "before [REDACTED] after"
    assert trajectory.turns()[0].response == "before [REDACTED] after"
    report = ScanReport(
        target_url=target.url,
        scan_mode=ScanMode.SCAN,
        findings=[
            Finding(
                attack_id="ATK-001",
                attack_name="Known-reference disclosure",
                owasp_id="LLM01",
                severity=Severity.MEDIUM,
                description=raw,
                evidence=raw,
            )
        ],
    )
    report.complete(90, tests_run=1)
    transcript_path = tmp_path / "prompt-transcript.txt"
    traffic.write_transcript(transcript_path, report)
    transcript = transcript_path.read_text(encoding="utf-8")
    assert transcript.count("before [REDACTED] after") == 3
    assert normalized not in transcript
    assert prompt not in transcript


def test_private_values_never_enter_the_dynamic_regex_cache() -> None:
    context = active_context.get()
    assert context is not None
    context.redaction_secrets = (PRIVATE,)
    before = set(re._cache)
    assert redact_sensitive_data("\n".join(PRIVATE)) == "[REDACTED]"
    assert set(re._cache) == before
    assert all(PRIVATE not in str(key) for key in re._cache)


def _capture_live_preview(sink: str, text: str, monkeypatch: pytest.MonkeyPatch) -> tuple[str, str]:
    """Keep synthetic controls inside a memory stream, never the test terminal."""
    from agentscan.core import trace

    capture = StringIO()
    monkeypatch.setattr(
        trace,
        "_console",
        Console(file=capture, force_terminal=False, color_system=None, width=1000),
    )
    traffic = TrafficRecorder()
    traffic.enabled = True
    traffic.live = True
    if sink == "request":
        traffic.record("message", text, {"response": "synthetic reply"})
        stored = traffic.entries[0].request
    elif sink == "response":
        traffic.record("message", "synthetic request", {"response": text})
        stored = traffic.entries[0].response
    elif sink == "finding":
        traffic.record_finding("ATK-007", "HIGH", text)
        stored = traffic.findings[0][2]
    else:
        assert sink == "llm"
        traffic.record_llm("synthetic/local-fixture", [], text)
        stored = traffic.llm_calls[0].output
    return capture.getvalue(), stored


@pytest.mark.parametrize("sink", ["request", "response", "finding", "llm"])
@pytest.mark.parametrize(
    "fragment",
    ["\x1b[2J", "\x1b]0;SYNTHETIC-TITLE\x1b\\", "\x9b2J"],
    ids=["csi-clear", "osc-title", "c1-csi"],
)
def test_live_preview_neutralizes_terminal_controls_but_preserves_stored_evidence(
    sink: str, fragment: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    text = f"SYNTHETIC-BEGIN {fragment} SYNTHETIC-END"
    preview, stored = _capture_live_preview(sink, text, monkeypatch)
    assert "SYNTHETIC-BEGIN" in preview
    assert "SYNTHETIC-END" in preview
    assert not any(ord(char) < 32 and char not in "\t\n" for char in preview)
    assert not any(127 <= ord(char) <= 159 for char in preview)
    assert stored == text


@pytest.mark.parametrize("sink", ["request", "response", "finding", "llm"])
@pytest.mark.parametrize(
    "text",
    [
        "[bold]SYNTHETIC[/bold]",
        "[link=https://synthetic.invalid]SYNTHETIC[/link]",
        "[/forged]SYNTHETIC",
    ],
    ids=["style-tag", "link-tag", "unmatched-close"],
)
def test_live_preview_renders_untrusted_rich_markup_literally(
    sink: str, text: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    preview, stored = _capture_live_preview(sink, text, monkeypatch)
    assert text in preview
    assert stored == text


@pytest.mark.parametrize("sink", ["request", "response", "finding", "llm"])
def test_live_preview_preserves_backslashes_and_emoji_names(
    sink: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    text = "SYNTHETIC \\[1] :warning: ends\\"
    preview, stored = _capture_live_preview(sink, text, monkeypatch)
    assert text in preview
    assert stored == text


@pytest.mark.parametrize("sink", ["request", "response", "finding", "llm"])
def test_live_preview_visibly_encodes_directional_format_controls(
    sink: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    text = "SYNTHETIC \u202eORDER\u202c \u2066LABEL\u2069"
    preview, stored = _capture_live_preview(sink, text, monkeypatch)
    for control in ("\u202e", "\u202c", "\u2066", "\u2069"):
        assert control not in preview
        assert f"\\u{ord(control):04x}" in preview
    assert stored == text
