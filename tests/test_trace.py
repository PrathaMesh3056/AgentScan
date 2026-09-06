# tests/test_trace.py
#
# Tests for the traffic recorder / transcript (scan --verbose / --transcript).

from __future__ import annotations

from pathlib import Path

import httpx
import pytest
import respx

from agentscan.core.models import ScanMode, Target
from agentscan.core.runner import run_scan
from agentscan.core.trace import extract_reply_text, recorder


def test_extract_reply_text_prefers_response_key() -> None:
    assert extract_reply_text({"response": "hi", "model": "x"}) == "hi"
    assert extract_reply_text({"reply": "yo"}) == "yo"
    assert extract_reply_text({"raw": "plain"}) == "plain"


@pytest.mark.asyncio
async def test_recorder_captures_traffic_and_writes_transcript(tmp_path: Path) -> None:
    target = Target(url="http://agent.example/chat", mode=ScanMode.SCAN)
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
