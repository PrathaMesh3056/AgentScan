# tests/test_trajectory_log.py

from __future__ import annotations

import json
from pathlib import Path

from agentscan.core.models import Finding, ScanMode, ScanReport, Severity
from agentscan.core.trace import TrafficRecorder


def test_write_trajectory_log_json(tmp_path: Path) -> None:
    recorder = TrafficRecorder()
    recorder.enabled = True
    recorder.set_module("ATK-013", "Excessive Agency")
    recorder.record("message", "rm -rf /", {"response": "Executed deletion."})
    recorder.record_finding("ATK-013", "CRITICAL", "Autonomous destructive action")

    report = ScanReport(
        target_url="http://agent.example/chat",
        scan_mode=ScanMode.SCAN,
        findings=[
            Finding(
                attack_id="ATK-013",
                attack_name="Excessive Agency",
                severity=Severity.CRITICAL,
                owasp_id="LLM06",
                description="Autonomous destructive action",
                evidence="Executed deletion.",
            )
        ],
    )
    report.complete(0, tests_run=1)

    out_json = tmp_path / "trajectory.json"
    recorder.write_trajectory_log(out_json, report)

    assert out_json.exists()
    data = json.loads(out_json.read_text(encoding="utf-8"))
    assert data["target_url"] == "http://agent.example/chat"
    assert data["total_turns"] == 1
    assert data["trajectories"][0]["module_id"] == "ATK-013"
    assert data["trajectories"][0]["prompt"] == "rm -rf /"
    assert data["trajectories"][0]["response"] == "Executed deletion."
    assert len(data["findings"]) == 1
    assert data["findings"][0]["attack_id"] == "ATK-013"


def test_write_trajectory_log_jsonl(tmp_path: Path) -> None:
    recorder = TrafficRecorder()
    recorder.enabled = True
    recorder.set_module("ATK-001", "Prompt Injection")
    recorder.record("message", "turn 1", {"response": "ok 1"})
    recorder.record("message", "turn 2", {"response": "ok 2"})

    report = ScanReport(
        target_url="http://agent.example/chat",
        scan_mode=ScanMode.SCAN,
        findings=[],
    )
    report.complete(100, tests_run=2)

    out_jsonl = tmp_path / "trajectory.jsonl"
    recorder.write_trajectory_log(out_jsonl, report)

    assert out_jsonl.exists()
    lines = [
        json.loads(line) for line in out_jsonl.read_text(encoding="utf-8").strip().splitlines()
    ]
    assert len(lines) == 2
    assert lines[0]["prompt"] == "turn 1"
    assert lines[1]["prompt"] == "turn 2"
