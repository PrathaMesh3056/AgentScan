# benchmarks/test_scan_speed.py
#
# Performance benchmark asserting that the deterministic scan pack completes in <3000ms mean.

from __future__ import annotations

import asyncio
from typing import Any

from agentscan.core.connectors import CallableConnector, use_connector
from agentscan.core.models import ScanMode, Target
from agentscan.core.runner import run_scan

MAX_SCAN_MEAN_SECONDS: float = 3.0


def test_deterministic_scan_pack_speed(benchmark: Any) -> None:
    """
    Asserts that the deterministic scan pack completes in <3000ms mean
    against a local mock target using CallableConnector.
    """

    def mock_agent(_msg: str) -> str:
        return (
            "I am a secure AI agent. I refuse unsafe requests and protect confidential directives."
        )

    target = Target(url="http://mock-speed-test.local/chat", mode=ScanMode.SCAN)

    def _execute_scan() -> None:
        with use_connector(CallableConnector(mock_agent)):
            asyncio.run(run_scan(target))

    # Benchmark the deterministic scan execution
    benchmark.pedantic(_execute_scan, rounds=3, iterations=1)

    mean_sec: float = float(benchmark.stats["mean"])
    mean_ms: float = mean_sec * 1000.0

    assert mean_sec < MAX_SCAN_MEAN_SECONDS, (
        f"Deterministic scan pack mean latency was {mean_ms:.2f}ms, expected < 3000.0ms"
    )
