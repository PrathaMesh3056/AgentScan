# agentscan/core/benchmark.py
#
# Discriminating-power benchmark. A "SAFE" verdict is only meaningful if the tool
# also gives a VULNERABLE agent a bad grade. This runs AgentScan against a spread
# of reference agents at KNOWN vulnerability levels and checks the scores rank
# them correctly — turning "trust me" into "here's the proof, repeatably".
#
# The reference agents are deterministic in-process functions (no network, no key).

from __future__ import annotations

from dataclasses import dataclass

from agentscan.core.connectors import CallableConnector, use_connector
from agentscan.core.models import ScanMode, Target
from agentscan.core.runner import run_scan_multi


def _wide_open(payload: str) -> str:
    """No defenses: naively complies by echoing whatever it's told (worst case)."""
    return "Sure! As instructed: " + payload


def _guarded(payload: str) -> str:
    """Strong scope guard: deflects everything to its allowed topic (best case)."""
    return "I can only help with questions about our products and services."


def _partial(payload: str) -> str:
    """Some defenses: falls for roughly half of attacks, resists the rest."""
    return ("Sure! As instructed: " + payload) if (len(payload) % 2 == 0) else _guarded(payload)


# Ordered weakest → strongest, so a correct tool produces ASCENDING scores.
REFERENCE_AGENTS = [
    ("wide-open (no defenses)", _wide_open, "expect LOW score"),
    ("partial (some defenses)", _partial, "expect MEDIUM score"),
    ("guarded (strong scope)", _guarded, "expect HIGH score"),
]


@dataclass
class BenchmarkRow:
    name: str
    expectation: str
    findings: int
    score: int


async def run_benchmark() -> list[BenchmarkRow]:
    """Grade each reference agent and return the rows (weakest → strongest)."""
    rows: list[BenchmarkRow] = []
    for name, agent, expectation in REFERENCE_AGENTS:
        target = Target(url="http://benchmark.local/chat", mode=ScanMode.SCAN)
        with use_connector(CallableConnector(agent)):
            report = await run_scan_multi(target, [ScanMode.SCAN, ScanMode.EXPLOIT])
        rows.append(
            BenchmarkRow(
                name=name,
                expectation=expectation,
                findings=len(report.findings),
                score=report.score or 0,
            )
        )
    return rows


def discriminates(rows: list[BenchmarkRow]) -> bool:
    """
    True if the tool grades correctly: findings strictly DECREASE weakest -> strongest
    (the robust signal), and the guarded agent scores strictly higher than the weakest.

    (Findings-count is the granular signal — the 0-100 Score saturates in the vulnerable
    range, since both a wide-open and a partly-vulnerable agent are legitimately CRITICAL.)
    """
    findings = [r.findings for r in rows]
    descending = all(a > b for a, b in zip(findings, findings[1:], strict=False))
    return descending and rows[-1].score > rows[0].score
