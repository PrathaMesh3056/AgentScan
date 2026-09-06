# tests/test_benchmark.py
#
# Proves AgentScan's score discriminates: a vulnerable reference agent must score
# worse than a guarded one. Deterministic, no network/key.

import pytest

from agentscan.core.benchmark import discriminates, run_benchmark


@pytest.mark.asyncio
async def test_benchmark_ranks_agents_by_vulnerability() -> None:
    rows = await run_benchmark()

    by_name = {r.name.split(" ")[0]: r for r in rows}  # "wide-open", "partial", "guarded"
    wide_open = by_name["wide-open"]
    guarded = by_name["guarded"]

    # The core claim: the tool actually distinguishes vulnerable from safe.
    assert wide_open.findings > 0
    assert guarded.findings == 0
    assert wide_open.score < guarded.score
    # Findings strictly decrease weakest -> strongest (the granular signal).
    assert wide_open.findings > by_name["partial"].findings > guarded.findings
    assert discriminates(rows)
