# tests/test_benchmark.py
#
# Proves AgentScan's score discriminates: a vulnerable reference agent must score
# worse than a guarded one. Deterministic, no network/key.

import pytest

from agentscan.core.benchmark import BENCHMARK_SCOPE, discriminates, run_benchmark


@pytest.mark.asyncio
async def test_benchmark_ranks_agents_by_vulnerability() -> None:
    rows = await run_benchmark()

    by_name = {r.name.split(" ")[0]: r for r in rows}  # "wide-open", "partial", "guarded"
    wide_open = by_name["wide-open"]
    guarded = by_name["guarded"]

    # This smoke check measures only fixture canary disclosure, not general safety.
    assert all(row.assessment_scope == BENCHMARK_SCOPE for row in rows)
    assert all(row.assessment_status == "COMPLETE" for row in rows)
    assert all(row.tests_selected == row.tests_evaluated == 3 for row in rows)
    assert [row.findings for row in rows] == [3, 1, 0]
    assert wide_open.findings > 0
    assert guarded.findings == 0
    assert wide_open.score < guarded.score
    # Findings strictly decrease weakest -> strongest (the granular signal).
    assert wide_open.findings > by_name["partial"].findings > guarded.findings
    assert discriminates(rows)


@pytest.mark.asyncio
async def test_missing_canary_criterion_is_unscored_and_does_not_discriminate() -> None:
    rows = await run_benchmark(canary_token=None)
    assert len(rows) == 3
    assert all(row.assessment_status == "INCONCLUSIVE" for row in rows)
    assert all(row.score is None and row.findings == 0 for row in rows)
    assert all(row.tests_selected == 3 and row.tests_evaluated == 0 for row in rows)
    assert all("out of band" in row.reason for row in rows)
    assert not discriminates(rows)


@pytest.mark.asyncio
async def test_benchmark_restores_caller_context_and_does_not_append_private_traffic() -> None:
    from agentscan.core.context import ScanContext, active_context
    from agentscan.core.trace import TrafficRecorder

    traffic = TrafficRecorder()
    traffic.enabled = True
    traffic.record("message", "caller request", {"response": "caller response"})
    previous = list(traffic.entries)
    context = ScanContext(recorder=traffic, redaction_secrets=("caller-private-value",))
    token = active_context.set(context)
    try:
        rows = await run_benchmark()
        assert discriminates(rows)
        assert active_context.get() is context
        assert traffic.entries == previous
        assert traffic.enabled is True
        assert context.redaction_secrets == ("caller-private-value",)
    finally:
        active_context.reset(token)


def test_benchmark_cli_states_its_narrow_synthetic_scope() -> None:
    from typer.testing import CliRunner

    from agentscan.cli import app

    result = CliRunner().invoke(app, ["benchmark"])
    assert result.exit_code == 0
    assert "Synthetic ATK-028 canary disclosure" in result.output
    assert "no independent accuracy claim" in " ".join(result.output.split())
    assert "[PASS]" in result.output


@pytest.mark.asyncio
async def test_benchmark_api_preserves_scope_and_evaluated_coverage() -> None:
    import json

    pytest.importorskip("fastapi")
    from agentscan.ui.routers.telemetry import api_benchmark

    response = await api_benchmark({})
    data = json.loads(response.body)
    assert data["assessment_scope"] == BENCHMARK_SCOPE
    assert data["independent_calibration"] is False
    assert data["discriminates"] is True
    assert all(row["assessment_status"] == "COMPLETE" for row in data["rows"])
    assert all(row["tests_evaluated"] == row["tests_selected"] == 3 for row in data["rows"])
