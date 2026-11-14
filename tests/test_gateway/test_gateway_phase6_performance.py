"""Phase 6 tests: benchmark and soak harnesses are runnable and self-checking.

Both tests are marked slow. ``pytest -m "not slow"`` (the CI profile) never
collects them, so the default suite stays fast and independent of host fsync
or scheduler noise.
"""

from __future__ import annotations

import importlib.util
import sys
import tempfile
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

BENCHMARK_DIR = Path(__file__).resolve().parents[2] / "benchmarks" / "runtime_gateway"

pytestmark = pytest.mark.slow


def _load_harness(name: str) -> ModuleType:
    path = BENCHMARK_DIR / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"gateway_harness_{name}", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_benchmark_reports_every_budget_and_verifies_chains() -> None:
    bench = _load_harness("bench_gateway")
    with tempfile.TemporaryDirectory(prefix="agentscan-gw-bench-test-") as temporary:
        report = bench.build_report(
            bench.parse_args(["--samples", "20", "--policy-samples", "200", "--warmup", "5"]),
            Path(temporary),
        )

    results = report["results"]
    assert set(results) == {"policy_decision", "decision_receipt_append", "gateway_overhead"}
    assert results["policy_decision"]["count"] == 200
    assert results["decision_receipt_append"]["count"] == 20
    assert results["gateway_overhead"]["count"] == 20
    for result in results.values():
        assert len(result["raw_ms"]) == result["count"]
        assert result["p50_ms"] <= result["p99_ms"] <= result["max_ms"]
    assert report["verification"]["decision_chain_verified"] is True
    assert report["verification"]["chain_verified"] is True
    assert report["verification"]["receipts"] == 50
    assert report["host"]["python_version"]
    assert report["command"]
    assert report["all_within_budget"] == all(
        result["within_budget"] for result in results.values()
    )


def test_benchmark_budgets_match_the_approved_spec() -> None:
    bench = _load_harness("bench_gateway")
    assert bench.POLICY_P99_BUDGET_MS == 10.0
    assert bench.DECISION_APPEND_P99_BUDGET_MS == 20.0
    assert bench.GATEWAY_OVERHEAD_P99_BUDGET_MS == 40.0


def test_soak_smoke_keeps_the_chain_valid_and_loses_no_receipts() -> None:
    soak = _load_harness("soak_gateway")
    with tempfile.TemporaryDirectory(prefix="agentscan-gw-soak-test-") as temporary:
        report = soak.run_soak(
            duration_seconds=2.0,
            rate_per_second=10.0,
            receipt_dir=Path(temporary),
            verify_every=5,
            memory_every=5,
        )

    assert report["passed"] is True
    assert report["failure_count"] == 0
    assert report["iterations"] >= 10
    assert report["chain"]["verified"] is True
    assert report["chain"]["decisions"] == report["iterations"]
    assert report["chain"]["receipts"] == 2 * report["iterations"]
    assert report["chain"]["all_outcomes_terminal"] is True
    assert report["receipts_lost"] == 0
    assert report["memory"]["within_heap_budget"] is True
    assert report["latency_ms"]["p99"] >= 0.0


def test_soak_rejects_invalid_configuration() -> None:
    soak: Any = _load_harness("soak_gateway")
    with tempfile.TemporaryDirectory(prefix="agentscan-gw-soak-invalid-") as temporary:
        with pytest.raises(ValueError):
            soak.run_soak(duration_seconds=0, rate_per_second=1, receipt_dir=Path(temporary))
        with pytest.raises(ValueError):
            soak.run_soak(duration_seconds=1, rate_per_second=0, receipt_dir=Path(temporary))
