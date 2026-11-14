#!/usr/bin/env python3
"""Soak harness for the AgentScan runtime gateway.

Repeatedly dispatches the high-risk fake tool through the real
``GatewayRuntime`` with the in-process fake upstream from the latency
benchmark, then verifies that:

- every receipt decision has exactly one terminal outcome (no lost receipts);
- the JSONL chain still verifies from genesis and matches the in-memory head;
- Python-heap growth stays within a documented per-decision bound.

The one-hour run from docs/RUNTIME_GATEWAY.md section 16 is::

    python benchmarks/runtime_gateway/soak_gateway.py --seconds 3600 --rate 2

A shortened smoke run is the same command with ``--seconds 60``. The harness
never opens a socket, reads a credential, or uses real data.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import sys
import time
import tracemalloc
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from bench_gateway import (  # noqa: E402
    TOOL_NAME,
    InProcessUpstream,
    delete_tool,
    host_profile,
    make_bundle,
    make_identity,
    make_session,
    make_settings,
    make_store,
    percentile,
)

from agentscan.gateway.catalog import ToolCatalog  # noqa: E402
from agentscan.gateway.idempotency import (  # noqa: E402
    IdempotencyIndex,
    IdempotencyState,
    pair_receipts,
)
from agentscan.gateway.receipts import ReceiptChainStore, verify_jsonl_file  # noqa: E402
from agentscan.gateway.runtime import GatewayRuntime  # noqa: E402
from agentscan.gateway.server import GatewayRequestContext  # noqa: E402
from agentscan.gateway.sessions import PINNED_PROTOCOL_VERSION  # noqa: E402

# v1 keeps the verified chain and idempotency index in memory, so growth is
# linear in receipts by design. This bound catches a leak beyond that retention.
MAX_HEAP_BYTES_PER_DECISION = 32 * 1024
MAX_HEAP_GROWTH_BYTES = 512 * 1024 * 1024


def _rss_bytes() -> int | None:
    """Best-effort resident set size; returns None when the platform has no probe."""
    try:
        if sys.platform == "win32":
            import ctypes
            from ctypes import wintypes

            class _ProcessMemoryCounters(ctypes.Structure):
                _fields_ = [
                    ("cb", wintypes.DWORD),
                    ("PageFaultCount", wintypes.DWORD),
                    ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t),
                    ("PeakPagefileUsage", ctypes.c_size_t),
                ]

            counters = _ProcessMemoryCounters()
            counters.cb = ctypes.sizeof(counters)
            kernel32: Any = ctypes.WinDLL("kernel32", use_last_error=True)
            psapi: Any = ctypes.WinDLL("psapi", use_last_error=True)
            psapi.GetProcessMemoryInfo.argtypes = [
                wintypes.HANDLE,
                ctypes.POINTER(_ProcessMemoryCounters),
                wintypes.DWORD,
            ]
            psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
            kernel32.GetCurrentProcess.restype = wintypes.HANDLE
            handle = kernel32.GetCurrentProcess()
            if not psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
                return None
            return int(counters.WorkingSetSize)
        import resource

        usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return int(usage) * (1 if sys.platform == "darwin" else 1024)
    except Exception:
        return None


def _chain_state(store: ReceiptChainStore, iterations: int) -> dict[str, Any]:
    verification = store.verify()
    durable = verify_jsonl_file(store.chain_path)
    pairs = pair_receipts(store.receipts)
    terminal = {state.value for state in (IdempotencyState.SUCCESS,)}
    return {
        "verified": (
            verification.head_hash == store.head_hash
            and durable.head_hash == store.head_hash
            and len(durable.receipts) == len(store.receipts)
        ),
        "receipts": len(store.receipts),
        "durable_receipts": len(durable.receipts),
        "decisions": len(pairs),
        "expected_decisions": iterations,
        "all_outcomes_terminal": all(pair.state.value in terminal for pair in pairs),
        "head_hash": store.head_hash,
    }


async def run_soak_async(
    *,
    duration_seconds: float,
    rate_per_second: float,
    receipt_dir: Path,
    verify_every: int = 50,
    memory_every: int = 50,
) -> dict[str, Any]:
    if duration_seconds <= 0 or rate_per_second <= 0:
        raise ValueError("duration and rate must be positive")
    if verify_every < 1 or memory_every < 1:
        raise ValueError("verify_every and memory_every must be positive")

    settings = make_settings(receipt_dir)
    store = make_store(receipt_dir, settings)
    upstream = InProcessUpstream()
    tracemalloc.start()
    heap_samples: list[dict[str, Any]] = []
    latencies_ms: list[float] = []
    chain_checks = 0
    failures: list[str] = []
    iterations = 0
    started_at = datetime.now(UTC)
    started = time.monotonic()
    deadline = started + duration_seconds
    heap_baseline: int | None = None
    heap_baseline_iteration = max(1, int(duration_seconds * rate_per_second * 0.1))
    rss_start = _rss_bytes()
    try:
        catalog = ToolCatalog(settings.upstream_server_id)
        catalog.replace((delete_tool(),))
        runtime = GatewayRuntime(
            settings=settings,
            bundle=make_bundle(),
            store=store,
            index=IdempotencyIndex(),
            upstream=upstream,
            catalog=catalog,
        )
        identity = make_identity()
        session = make_session(identity)
        interval = 1.0 / rate_per_second
        next_at = started
        while time.monotonic() < deadline:
            context = GatewayRequestContext(
                trace_id=f"soak-trace-{iterations}",
                request_id=str(iterations),
                method="tools/call",
                identity=identity,
                session=session,
                protocol_version=PINNED_PROTOCOL_VERSION,
            )
            call_started = time.perf_counter_ns()
            try:
                await runtime.call_tool(
                    context,
                    TOOL_NAME,
                    {"customer_id": f"cust-{iterations % 9000 + 1000:04d}"},
                    meta={"agentscan.idempotency_key": f"soak-key-{iterations}"},
                )
            except Exception as exc:  # noqa: BLE001 - the soak must record, not hide, failures
                failures.append(f"iteration={iterations} error={type(exc).__name__}:{exc}")
            else:
                latencies_ms.append((time.perf_counter_ns() - call_started) / 1_000_000.0)
            iterations += 1

            if iterations % verify_every == 0:
                state = _chain_state(store, iterations)
                chain_checks += 1
                if not state["verified"]:
                    raise RuntimeError("receipt chain failed mid-soak verification")
            if iterations % memory_every == 0:
                current, peak = tracemalloc.get_traced_memory()
                if heap_baseline is None and iterations >= heap_baseline_iteration:
                    heap_baseline = current
                heap_samples.append(
                    {
                        "iteration": iterations,
                        "heap_current_bytes": current,
                        "heap_peak_bytes": peak,
                        "rss_bytes": _rss_bytes(),
                    }
                )
            next_at += interval
            pause = next_at - time.monotonic()
            if pause > 0:
                await asyncio.sleep(pause)

        duration_actual = time.monotonic() - started
        state = _chain_state(store, iterations)
        chain_checks += 1
        current, peak = tracemalloc.get_traced_memory()
        rss_end = _rss_bytes()
        if heap_baseline is None:
            heap_baseline = current
        heap_growth = current - heap_baseline
        bytes_per_decision = heap_growth / iterations if iterations else 0.0
        within_heap_budget = heap_growth <= MAX_HEAP_GROWTH_BYTES and (
            iterations < heap_baseline_iteration
            or bytes_per_decision <= MAX_HEAP_BYTES_PER_DECISION
        )
        receipts_ok = (
            state["verified"]
            and state["decisions"] == iterations
            and state["receipts"] == 2 * iterations
        )
        passed = receipts_ok and not failures and within_heap_budget
        ordered = sorted(latencies_ms)
        return {
            "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "started_at": started_at.isoformat(timespec="seconds"),
            "command": " ".join([sys.executable, *sys.argv]),
            "host": host_profile(),
            "config": {
                "duration_seconds": duration_seconds,
                "rate_per_second": rate_per_second,
                "verify_every": verify_every,
                "memory_every": memory_every,
                "receipt_dir": str(receipt_dir),
                "tool": TOOL_NAME,
            },
            "duration_seconds_actual": round(duration_actual, 3),
            "iterations": iterations,
            "failures": failures[:20],
            "failure_count": len(failures),
            "chain": {**state, "checks": chain_checks},
            "latency_ms": {
                "count": len(ordered),
                "p50": round(percentile(ordered, 0.50), 4),
                "p99": round(percentile(ordered, 0.99), 4),
                "mean": round(statistics.fmean(ordered), 4) if ordered else 0.0,
                "max": round(ordered[-1], 4) if ordered else 0.0,
            },
            "memory": {
                "heap_baseline_bytes": heap_baseline,
                "heap_final_bytes": current,
                "heap_peak_bytes": peak,
                "heap_growth_bytes": heap_growth,
                "heap_bytes_per_decision": round(bytes_per_decision, 1),
                "heap_budget_bytes_per_decision": MAX_HEAP_BYTES_PER_DECISION,
                "heap_growth_budget_bytes": MAX_HEAP_GROWTH_BYTES,
                "within_heap_budget": within_heap_budget,
                "rss_start_bytes": rss_start,
                "rss_end_bytes": rss_end,
                "rss_growth_bytes": (rss_end - rss_start)
                if rss_start is not None and rss_end is not None
                else None,
                "samples": heap_samples,
            },
            "receipts_lost": max(0, 2 * iterations - state["receipts"]),
            "passed": passed,
        }
    finally:
        store.close()
        tracemalloc.stop()


def run_soak(
    *,
    duration_seconds: float,
    rate_per_second: float,
    receipt_dir: Path,
    verify_every: int = 50,
    memory_every: int = 50,
) -> dict[str, Any]:
    return asyncio.run(
        run_soak_async(
            duration_seconds=duration_seconds,
            rate_per_second=rate_per_second,
            receipt_dir=receipt_dir,
            verify_every=verify_every,
            memory_every=memory_every,
        )
    )


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Soak-test the AgentScan runtime gateway.")
    parser.add_argument(
        "--seconds",
        type=float,
        default=3600.0,
        help="soak duration in seconds (full v1 run: 3600)",
    )
    parser.add_argument(
        "--rate",
        type=float,
        default=2.0,
        help="target tool calls per second",
    )
    parser.add_argument(
        "--verify-every", type=int, default=50, help="iterations between chain checks"
    )
    parser.add_argument(
        "--memory-every", type=int, default=50, help="iterations between memory samples"
    )
    parser.add_argument("--out", type=Path, default=None, help="write the JSON report here")
    parser.add_argument(
        "--receipt-dir",
        type=Path,
        required=True,
        help="receipt directory for the soak chain (removed by the caller, not this tool)",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    report = run_soak(
        duration_seconds=args.seconds,
        rate_per_second=args.rate,
        receipt_dir=args.receipt_dir,
        verify_every=args.verify_every,
        memory_every=args.memory_every,
    )
    if args.out is not None:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    chain = report["chain"]
    memory = report["memory"]
    print(f"host: {report['host']['platform']} | Python {report['host']['python_version']}")
    print(
        f"ran {report['iterations']} decisions in {report['duration_seconds_actual']}s "
        f"at {args.rate}/s; failures={report['failure_count']}"
    )
    print(
        f"chain: verified={chain['verified']} receipts={chain['receipts']} "
        f"decisions={chain['decisions']} checks={chain['checks']} "
        f"all_outcomes_terminal={chain['all_outcomes_terminal']}"
    )
    print(
        f"memory: heap_growth={memory['heap_growth_bytes']}B "
        f"({memory['heap_bytes_per_decision']}B/decision, budget "
        f"{memory['heap_budget_bytes_per_decision']}B) rss_growth={memory['rss_growth_bytes']}"
    )
    print(
        f"latency: p50={report['latency_ms']['p50']}ms p99={report['latency_ms']['p99']}ms "
        f"max={report['latency_ms']['max']}ms"
    )
    print(f"overall: {'PASS' if report['passed'] else 'FAIL'}")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
