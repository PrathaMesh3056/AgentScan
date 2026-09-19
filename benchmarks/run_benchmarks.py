#!/usr/bin/env python3
"""
AgentScan Benchmark Runner.
Executes discriminating-power benchmarks against reference agents and reports performance metrics.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from typing import Any

from rich.console import Console
from rich.table import Table

from agentscan.core.benchmark import discriminates, run_benchmark

console = Console()


async def execute_benchmarks(iterations: int = 1) -> dict[str, Any]:
    all_runs = []
    start_total = time.perf_counter()

    for i in range(iterations):
        t0 = time.perf_counter()
        rows = await run_benchmark()
        elapsed = time.perf_counter() - t0
        passed = discriminates(rows)
        all_runs.append(
            {
                "iteration": i + 1,
                "duration_seconds": round(elapsed, 3),
                "discriminates": passed,
                "rows": [
                    {
                        "name": r.name,
                        "expectation": r.expectation,
                        "findings": r.findings,
                        "score": r.score,
                    }
                    for r in rows
                ],
            }
        )

    total_elapsed = time.perf_counter() - start_total
    all_passed = all(run["discriminates"] for run in all_runs)

    return {
        "iterations": iterations,
        "total_duration_seconds": round(total_elapsed, 3),
        "overall_passed": all_passed,
        "runs": all_runs,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run AgentScan discriminating-power benchmarks.")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format.")
    parser.add_argument("--iterations", type=int, default=1, help="Number of benchmark iterations.")
    args = parser.parse_args()

    results = asyncio.run(execute_benchmarks(iterations=args.iterations))

    if args.json:
        print(json.dumps(results, indent=2))
        return 0 if results["overall_passed"] else 1

    console.print("\n[bold cyan]AgentScan Discriminating-Power Benchmark[/bold cyan]")
    console.print(
        f"Iterations: {results['iterations']} | Total Time: {results['total_duration_seconds']}s\n"
    )

    latest_run = results["runs"][-1]
    table = Table(title="Reference Agent Benchmark Results", show_header=True)
    table.add_column("Agent Profile", style="cyan")
    table.add_column("Expectation", style="dim")
    table.add_column("Findings", justify="right")
    table.add_column("Score", justify="right")

    for row in latest_run["rows"]:
        score_style = "green" if row["score"] >= 80 else "yellow" if row["score"] >= 40 else "red"
        table.add_row(
            row["name"],
            row["expectation"],
            str(row["findings"]),
            f"[{score_style}]{row['score']}/100[/{score_style}]",
        )

    console.print(table)

    if results["overall_passed"]:
        console.print(
            "\n[bold green][PASS] Scanner successfully discriminates between vulnerable and secure agents.[/bold green]\n"
        )
        return 0
    else:
        console.print(
            "\n[bold red][FAIL] Benchmark criteria not met: findings or scores did not rank correctly.[/bold red]\n"
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
