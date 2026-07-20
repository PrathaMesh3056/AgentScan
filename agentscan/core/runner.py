# agentscan/core/runner.py
#
# The scan orchestrator. Given a Target, it:
# 1. Discovers applicable attack modules via the registry
# 2. Runs them all concurrently (asyncio.gather)
# 3. Scores the aggregated findings
# 4. Returns a completed ScanReport
#
# Resilience: a module that raises an exception is logged and excluded
# from both findings and total_tests_run — it doesn't crash the scan.

from __future__ import annotations

import asyncio

from loguru import logger

from agentscan.attacks.registry import registry
from agentscan.core.models import ScanReport, Target
from agentscan.core.scorer import calculate_score


async def run_scan(target: Target) -> ScanReport:
    """
    Run a full security scan against the target.

    Discovers all applicable attack modules, runs them concurrently,
    scores the results, and returns a completed ScanReport.
    """
    # 1. Load all attack modules (idempotent — safe to call every time)
    registry.load_all()

    # 2. Get modules applicable to this target
    modules = registry.get_for_target(target)
    logger.info(f"Running {len(modules)} attack modules against {target.url}")

    if not modules:
        logger.warning("No applicable attack modules found for this target.")
        report = ScanReport(
            target_url=target.url,
            scan_mode=target.mode,
            framework=target.framework,
            findings=[],
        )
        score = calculate_score([], 0)
        report.complete(score)
        return report

    # 3. Run all modules concurrently
    # return_exceptions=True so one broken module doesn't kill the scan
    results = await asyncio.gather(
        *[m.run(target) for m in modules],
        return_exceptions=True,
    )

    # 4. Collect findings and compute total_tests_run
    all_findings = []
    total_tests_run = 0

    for module, result in zip(modules, results, strict=True):
        if isinstance(result, BaseException):
            # Module raised — log and exclude from totals
            logger.error(f"Module {module.attack_id} ({module.attack_name}) failed: {result}")
            continue

        # result is list[Finding]
        all_findings.extend(result)
        total_tests_run += module.variant_count()

    # 5. Build report
    report = ScanReport(
        target_url=target.url,
        scan_mode=target.mode,
        framework=target.framework,
        findings=all_findings,
    )

    # 6. Score and complete
    score = calculate_score(all_findings, total_tests_run)
    report.complete(score)

    logger.info(
        f"Scan complete: {len(all_findings)} findings, "
        f"score {score}/100, {total_tests_run} tests run"
    )

    return report
