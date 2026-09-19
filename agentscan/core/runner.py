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
from agentscan.core.client import set_global_concurrency_limit
from agentscan.core.connectors import (
    browser_session_active,
    close_browser_session,
    open_browser_session,
)
from agentscan.core.models import Finding, ScanMode, ScanReport, Target
from agentscan.core.scorer import calculate_score
from agentscan.core.ssp_mapper import classify_ssp
from agentscan.core.trace import recorder
from agentscan.core.trajectory import trajectory_recorder


def _attach_trajectory(report: ScanReport) -> None:
    report.trajectory = trajectory_recorder.turns()
    report.ssp_class = classify_ssp(report.trajectory)


async def run_scan(target: Target, *, reset_trajectory: bool = True) -> ScanReport:
    """
    Run a full security scan against the target.

    Discovers all applicable attack modules, runs them concurrently,
    scores findings, and returns a completed ScanReport.
    """
    if reset_trajectory:
        trajectory_recorder.reset()

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
        report.complete(score, tests_run=0)
        _attach_trajectory(report)
        return report

    # 3. Run the modules.
    # Sequential when: traffic recording is on (correct attribution / no interleaving),
    # OR browser mode (a single shared page can't be typed into concurrently).
    # Otherwise run concurrently for speed.
    # Browser mode also opens ONE shared browser for the whole scan (reused by every
    # module) instead of launching Chromium per module.
    own_session = False
    if target.browser is not None and not browser_session_active():
        await open_browser_session(target.browser)
        own_session = True

    sequential = recorder.enabled or target.browser is not None
    if not sequential and getattr(target, "concurrency", None):
        set_global_concurrency_limit(target.concurrency * 2)

    try:
        results: list[list[Finding] | BaseException]
        if sequential:
            results = []
            for m in modules:
                recorder.set_module(m.attack_id, m.attack_name)
                try:
                    res: list[Finding] = await m.run(target)
                except Exception as e:  # noqa: BLE001 - mirror gather(return_exceptions=True)
                    results.append(e)
                else:
                    for f in res:
                        recorder.record_finding(f.attack_id, f.severity.value, f.description)
                    results.append(res)
        else:
            # return_exceptions=True so one broken module doesn't kill the scan
            results = await asyncio.gather(
                *[m.run(target) for m in modules],
                return_exceptions=True,
            )
    finally:
        set_global_concurrency_limit(None)
        if own_session:
            await close_browser_session()

    # 4. Collect findings and compute total_tests_run
    all_findings: list[Finding] = []
    total_tests_run = 0
    module_errors: list[dict[str, str]] = []

    for module, result in zip(modules, results, strict=True):
        if isinstance(result, BaseException):
            # Module raised — log and track error
            err_msg = str(result) or type(result).__name__
            logger.error(f"Module {module.attack_id} ({module.attack_name}) failed: {err_msg}")
            module_errors.append(
                {
                    "module_id": module.attack_id,
                    "module_name": module.attack_name,
                    "error": err_msg,
                }
            )
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
        module_errors=module_errors,
    )

    # 6. Score and complete
    score = calculate_score(all_findings, total_tests_run)
    report.complete(score, tests_run=total_tests_run)

    _attach_trajectory(report)

    logger.info(
        f"Scan complete: {len(all_findings)} findings, "
        f"score {score}/100, {total_tests_run} tests run, "
        f"{len(module_errors)} module errors"
    )

    return report


async def run_scan_multi(target: Target, modes: list[ScanMode]) -> ScanReport:
    """
    Run scans across multiple modes sequentially and merge the results.
    """
    trajectory_recorder.reset()

    all_findings = []
    total_tests_run = 0
    all_errors: list[dict[str, str]] = []

    # Open ONE shared browser for the entire multi-mode scan (SCAN + EXPLOIT + …),
    # so the whole run uses a single Chromium instead of one per mode. run_scan()
    # sees the active session and reuses it rather than opening its own.
    own_session = False
    if target.browser is not None and not browser_session_active():
        await open_browser_session(target.browser)
        own_session = True

    try:
        for m in modes:
            mode_target = target.model_copy(update={"mode": m})
            report = await run_scan(mode_target, reset_trajectory=False)
            all_findings.extend(report.findings)
            total_tests_run += report.tests_run
            all_errors.extend(report.module_errors)
    finally:
        if own_session:
            await close_browser_session()

    # Create merged report. Use the first mode as the primary scan_mode for the report.
    merged_report = ScanReport(
        target_url=target.url,
        scan_mode=modes[0] if modes else target.mode,
        framework=target.framework,
        findings=all_findings,
        module_errors=all_errors,
    )
    score = calculate_score(all_findings, total_tests_run)
    merged_report.complete(score, tests_run=total_tests_run)
    _attach_trajectory(merged_report)
    return merged_report
