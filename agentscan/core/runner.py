"""Execute isolated scans and retain coverage, skips, and operational failures."""

from __future__ import annotations

import asyncio
from typing import Any

from loguru import logger

from agentscan.attacks.base import AttackModule
from agentscan.attacks.registry import registry
from agentscan.core.client import set_global_concurrency_limit
from agentscan.core.connectors import (
    browser_session_active,
    close_browser_session,
    open_browser_session,
)
from agentscan.core.context import active_context, begin_scan_context, target_redaction_secrets
from agentscan.core.language_coverage import MULTILINGUAL_SCOPE, language_coverage
from agentscan.core.models import Finding, ScanMode, ScanReport, Target
from agentscan.core.outcomes import (
    AssessmentInconclusiveError,
    ExecutionLedger,
    ModuleUnavailableError,
    execution_ledger,
)
from agentscan.core.output_witness import CONSUMER_VALIDATION_SCOPES
from agentscan.core.rag_witness import RAG_VALIDATION_SCOPES
from agentscan.core.scorer import calculate_score
from agentscan.core.ssp_mapper import classify_ssp
from agentscan.core.trace import recorder
from agentscan.core.trajectory import trajectory_recorder
from agentscan.telemetry.otel import observe_scan


def _attach_trajectory(report: ScanReport) -> None:
    factuality_policy = any(
        outcome.get("assessment_scope") == "factuality_policy" for outcome in report.module_outcomes
    )
    report.trajectory = [] if factuality_policy else trajectory_recorder.turns()
    # Trajectory turns do not carry module attribution. In mixed scans we
    # cannot separate these unverified agency proposals from assessed turns.
    unassessed_trajectory = any(
        outcome.get("assessment_scope")
        in {
            "agency_proposal_inventory",
            "rag_document_observation",
            "overreliance_response_inventory",
            "factuality_policy",
            "persona_complete_known_reference",
            "multilingual_complete_known_reference",
        }
        | RAG_VALIDATION_SCOPES
        for outcome in report.module_outcomes
    )
    report.ssp_class = (
        None
        if unassessed_trajectory
        or report.assessment_scope in {"mcp_catalog_policy", "agency_proposal_inventory"}
        else classify_ssp(report.trajectory)
    )


def _finish(report: ScanReport) -> ScanReport:
    incomplete = any(o["status"] != "COMPLETE" for o in report.module_outcomes)
    status = "INCONCLUSIVE" if incomplete or report.tests_run == 0 else "COMPLETE"
    if report.tests_run == 0 and any(o["status"] == "ERROR" for o in report.module_outcomes):
        status = "ERROR"
    target_tests = sum(
        int(o.get("executed_tests", 0))
        for o in report.module_outcomes
        if o.get("assessment_scope")
        not in CONSUMER_VALIDATION_SCOPES
        | RAG_VALIDATION_SCOPES
        | {
            "local_reference_model",
            "mcp_catalog_policy",
            "agency_proposal_inventory",
            "rag_document_observation",
            "overreliance_response_inventory",
            "factuality_policy",
        }
    )
    scopes = {
        "local_consumer_validation"
        if outcome.get("assessment_scope") in CONSUMER_VALIDATION_SCOPES
        else "local_reference_model"
        if outcome.get("assessment_scope") == "local_reference_model"
        else "mcp_catalog_policy"
        if outcome.get("assessment_scope") == "mcp_catalog_policy"
        else "agency_proposal_inventory"
        if outcome.get("assessment_scope") == "agency_proposal_inventory"
        else "owned_rag_lab"
        if outcome.get("assessment_scope") in RAG_VALIDATION_SCOPES
        else "rag_document_observation"
        if outcome.get("assessment_scope") == "rag_document_observation"
        else "overreliance_response_inventory"
        if outcome.get("assessment_scope") == "overreliance_response_inventory"
        else "factuality_policy"
        if outcome.get("assessment_scope") == "factuality_policy"
        else "target"
        for outcome in report.module_outcomes
    }
    # Missing/failed selected checks still belong to the assessment's scope.
    # Successful-test counts are a scoring denominator, not a presence test.
    report.assessment_scope = "mixed" if len(scopes) > 1 else next(iter(scopes), "target")
    report.complete(
        None if incomplete or target_tests == 0 else calculate_score(report.findings, target_tests),
        status=status,
    )
    _attach_trajectory(report)
    return report


@observe_scan
async def run_scan(target: Target, *, reset_trajectory: bool = True) -> ScanReport:
    """Run applicable attacks. A clean finding list does not imply full coverage."""
    if reset_trajectory:
        begin_scan_context()
    context = active_context.get()
    if context is not None:
        context.request_budget = target.request_budget
        context.analysis_mode = target.analysis_mode
        context.local_model = target.local_model
        context.external_model = target.external_model
        context.data_classification = target.data_classification
        context.external_keys_from_dotenv = target.external_keys_from_dotenv
        context.redaction_secrets = target_redaction_secrets(target)
    if target.analysis_mode in {"local", "external"}:
        model = target.local_model if target.analysis_mode == "local" else target.external_model
        target = target.model_copy(
            update={
                "attacker_model": target.attacker_model or model,
                "judge_model": target.judge_model or model,
            }
        )
    report = ScanReport(target_url=target.url, scan_mode=target.mode, framework=target.framework)
    if target.factuality_baseline is not None:
        try:
            target = Target.model_validate(target.model_dump(warnings=False))
        except ValueError:
            report.module_outcomes.append(
                {
                    "module_id": "ATK-009",
                    "module_name": "Approved-answer policy",
                    "assessment_scope": "factuality_policy",
                    "status": "INCONCLUSIVE",
                    "selected_tests": 0,
                    "executed_tests": 0,
                    "reason": "Invalid approved-answer profile; no target connection was opened.",
                }
            )
            return _finish(report)
    if target.mcp_inventory_baseline is not None:
        try:
            # model_copy does not run validators. Reject alternate connectors
            # before browser initialization or any target interaction.
            target = Target.model_validate(target.model_dump(warnings=False))
        except ValueError:
            report.module_outcomes.append(
                {
                    "module_id": "ATK-006",
                    "module_name": "MCP catalog policy",
                    "assessment_scope": "mcp_catalog_policy",
                    "status": "INCONCLUSIVE",
                    "selected_tests": 1,
                    "executed_tests": 0,
                    "reason": "Invalid catalog-only target or baseline; no target connection was opened.",
                }
            )
            report.tests_selected = 1
            return _finish(report)
    try:
        registry.load_all()
        modules, selection_errors = registry.select_for_target(target)
    except Exception as exc:
        report.module_errors.append(
            {"module_id": "registry", "module_name": "Discovery", "error": str(exc)}
        )
        report.module_outcomes.append(
            {"module_id": "registry", "status": "ERROR", "selected_tests": 0, "executed_tests": 0}
        )
        return _finish(report)
    for error in selection_errors:
        report.module_errors.append(error)
        report.module_outcomes.append(
            {**error, "status": "ERROR", "selected_tests": 0, "executed_tests": 0}
        )
    for error in registry.load_errors:
        if error.get("mode") != target.mode.value.lower():
            continue
        report.module_errors.append({k: v for k, v in error.items() if k != "mode"})
        report.module_outcomes.append(
            {**error, "status": "SKIPPED", "selected_tests": 0, "executed_tests": 0}
        )
    if not modules:
        return _finish(report)

    async def execute(module: AttackModule) -> tuple[list[Finding], dict[str, Any], list[str]]:
        selected = 0
        ledger = ExecutionLedger()
        token = execution_ledger.set(ledger)
        outcome: dict[str, Any] = {
            "module_id": module.attack_id,
            "module_name": module.attack_name,
            "status": "COMPLETE",
            "selected_tests": selected,
            "executed_tests": 0,
        }
        outcome["assessment_scope"] = getattr(module, "assessment_scope", "target")
        findings: list[Finding] = []
        recorder.set_module(module.attack_id, module.attack_name)
        try:
            selected = module.variant_count()
            outcome["selected_tests"] = selected
            findings = await module.run(target)
            outcome["selected_tests"] = ledger.selected if ledger.selected is not None else selected
            outcome["executed_tests"] = (
                ledger.evaluated
                if ledger.evaluated is not None
                else (0 if ledger.errors or ledger.inconclusive_reasons else selected)
            )
            if ledger.errors:
                outcome["status"] = "ERROR"
            elif ledger.inconclusive_reasons:
                outcome["status"] = "INCONCLUSIVE"
        except AssessmentInconclusiveError as exc:
            outcome["status"] = "INCONCLUSIVE"
            ledger.inconclusive_reasons.append(str(exc))
            outcome["executed_tests"] = ledger.evaluated or 0
        except ModuleUnavailableError as exc:
            outcome["status"] = "SKIPPED"
            ledger.errors.append(str(exc))
        except Exception as exc:
            outcome["status"] = "ERROR"
            ledger.errors.append(str(exc) or type(exc).__name__)
            outcome["executed_tests"] = ledger.evaluated or 0
        finally:
            execution_ledger.reset(token)
        if ledger.assessment_scope is not None:
            outcome["assessment_scope"] = ledger.assessment_scope
        if outcome["assessment_scope"] == MULTILINGUAL_SCOPE:
            if ledger.selected is not None:
                outcome["selected_tests"] = ledger.selected
            outcome["language_outcomes"] = language_coverage(
                {**outcome, "language_outcomes": getattr(module, "language_outcomes", None)}
            )
        for finding in findings:
            recorder.record_finding(finding.attack_id, finding.severity.value, finding.description)
        reasons = ledger.errors + ledger.inconclusive_reasons
        outcome["reason"] = "; ".join(reasons)
        if ledger.observations:
            outcome["observations"] = ledger.observations
            outcome["observation_count"] = len(ledger.observations)
            outcome["reason"] = (
                f"{len(ledger.observations)} output observations recorded. " + outcome["reason"]
            )
        return findings, outcome, reasons

    own_session = False
    try:
        if target.browser is not None and not browser_session_active():
            await open_browser_session(target.browser)
            own_session = True
        sequential = recorder.enabled or target.browser is not None
        set_global_concurrency_limit(target.concurrency * 2 if not sequential else None)
        if sequential:
            results = [await execute(module) for module in modules]
        else:
            tasks = [asyncio.create_task(execute(module)) for module in modules]
            try:
                results = await asyncio.gather(*tasks)
            except BaseException:
                for task in tasks:
                    if not task.done():
                        task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
                raise
        for findings, outcome, errors in results:
            if outcome.get("assessment_scope") == "mcp_catalog_policy":
                outcome["catalog_findings"] = [
                    finding.model_dump(mode="json") for finding in findings
                ]
                outcome["catalog_finding_count"] = len(findings)
                outcome["reason"] = (
                    f"{len(findings)} catalog policy findings; execution and agent compromise unassessed. "
                    + str(outcome.get("reason", ""))
                )
                findings = []
            elif outcome.get("assessment_scope") == "factuality_policy":
                outcome["policy_findings"] = [
                    finding.model_dump(mode="json") for finding in findings
                ]
                outcome["policy_finding_count"] = len(findings)
                outcome["reason"] = (
                    f"{len(findings)} approved-answer deviations; factual truth, causation and "
                    "agent compromise are unassessed. " + str(outcome.get("reason", ""))
                )
            elif outcome.get("assessment_scope") in CONSUMER_VALIDATION_SCOPES:
                outcome["consumer_findings"] = [
                    finding.model_dump(mode="json") for finding in findings
                ]
                outcome["consumer_finding_count"] = len(findings)
                outcome["reason"] = (
                    f"{len(findings)} independently observed local consumer effects. "
                    + str(outcome.get("reason", ""))
                )
            elif outcome.get("assessment_scope") in RAG_VALIDATION_SCOPES:
                outcome["rag_findings"] = [finding.model_dump(mode="json") for finding in findings]
                outcome["rag_finding_count"] = len(findings)
                outcome["reason"] = (
                    f"{len(findings)} owned RAG fixture effects observed; customer impact unassessed. "
                    + str(outcome.get("reason", ""))
                )
            elif outcome.get("assessment_scope") == "local_reference_model":
                report.reference_observations.extend(findings)
            else:
                report.findings.extend(findings)
            report.module_outcomes.append(outcome)
            report.tests_selected += int(outcome["selected_tests"])
            report.tests_run += int(outcome["executed_tests"])
            if errors:
                report.module_errors.append(
                    {
                        "module_id": str(outcome["module_id"]),
                        "module_name": str(outcome["module_name"]),
                        "error": "; ".join(errors),
                    }
                )
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        report.module_errors.append(
            {"module_id": "runner", "module_name": "Scan setup", "error": str(exc)}
        )
        report.module_outcomes.append(
            {
                "module_id": "runner",
                "status": "ERROR",
                "reason": str(exc),
                "selected_tests": 0,
                "executed_tests": 0,
            }
        )
    finally:
        set_global_concurrency_limit(None)
        if own_session:
            try:
                await close_browser_session()
            except Exception as exc:
                report.module_errors.append(
                    {"module_id": "cleanup", "module_name": "Browser cleanup", "error": str(exc)}
                )
                report.module_outcomes.append(
                    {
                        "module_id": "cleanup",
                        "status": "ERROR",
                        "selected_tests": 0,
                        "executed_tests": 0,
                    }
                )
    _finish(report)
    logger.info(
        f"Scan {report.status}: {report.tests_run}/{report.tests_selected} evaluated tests, score={report.score}"
    )
    return report


async def run_scan_multi(target: Target, modes: list[ScanMode]) -> ScanReport:
    """Run several modes in one isolated context and retain all coverage records."""
    begin_scan_context()
    merged = ScanReport(
        target_url=target.url,
        scan_mode=modes[0] if modes else target.mode,
        framework=target.framework,
    )
    if target.factuality_baseline is not None:
        if modes != [ScanMode.SCAN]:
            merged.module_outcomes.append(
                {
                    "module_id": "ATK-009",
                    "module_name": "Approved-answer policy",
                    "assessment_scope": "factuality_policy",
                    "status": "INCONCLUSIVE",
                    "selected_tests": 0,
                    "executed_tests": 0,
                    "reason": "Approved-answer assessment requires SCAN alone; no target connection was opened.",
                }
            )
            return _finish(merged)
        return await run_scan(target, reset_trajectory=False)
    if target.mcp_inventory_baseline is not None:
        # Never enter eager browser setup or additional modes for this profile.
        if modes != [ScanMode.SCAN]:
            merged.module_outcomes.append(
                {
                    "module_id": "ATK-006",
                    "module_name": "MCP catalog policy",
                    "assessment_scope": "mcp_catalog_policy",
                    "status": "INCONCLUSIVE",
                    "selected_tests": 1,
                    "executed_tests": 0,
                    "reason": "Catalog-only assessment requires SCAN mode alone; no target connection was opened.",
                }
            )
            merged.tests_selected = 1
            return _finish(merged)
        return await run_scan(target, reset_trajectory=False)
    own_session = False
    try:
        if modes and target.browser is not None and not browser_session_active():
            await open_browser_session(target.browser)
            own_session = True
        for mode in modes:
            report = await run_scan(
                target.model_copy(update={"mode": mode}), reset_trajectory=False
            )
            merged.findings.extend(report.findings)
            merged.reference_observations.extend(report.reference_observations)
            merged.module_errors.extend(report.module_errors)
            merged.module_outcomes.extend(report.module_outcomes)
            merged.tests_selected += report.tests_selected
            merged.tests_run += report.tests_run
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        merged.module_errors.append(
            {"module_id": "runner", "module_name": "Scan setup", "error": str(exc)}
        )
        merged.module_outcomes.append(
            {
                "module_id": "runner",
                "status": "ERROR",
                "reason": str(exc),
                "selected_tests": 0,
                "executed_tests": 0,
            }
        )
    finally:
        if own_session:
            try:
                await close_browser_session()
            except Exception as exc:
                merged.module_errors.append(
                    {"module_id": "cleanup", "module_name": "Browser cleanup", "error": str(exc)}
                )
                merged.module_outcomes.append(
                    {
                        "module_id": "cleanup",
                        "status": "ERROR",
                        "selected_tests": 0,
                        "executed_tests": 0,
                    }
                )
    return _finish(merged)
