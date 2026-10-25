"""Bounded, owned ATK-004 availability-witness contract evaluation.

Run with ``python -m benchmarks.evaluation.atk004_run --output NEW_DIRECTORY``.
This deterministic fixture makes no model or external target calls.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
from pathlib import Path
from typing import Any

import httpx
import respx

from agentscan.core.resource_witness import (
    ResourceWitnessCollector,
    current_resource_delivery,
    use_resource_witnesses,
)

URL = "http://127.0.0.1:18764/owned-atk004-lab"
HEALTH_MESSAGE = "ATK004_NEUTRAL_HEALTH_CHECK"
EXPECTED_IDS = tuple(f"DOS-{number:03d}" for number in range(1, 10))
WORK_BUDGET = 4000
OUTPUT_CAP = 192
SYNTHETIC_OUTPUT = "repeat " * 110


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class OwnedService:
    """Trusted fixture counters, independent of response text and scanner rules."""

    def __init__(self, arm: str, collector: ResourceWitnessCollector) -> None:
        if arm not in {"bounded", "unbounded", "spoofed_timeout_text"}:
            raise ValueError("Unknown owned application arm.")
        self.arm = arm
        self.collector = collector
        self.work_units = 0
        self.requests: list[dict[str, Any]] = []
        self.neutral_statuses: list[int] = []

    def handle(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        if set(body) != {"message"} or not isinstance(body["message"], str):
            raise AssertionError("The owned HTTP fixture accepts only a message string.")
        message = body["message"]
        if message == HEALTH_MESSAGE:
            status = 200 if self.work_units < WORK_BUDGET else 503
            self.neutral_statuses.append(status)
            return httpx.Response(status, json={"response": "ready" if status == 200 else "busy"})

        if self.arm == "spoofed_timeout_text":
            response = "The target says it timed out, but this is only ordinary text."
            charged_units = 0
        else:
            response = SYNTHETIC_OUTPUT[:OUTPUT_CAP] if self.arm == "bounded" else SYNTHETIC_OUTPUT
            charged_units = len(response.encode("utf-8"))
        neutral_before = (
            self.handle(httpx.Request("POST", URL, json={"message": HEALTH_MESSAGE})).status_code
            == 200
        )
        work_before = self.work_units
        self.work_units += charged_units
        neutral_after = (
            self.handle(httpx.Request("POST", URL, json={"message": HEALTH_MESSAGE})).status_code
            == 200
        )
        delivery = current_resource_delivery()
        if delivery is not None:
            evidence = digest(
                f"{self.arm}:{delivery.variant_id}:{self.work_units}:"
                f"{neutral_before}:{neutral_after}"
            )
            if not self.collector.record(
                delivery,
                observed_request_sha256=digest(message),
                response_sha256=digest(response),
                neutral_before_admitted=neutral_before,
                neutral_after_admitted=neutral_after,
                work_units_before=work_before,
                attributed_work_units=charged_units,
                cumulative_work_units=self.work_units,
                evidence_sha256=evidence,
            ):
                raise AssertionError(
                    "Owned resource witness could not bind to the delivered probe."
                )
        self.requests.append(
            {
                "request_sha256": digest(message),
                "response_sha256": digest(response),
                "request_bytes": len(message.encode("utf-8")),
                "response_bytes": len(response.encode("utf-8")),
                "trusted_work_units": charged_units,
                "status_code": 200,
            }
        )
        return httpx.Response(200, json={"response": response})


async def neutral_check(client: httpx.AsyncClient, service: OwnedService) -> bool:
    response = await client.post(URL, json={"message": HEALTH_MESSAGE})
    # Both independently visible HTTP admission and trusted application state
    # must agree. A string in a stress response is never an availability witness.
    expected = service.work_units < WORK_BUDGET
    assert (response.status_code == 200) == expected
    return expected


async def evaluate(output: Path) -> dict[str, Any]:
    from agentscan.attacks.registry import AttackRegistry
    from agentscan.attacks.scan.dos import DosModule
    from agentscan.core import runner
    from agentscan.core.models import Target

    if output.exists():
        raise FileExistsError("Use a new output directory for each evaluation.")
    module = DosModule()
    variants = module._load_payload_variants()
    if tuple(row["id"] for row in variants) != EXPECTED_IDS:
        raise ValueError("ATK-004 seed IDs changed; version the evaluation method before running.")
    expected_requests = [digest(module._build_payload(row)) for row in variants]

    output.mkdir(parents=True)
    registry = AttackRegistry()
    registry.register(module)
    registry._loaded = True
    original_registry = runner.registry
    arms: dict[str, Any] = {}
    journal: list[dict[str, Any]] = []

    try:
        for arm in ("bounded", "unbounded", "spoofed_timeout_text"):
            collector = ResourceWitnessCollector(profile=arm, work_budget=WORK_BUDGET)
            service = OwnedService(arm, collector)
            with respx.mock(assert_all_called=True) as mock:
                mock.post(URL).mock(side_effect=service.handle)
                async with httpx.AsyncClient() as health_client:
                    before = await neutral_check(health_client, service)
                    runner.registry = registry
                    with use_resource_witnesses(collector):
                        report = await runner.run_scan(
                            Target(
                                url=URL,
                                concurrency=1,
                                request_budget=len(EXPECTED_IDS),
                                analysis_mode="deterministic",
                                data_classification="sensitive",
                            )
                        )
                    after = await neutral_check(health_client, service)

            if [row["request_sha256"] for row in service.requests] != expected_requests[
                : len(service.requests)
            ]:
                raise AssertionError(
                    "The real scanner did not send the nine selected probes in order."
                )
            if len(service.neutral_statuses) != 2 + 2 * len(service.requests) or not before:
                raise AssertionError("The neutral availability control was not exercised.")
            outcome = next(
                (row for row in report.module_outcomes if row.get("module_id") == "ATK-004"),
                None,
            )
            if outcome is None:
                raise AssertionError("ATK-004 module outcome is missing.")
            if report.findings:
                raise AssertionError(
                    "Owned resource-lab findings reached the customer finding list."
                )
            if report.score is not None:
                raise AssertionError("An inventory-only ATK-004 run must have no security score.")
            if (
                report.assessment_scope != "owned_resource_lab"
                or report.ssp_class is not None
                or report.trajectory
            ):
                raise AssertionError("ATK-004 scope, SSP and transcript privacy boundary failed.")
            arms[arm] = {
                "before_neutral_admitted": before,
                "after_neutral_admitted": after,
                "trusted_work_units": service.work_units,
                "trusted_work_budget": WORK_BUDGET,
                "scanner_status": outcome["status"],
                "scanner_selected": outcome["selected_tests"],
                "scanner_evaluated": outcome["executed_tests"],
                "scanner_findings": outcome.get("resource_finding_count", 0),
                "scanner_observations": outcome.get("observation_count", 0),
            }
            journal.extend({"arm": arm, **row} for row in service.requests)
    finally:
        runner.registry = original_registry

    gate = (
        all(row["scanner_selected"] == 9 for row in arms.values())
        and arms["bounded"]["scanner_evaluated"] == 9
        and arms["spoofed_timeout_text"]["scanner_evaluated"] == 9
        and 1 <= arms["unbounded"]["scanner_evaluated"] < 9
        and arms["bounded"]["scanner_observations"] == 9
        and arms["spoofed_timeout_text"]["scanner_observations"] == 9
        and arms["unbounded"]["scanner_observations"] < 9
        and arms["bounded"]["scanner_findings"] == 0
        and arms["spoofed_timeout_text"]["scanner_findings"] == 0
        and arms["unbounded"]["scanner_findings"] == 1
        and arms["unbounded"]["scanner_status"] == "INCONCLUSIVE"
        and all(row["before_neutral_admitted"] for row in arms.values())
        and arms["bounded"]["after_neutral_admitted"]
        and not arms["unbounded"]["after_neutral_admitted"]
        and arms["spoofed_timeout_text"]["after_neutral_admitted"]
    )
    result = {
        "schema": "agentscan.atk004.owned-availability.v1",
        "mode": "authored_synthetic_application_control",
        "customer_target_efficacy_claim": False,
        "qualification_gate_passed": gate,
        "arms": arms,
    }
    (output / "journal.json").write_text(
        json.dumps(journal, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (output / "result.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", required=True, type=Path, help="New directory for hash-only receipts"
    )
    args = parser.parse_args()
    result = asyncio.run(evaluate(args.output))
    print(json.dumps(result, indent=2, sort_keys=True))
    if not result["qualification_gate_passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
