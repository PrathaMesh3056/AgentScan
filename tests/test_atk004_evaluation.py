"""Owned ATK-004 availability-witness evaluation controls."""

from __future__ import annotations

import json

import httpx
import pytest

from agentscan.core.resource_witness import (
    ResourceDelivery,
    ResourceWitnessCollector,
    resource_delivery,
    use_resource_witnesses,
)
from benchmarks.evaluation.atk004_run import (
    HEALTH_MESSAGE,
    OwnedService,
    evaluate,
)


def test_target_timeout_words_are_not_an_availability_witness() -> None:
    service = OwnedService(
        "spoofed_timeout_text", ResourceWitnessCollector(profile="spoof", work_budget=4000)
    )
    response = service.handle(
        httpx.Request("POST", "http://owned.test/", json={"message": "ordinary probe"})
    )
    assert "timed out" in response.json()["response"]
    assert service.work_units == 0
    assert service.neutral_statuses == [200, 200]
    assert (
        service.handle(
            httpx.Request("POST", "http://owned.test/", json={"message": HEALTH_MESSAGE})
        ).status_code
        == 200
    )


def test_owned_witness_is_single_use_and_binds_response() -> None:
    collector = ResourceWitnessCollector(profile="owned", work_budget=100)
    digest = "a" * 64
    evidence = "b" * 64
    with use_resource_witnesses(collector), resource_delivery("DOS-001", digest) as delivery:
        assert delivery is not None
        forged = ResourceDelivery("forged", "DOS-001", digest)
        assert not collector.record(
            forged,
            observed_request_sha256=digest,
            response_sha256=digest,
            neutral_before_admitted=True,
            neutral_after_admitted=True,
            work_units_before=0,
            attributed_work_units=10,
            cumulative_work_units=10,
            evidence_sha256=evidence,
        )
        assert not collector.record(
            delivery,
            observed_request_sha256=digest,
            response_sha256=digest,
            neutral_before_admitted=1,  # type: ignore[arg-type]
            neutral_after_admitted=True,
            work_units_before=0,
            attributed_work_units=10,
            cumulative_work_units=10,
            evidence_sha256=evidence,
        )
        assert not collector.record(
            delivery,
            observed_request_sha256="c" * 64,
            response_sha256=digest,
            neutral_before_admitted=True,
            neutral_after_admitted=True,
            work_units_before=0,
            attributed_work_units=10,
            cumulative_work_units=10,
            evidence_sha256=evidence,
        )
        assert not collector.record(
            delivery,
            observed_request_sha256=digest,
            response_sha256=digest,
            neutral_before_admitted=True,
            neutral_after_admitted=True,
            work_units_before=0,
            attributed_work_units=0,
            cumulative_work_units=10,
            evidence_sha256=evidence,
        )
        assert collector.record(
            delivery,
            observed_request_sha256=digest,
            response_sha256=digest,
            neutral_before_admitted=True,
            neutral_after_admitted=True,
            work_units_before=0,
            attributed_work_units=10,
            cumulative_work_units=10,
            evidence_sha256=evidence,
        )
        assert collector.consume(delivery, "c" * 64) is None
        assert collector.consume(delivery, digest) is None


@pytest.mark.asyncio
async def test_owned_control_checks_actual_scanner_and_neutral_admission(tmp_path) -> None:
    result = await evaluate(tmp_path / "owned-run")
    assert result["qualification_gate_passed"] is True
    assert result["customer_target_efficacy_claim"] is False
    bounded = result["arms"]["bounded"]
    unbounded = result["arms"]["unbounded"]
    spoofed = result["arms"]["spoofed_timeout_text"]
    assert bounded["after_neutral_admitted"] is True
    assert unbounded["after_neutral_admitted"] is False
    assert spoofed["after_neutral_admitted"] is True
    assert bounded["scanner_findings"] == 0
    assert unbounded["scanner_findings"] == 1
    assert spoofed["scanner_findings"] == 0
    assert bounded["scanner_evaluated"] == 9
    assert 0 < unbounded["scanner_evaluated"] < 9

    journal = json.loads((tmp_path / "owned-run" / "journal.json").read_text(encoding="utf-8"))
    assert 18 < len(journal) < 27
    assert all("request_sha256" in row and "response_sha256" in row for row in journal)
    assert all("message" not in row and "response" not in row for row in journal)
    assert "repeat repeat" not in (tmp_path / "owned-run" / "journal.json").read_text(
        encoding="utf-8"
    )


@pytest.mark.asyncio
async def test_owned_run_never_overwrites_receipts(tmp_path) -> None:
    output = tmp_path / "owned-run"
    output.mkdir()
    with pytest.raises(FileExistsError):
        await evaluate(output)
