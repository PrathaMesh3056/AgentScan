"""Offline ATK-027 authored contract evaluation and receipt boundaries."""

from __future__ import annotations

import json

import pytest

from agentscan.attacks.scan.model_theft import ModelTheftModule
from benchmarks.evaluation.atk027_run import REFERENCE, evaluate


@pytest.mark.asyncio
async def test_atk027_authored_controls_use_real_scanner_and_preserve_privacy(tmp_path) -> None:
    from agentscan.core import runner

    original = runner.registry
    output = tmp_path / "owned-control"
    result = await evaluate(output)
    assert runner.registry is original
    assert result["qualification_gate_passed"] is True
    assert result["real_model_efficacy_claim"] is False
    assert result["model_theft_verified"] is False
    arms = result["arms"]
    assert arms["private_reference"]["findings"] == 10
    assert arms["public_information"]["evaluated"] == 10
    assert arms["public_information"]["findings"] == 0
    assert arms["incomplete_reference"]["evaluated"] == 0
    assert arms["missing_reference"]["http_requests"] == 0
    assert arms["public_input_reference"]["http_requests"] == 0
    assert arms["request_budget"]["http_requests"] == 2
    journal_text = (output / "journal.json").read_text(encoding="utf-8")
    result_text = (output / "result.json").read_text(encoding="utf-8")
    assert REFERENCE not in journal_text + result_text
    journal = json.loads(journal_text)
    assert len(journal) == 32
    assert all("request_sha256" in row and "response_sha256" in row for row in journal)
    assert all("message" not in row and "response" not in row for row in journal)


@pytest.mark.asyncio
async def test_atk027_evaluation_never_overwrites_receipts(tmp_path) -> None:
    output = tmp_path / "existing"
    output.mkdir()
    receipt = output / "result.json"
    receipt.write_text("keep", encoding="utf-8")
    with pytest.raises(FileExistsError):
        await evaluate(output)
    assert receipt.read_text(encoding="utf-8") == "keep"


@pytest.mark.asyncio
async def test_atk027_evaluation_rejects_changed_frozen_requests(tmp_path, monkeypatch) -> None:
    from agentscan.core import runner

    original = runner.registry
    variants = ModelTheftModule()._load_payload_variants()
    altered = ({**variants[0], "payload": "Changed evaluation request"}, *variants[1:])
    monkeypatch.setattr(ModelTheftModule, "_load_payload_variants", lambda self: altered)
    with pytest.raises(ValueError, match="Frozen ATK-027 request payloads changed"):
        await evaluate(tmp_path / "changed")
    assert runner.registry is original
    assert not (tmp_path / "changed").exists()
