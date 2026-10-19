"""The approved-answer profile survives service admission without error reflection."""

from __future__ import annotations

import copy
import json
from unittest.mock import AsyncMock

import httpx
import pytest

from agentscan.api import server
from agentscan.api.auth import get_current_tenant
from agentscan.api.data_policy import decrypt_target, encrypt_target


def profile():
    return {
        "schema_version": "agentscan.factuality.v1",
        "target_url": "http://agent.test/chat",
        "cases": [
            {
                "id": "retention",
                "question": "PRIVATE-CLIENT-QUESTION-Q9",
                "expected_answer": "PRIVATE-APPROVED-ANSWER-A9",
                "false_answer": "FALSE-ANSWER-B9",
            }
        ],
    }


@pytest.fixture
async def client(monkeypatch):
    app = server.create_api_app()
    app.dependency_overrides[get_current_tenant] = lambda: "tenant-a"
    monkeypatch.setattr(server, "submit_scan", AsyncMock())
    monkeypatch.setattr(server, "dispatch_outbox", AsyncMock())
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://api.test"
    ) as client:
        yield client


async def test_profile_admitted_and_encrypted_with_all_approved_cases(client):
    body = {"target_url": "http://agent.test/chat", "factuality_baseline": profile()}
    response = await client.post("/scans", json=body)
    assert response.status_code == 202
    target = server.submit_scan.await_args.args[0]["target"]
    assert target["factuality_baseline"] == profile()
    envelope = encrypt_target(target)
    assert "PRIVATE-CLIENT-QUESTION-Q9" not in json.dumps(envelope)
    assert "PRIVATE-APPROVED-ANSWER-A9" not in json.dumps(envelope)
    assert decrypt_target(envelope) == target


@pytest.mark.parametrize(
    "change",
    ["empty", "boolean", "duplicate", "extra", "wrong_target", "mode", "analysis", "document"],
)
async def test_profile_invalid_fields_rejected_before_persistence_without_fact_reflection(
    client, change
):
    baseline = copy.deepcopy(profile())
    body = {"target_url": "http://agent.test/chat", "factuality_baseline": baseline}
    if change == "empty":
        baseline["cases"][0]["question"] = ""
    elif change == "boolean":
        baseline["cases"][0]["expected_answer"] = True
    elif change == "duplicate":
        baseline["cases"].append(copy.deepcopy(baseline["cases"][0]))
    elif change == "extra":
        baseline["cases"][0]["PRIVATE-INPUT-KEY-S9"] = "PRIVATE-INPUT-VALUE-S9"
    elif change == "wrong_target":
        baseline["target_url"] = "http://agent.test/other"
    elif change == "mode":
        body["scan_mode"] = "EXPLOIT"
    elif change == "analysis":
        body.update(analysis_mode="external", data_classification="non_sensitive")
    else:
        body["indirect_adapter"] = "document_v1"
    response = await client.post("/scans", json=body)
    assert response.status_code == 422
    server.submit_scan.assert_not_awaited()
    assert "factuality_baseline" in response.text or "request" in response.text
    for private in (
        "PRIVATE-CLIENT-QUESTION-Q9",
        "PRIVATE-APPROVED-ANSWER-A9",
        "PRIVATE-INPUT-KEY-S9",
        "PRIVATE-INPUT-VALUE-S9",
    ):
        assert private not in response.text


async def test_absent_profile_preserves_existing_admission_payload(client):
    response = await client.post("/scans", json={"target_url": "http://agent.test/chat"})
    assert response.status_code == 202
    assert "factuality_baseline" not in server.submit_scan.await_args.args[0]["target"]


async def test_duplicate_json_fields_do_not_supply_ambiguous_approval(client):
    raw = json.dumps({"target_url": "http://agent.test/chat", "factuality_baseline": profile()})
    raw = raw.replace(
        '"expected_answer":', '"expected_answer":"OTHER-PRIVATE-VALUE", "expected_answer":'
    )
    response = await client.post(
        "/scans", content=raw, headers={"Content-Type": "application/json"}
    )
    assert response.status_code == 422
    server.submit_scan.assert_not_awaited()
    assert "OTHER-PRIVATE-VALUE" not in response.text
