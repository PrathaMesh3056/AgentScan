from __future__ import annotations

import json
import socket
from urllib.parse import urlsplit

import httpx
import pytest

from benchmarks.evaluation.fixture import AUTH_TOKEN, MAX_BODY, provisioned_canary, serve
from benchmarks.evaluation.run import evaluate_cases, load_cases, oracle_positive, summarize


@pytest.mark.asyncio
async def test_production_evaluation_does_not_turn_failed_requests_into_clean_results() -> None:
    cases = [case for case in load_cases() if case["split"] == "operational"]
    rows = await evaluate_cases(cases)
    assert len(rows) == 4
    assert all(row["prediction"] is None for row in rows)
    assert all(row["assessment_status"] == "ERROR" for row in rows)
    assert all(row["tests_evaluated"] == 0 for row in rows)
    assert all(row["module_errors"] for row in rows)
    metrics = summarize(rows)["operational"]
    assert metrics["unknown"] == metrics["total"] == 4
    assert metrics["tn"] == metrics["fn"] == 0


@pytest.mark.asyncio
async def test_authenticated_stateful_canary_is_provisioned_out_of_band() -> None:
    cases = [case for case in load_cases() if case["id"] in {"CAN-H-02", "CAN-H-03", "CAN-H-04"}]
    rows = await evaluate_cases(cases)
    for row in rows:
        assert row["prediction"] is row["label"]
        assert row["tests_evaluated"] == row["tests_selected"] == 3
        assert row["requests_observed"] == 9
        assert all(not receipt["canary_in_request"] for receipt in row["synthetic_http_receipts"])
        assert [receipt["user_turns"] for receipt in row["synthetic_http_receipts"]] == [
            1,
            2,
            3,
        ] * 3


def test_fixture_authentication_prevents_state_changes() -> None:
    case = next(case for case in load_cases() if case["id"] == "EXA-H-03")
    with serve([case]) as (agent, origin), httpx.Client(trust_env=False) as client:
        url = f"{origin}/cases/{case['id']}/chat"
        response = client.post(url, json={"message": "perform cleanup"})
        assert response.status_code == 401
        assert agent.states[case["id"]]["records"] == ["synthetic-record"]
        assert not agent.receipts[case["id"]]
        response = client.post(
            url,
            json={"message": "perform cleanup"},
            headers={"Authorization": "Bearer " + AUTH_TOKEN},
        )
        assert response.status_code == 200
        assert agent.states[case["id"]]["records"] == []
        assert oracle_positive(case, agent.receipts[case["id"]]) is True


def _unauthorized_headers(case_id: str, declared_length: str) -> bytes:
    return (
        f"POST /cases/{case_id}/chat HTTP/1.0\r\n"
        f"Host: localhost\r\nContent-Length: {declared_length}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")


def _bounded_socket_response(wire: socket.socket) -> bytes:
    chunks = []
    total = 0
    while chunk := wire.recv(4096):
        total += len(chunk)
        assert total <= 4096
        chunks.append(chunk)
    return b"".join(chunks)


def test_unauthorized_response_waits_for_bounded_body_without_parsing_or_state_changes() -> None:
    """Early rejection with unread POST bytes can reset a Windows loopback connection."""
    case = next(case for case in load_cases() if case["id"] == "EXA-H-03")
    with serve([case]) as (agent, origin):
        url = urlsplit(origin)
        with socket.create_connection((url.hostname, url.port), timeout=3) as wire:
            wire.sendall(_unauthorized_headers(case["id"], "4"))
            wire.settimeout(0.25)
            with pytest.raises(TimeoutError):
                wire.recv(1)
            # Deliberately invalid JSON: unauthorized bodies must never be parsed.
            wire.sendall(b"xxxx")
            wire.settimeout(3)
            response = _bounded_socket_response(wire)
        assert response.startswith(b"HTTP/1.0 401 ")
        assert json.loads(response.split(b"\r\n\r\n", 1)[1]) == {
            "error": "Synthetic target authentication required"
        }
        assert agent.states[case["id"]]["records"] == ["synthetic-record"]
        assert agent.states[case["id"]]["turns"] == 0
        assert agent.receipts[case["id"]] == []


@pytest.mark.parametrize("declared_length", ["not-an-integer", "-1", str(MAX_BODY + 1)])
def test_unauthorized_invalid_or_oversized_body_length_is_rejected_without_waiting(
    declared_length: str,
) -> None:
    case = next(case for case in load_cases() if case["id"] == "EXA-H-03")
    with serve([case]) as (agent, origin):
        url = urlsplit(origin)
        with socket.create_connection((url.hostname, url.port), timeout=1) as wire:
            wire.sendall(_unauthorized_headers(case["id"], declared_length))
            response = _bounded_socket_response(wire)
        assert response.startswith(b"HTTP/1.0 401 ")
        assert agent.states[case["id"]]["turns"] == 0
        assert agent.receipts[case["id"]] == []


def test_unauthorized_body_at_size_limit_is_drained_without_state_changes() -> None:
    case = next(case for case in load_cases() if case["id"] == "EXA-H-03")
    with serve([case]) as (agent, origin), httpx.Client(trust_env=False) as client:
        response = client.post(f"{origin}/cases/{case['id']}/chat", content=b"x" * MAX_BODY)
        assert response.status_code == 401
        assert agent.states[case["id"]]["records"] == ["synthetic-record"]
        assert agent.states[case["id"]]["turns"] == 0
        assert agent.receipts[case["id"]] == []


def test_unauthorized_incomplete_body_has_a_bounded_read_deadline() -> None:
    case = next(case for case in load_cases() if case["id"] == "EXA-H-03")
    with serve([case]) as (agent, origin):
        url = urlsplit(origin)
        with socket.create_connection((url.hostname, url.port), timeout=3) as wire:
            wire.sendall(_unauthorized_headers(case["id"], "4"))
            # No body follows. The fixture must end its read before our own bound.
            response = _bounded_socket_response(wire)
        assert response.startswith(b"HTTP/1.0 401 ")
        assert agent.states[case["id"]]["turns"] == 0
        assert agent.receipts[case["id"]] == []


def test_fixture_preview_is_not_a_mutation_even_when_function_name_contains_delete() -> None:
    case = next(case for case in load_cases() if case["id"] == "EXA-H-02")
    with serve([case]) as (agent, origin), httpx.Client(trust_env=False) as client:
        response = client.post(
            f"{origin}/cases/{case['id']}/chat",
            json={"message": "preview"},
            headers={"Authorization": "Bearer " + AUTH_TOKEN},
        )
        assert response.status_code == 200
        assert agent.states[case["id"]]["records"] == ["synthetic-record"]
        assert agent.states[case["id"]]["tool_events"] == [
            {"tool": "delete_preview", "executed": True, "removed": 0}
        ]
        assert oracle_positive(case, agent.receipts[case["id"]]) is False


def test_fixture_has_no_detector_dependency_and_canary_is_not_dataset_content() -> None:
    from pathlib import Path

    import benchmarks.evaluation.fixture as fixture

    source = Path(fixture.__file__).read_text(encoding="utf-8")
    assert "from agentscan" not in source
    assert "subprocess" not in source
    for case in load_cases():
        assert provisioned_canary(case["id"]) not in json.dumps(case)
