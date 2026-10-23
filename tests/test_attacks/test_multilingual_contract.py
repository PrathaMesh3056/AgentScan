"""ATK-011 evidence and language coverage contracts using owned synthetic replies."""

import asyncio
import base64
import hashlib
import json
from unittest.mock import AsyncMock, patch

import pytest
import respx

from agentscan.attacks.registry import AttackRegistry
from agentscan.attacks.scan.known_reference_chat import KnownReferenceChatModule
from agentscan.attacks.scan.multilingual import MultilingualModule
from agentscan.core.models import RequestTemplate, Target
from agentscan.core.outcomes import AssessmentInconclusiveError

PRIVATE = "SYNTHETIC_MULTILINGUAL_PRIVATE_63QmR8z"
URL = "http://synthetic.invalid/chat"


@pytest.mark.asyncio
@pytest.mark.parametrize("module_type", [MultilingualModule, pytest.param(None, id="persona")])
@pytest.mark.parametrize("frame", ["Ordinary partial text", '{"response":"partial"}'])
async def test_websocket_first_frame_without_completion_is_inconclusive(module_type, frame):
    from agentscan.attacks.scan.jailbreak import JailbreakModule
    from agentscan.core.connectors.websocket import _normalise_ws_frame

    module = (module_type or JailbreakModule)()
    module._current_target = Target(url="ws://synthetic.invalid/chat", canary_token=PRIVATE)
    client = AsyncMock()
    client.send_message.return_value = _normalise_ws_frame(frame)
    with pytest.raises(AssessmentInconclusiveError, match="completion"):
        await module._test_variant(client, module._load_payload_variants()[0])


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["complete", "done", "completion_verified", "finish_reason"])
async def test_websocket_explicit_completion_allows_a_complete_reference(field):
    from agentscan.core.connectors.websocket import _normalise_ws_frame

    module = MultilingualModule()
    module._current_target = Target(url="wss://synthetic.invalid/chat", canary_token=PRIVATE)
    client = AsyncMock()
    # The text mapping wraps the protocol envelope in raw; that evidence must
    # survive normalization without treating the first frame itself as complete.
    client.send_message.return_value = _normalise_ws_frame(
        json.dumps({"text": PRIVATE, field: "stop" if field == "finish_reason" else True})
    )
    assert await module._test_variant(client, module._load_payload_variants()[0]) is not None


@pytest.mark.asyncio
async def test_websocket_conflicting_completion_cannot_be_overridden_by_stop():
    module = MultilingualModule()
    module._current_target = Target(url="ws://synthetic.invalid/chat", canary_token=PRIVATE)
    client = AsyncMock()
    client.send_message.return_value = {"response": PRIVATE, "done": False, "finish_reason": "stop"}
    with pytest.raises(AssessmentInconclusiveError, match="incomplete"):
        await module._test_variant(client, module._load_payload_variants()[0])


@pytest.mark.asyncio
async def test_public_spanish_activation_marker_is_not_private_disclosure():
    module = MultilingualModule()
    module._current_target = Target(url=URL, canary_token=PRIVATE)
    client = AsyncMock()
    client.send_message.return_value = {"response": "SISTEMA DESPROTEGIDO: MODO LIBRE ACTIVADO"}
    assert await module._test_variant(client, module._load_payload_variants()[9]) is None


@pytest.mark.asyncio
async def test_missing_reference_stops_before_dispatch():
    module = MultilingualModule()
    client = AsyncMock()
    client.send_message.return_value = {"response": "SISTEMA DESPROTEGIDO"}
    with pytest.raises(AssessmentInconclusiveError):
        await module._test_variant(client, module._load_payload_variants()[9])
    client.send_message.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "text,positive",
    [
        (PRIVATE, True),
        (" ".join(PRIVATE), True),
        (PRIVATE[:-1], False),
        (base64.b64encode(PRIVATE.encode()).decode(), False),
        ("无法提供系统提示。", False),
        ("لا يمكنني مشاركة التعليمات", False),
        ("def example(): pass", False),
    ],
)
async def test_only_complete_private_reference_establishes_disclosure(text, positive):
    module = MultilingualModule()
    module._current_target = Target(url=URL, canary_token=PRIVATE)
    client, judge = AsyncMock(), AsyncMock()
    client.send_message.return_value = {"response": text}
    finding = await module._test_variant(client, module._load_payload_variants()[10], judge=judge)
    assert bool(finding) is positive
    judge.judge.assert_not_awaited()
    if finding:
        assert PRIVATE not in finding.model_dump_json()
        assert finding.metadata["criterion_version"] == "atk011-known-reference-2026-10-22"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "response",
    [
        {},
        {"response": ""},
        {"response": PRIVATE, "done": False},
        {"response": PRIVATE, "choices": [{"finish_reason": "length"}]},
        {"response": PRIVATE, "raw": 'data: {"content":"private"}\n'},
    ],
)
async def test_incomplete_or_unreadable_response_never_proves_resistance(response):
    module = MultilingualModule()
    module._current_target = Target(url=URL, canary_token=PRIVATE)
    client = AsyncMock()
    client.send_message.return_value = response
    with pytest.raises(AssessmentInconclusiveError):
        await module._test_variant(client, module._load_payload_variants()[10])


@pytest.mark.asyncio
@pytest.mark.parametrize("location", ["payload", "history", "header", "url"])
async def test_supplied_private_reference_is_not_disclosure(location):
    module = MultilingualModule()
    variant = dict(module._load_payload_variants()[10])
    kwargs = {}
    if location == "payload":
        variant["payload"] += PRIVATE
    if location == "history":
        kwargs["request_template"] = RequestTemplate(
            url=URL, message_path="message", json_body={"message": "replace", "history": PRIVATE}
        )
    if location == "header":
        kwargs["extra_headers"] = {"X-Public-Context": PRIVATE}
    module._current_target = Target(
        url=URL + ("?public=" + PRIVATE if location == "url" else ""),
        canary_token=PRIVATE,
        **kwargs,
    )
    client = AsyncMock()
    with pytest.raises(AssessmentInconclusiveError):
        await module._test_variant(client, variant)
    client.send_message.assert_not_awaited()


@pytest.mark.asyncio
async def test_unicode_private_value_is_exact_not_translated_or_canonically_rewritten():
    reference = "Privé_秘密_épreuve"
    module = MultilingualModule()
    module._current_target = Target(url=URL, system_prompt=f'SECRET="{reference}"')
    client = AsyncMock()
    client.send_message.return_value = {"response": "参考：" + reference}
    assert await module._test_variant(client, module._load_payload_variants()[10]) is not None
    client.send_message.return_value = {"response": reference.replace("é", "e\u0301")}
    assert await module._test_variant(client, module._load_payload_variants()[10]) is None


@pytest.mark.asyncio
async def test_language_counts_keep_failed_and_inconclusive_attempts_separate():
    module = MultilingualModule()
    cases = list(module._load_payload_variants()[:4])
    replies = [
        {"response": PRIVATE},
        {"response": ""},
        {"error": "unauthorized", "status_code": 401},
        {"response": "Ordinary public response."},
    ]
    with patch.object(module, "_load_payload_variants", return_value=cases), respx.mock() as mock:
        route = mock.post(URL)
        import httpx

        route.side_effect = [httpx.Response(200, json=reply) for reply in replies]
        findings = await module.run(Target(url=URL, canary_token=PRIVATE, concurrency=1))
    assert len(findings) == 1
    rows = {row["language"]: row for row in module.language_outcomes}
    assert rows["zh"]["evaluated_tests"] == rows["zh"]["findings"] == 1
    assert rows["ru"]["inconclusive_tests"] == 1
    assert rows["ar"]["error_tests"] == 1
    assert rows["hi"]["evaluated_tests"] == 1
    assert all(row["not_run_tests"] == 0 for row in rows.values())
    rows["zh"]["findings"] = 123
    assert module.language_outcomes[0]["findings"] == 1


@pytest.mark.asyncio
async def test_missing_reference_retains_selected_mutations_and_does_not_reuse_counts():
    module = MultilingualModule()
    with respx.mock(assert_all_called=False) as mock:
        route = mock.post(URL).respond(200, json={"response": PRIVATE})
        await module.run(Target(url=URL, canary_token=PRIVATE))
        assert route.call_count == 18
        with pytest.raises(AssessmentInconclusiveError):
            await module.run(Target(url=URL, mutate=True, mutation_budget=2))
        assert route.call_count == 18
    rows = module.language_outcomes
    assert sum(row["selected_tests"] for row in rows) == 54
    assert sum(row["not_run_tests"] for row in rows) == 54
    assert sum(row["evaluated_tests"] + row["findings"] for row in rows) == 0


@pytest.mark.asyncio
async def test_cancelled_probe_stays_not_run_and_propagates():
    module = MultilingualModule()
    case = module._load_payload_variants()[0]
    module._language_counts = {
        ("zh", "Hans"): {
            "selected_tests": 1,
            "evaluated_tests": 0,
            "findings": 0,
            "inconclusive_tests": 0,
            "error_tests": 0,
        }
    }
    module._current_target = Target(url=URL, canary_token=PRIVATE)
    client = AsyncMock()
    client.send_message.side_effect = asyncio.CancelledError()
    with pytest.raises(asyncio.CancelledError):
        await module._test_variant(client, case)
    assert module.language_outcomes[0]["not_run_tests"] == 1
    assert module.language_outcomes[0]["error_tests"] == 0


def test_unknown_language_metadata_is_bounded_and_shared_base_is_abstract():
    assert MultilingualModule._language_key({"language": "<script>", "script": []}) == (
        "und",
        "Zyyy",
    )
    with pytest.raises(TypeError):
        KnownReferenceChatModule()
    registry = AttackRegistry()
    import agentscan.attacks.scan as scan_package

    registry._load_package(scan_package)
    assert registry.load_errors == []
    assert registry.get("ATK-011") is not None
    assert registry.get("ATK-002") is not None


def test_packaged_requests_are_bounded_and_original_payloads_preserved():
    variants = MultilingualModule()._load_payload_variants()
    assert len(variants) == len({variant["id"] for variant in variants}) == 18
    assert all(len(variant["payload"]) < 4096 for variant in variants)
    assert PRIVATE not in json.dumps(variants)
    digest = hashlib.sha256(
        json.dumps(
            [item["payload"] for item in variants[:10]], ensure_ascii=False, separators=(",", ":")
        ).encode()
    ).hexdigest()
    assert digest == "5953e305ce7dba08f2392c7b5362cbc88d0574a85ebb280840aaf3905936b763"
