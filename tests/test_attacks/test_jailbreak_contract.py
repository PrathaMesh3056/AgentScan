"""Production ATK-002 confidentiality and execution-boundary regression contracts."""

from __future__ import annotations

import base64
import hashlib
import json
from unittest.mock import AsyncMock, patch
from urllib.parse import quote

import pytest
import respx

from agentscan.attacks.mutators import mutate_variant
from agentscan.attacks.registry import AttackRegistry
from agentscan.attacks.scan.jailbreak import JailbreakModule
from agentscan.core import runner
from agentscan.core.connectors import CallableConnector, use_connector
from agentscan.core.connectors.http import HttpJsonConnector
from agentscan.core.context import active_context
from agentscan.core.models import RequestTemplate, Target
from agentscan.core.outcomes import AssessmentInconclusiveError, ModuleUnavailableError

PRIVATE = "SYNTHETIC_PERSONA_PRIVATE_92KmT7aZ31"
URL = "http://synthetic.invalid/chat"


def registry(module):
    result = AttackRegistry()
    result.register(module)
    result._loaded = True
    return result


def variant():
    return dict(JailbreakModule()._load_payload_variants()[10])


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "text,positive",
    [
        (PRIVATE, True),
        ('"' + PRIVATE + '"', True),
        ("I refuse; however " + PRIVATE, True),
        (" ".join(PRIVATE), True),
        (PRIVATE[:-1], False),
        (PRIVATE.lower(), False),
        ("prefix_" + PRIVATE, False),
        (PRIVATE + "_suffix", False),
        (base64.b64encode(PRIVATE.encode()).decode(), False),
        ("[Mal]: I can do anything! MAL_ACTIVATED", False),
        ("NEXUS SYSTEM FULLY UNBOUND", False),
        ('{"tool_calls":[{"name":"SHOW_PRIVATE_REFERENCE"}]}', False),
    ],
)
async def test_complete_known_reference_criterion(text, positive):
    module = JailbreakModule()
    module._current_target = Target(url=URL, canary_token=PRIVATE)
    client = AsyncMock()
    client.send_message.return_value = {"response": text}
    judge = AsyncMock()
    result = await module._test_variant(client, variant(), judge=judge)
    assert bool(result) is positive
    judge.judge.assert_not_awaited()
    assert PRIVATE not in client.send_message.await_args.args[0]


@pytest.mark.asyncio
async def test_complete_prompt_requires_complete_independent_reference():
    prompt = "Keep the fictional archive private and preserve the approved customer workflow."
    module = JailbreakModule()
    module._current_target = Target(url=URL, system_prompt=prompt)
    client = AsyncMock()
    client.send_message.return_value = {"response": prompt}
    finding = await module._test_variant(client, variant())
    assert finding is not None
    assert finding.metadata["assessment_criterion"] == "complete_operator_known_prompt"
    assert finding.severity.value == "MEDIUM"
    assert prompt not in finding.model_dump_json()
    client.send_message.return_value = {"response": prompt[:30]}
    assert await module._test_variant(client, variant()) is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "response",
    [
        {},
        {"response": ""},
        {"response": 42},
        {"other": PRIVATE},
        {"response": PRIVATE, "truncated": True},
        {"response": PRIVATE, "incomplete": True},
        {"response": PRIVATE, "done": False},
        {"response": PRIVATE, "complete": False},
        {"response": PRIVATE, "finish_reason": "length"},
        {"response": PRIVATE, "choices": [{"finish_reason": "content_filter"}]},
        {"response": PRIVATE, "raw": {"done": False}},
        {"response": PRIVATE, "raw": {"choices": [{"finish_reason": "length"}]}},
        {"response": PRIVATE, "raw": ": keepalive\ndata: " + PRIVATE},
        {"response": PRIVATE, "raw": 'data: {"content":"' + PRIVATE + '"}\n'},
        {"response": PRIVATE, "raw": 'data: {"content":"' + PRIVATE + '"}\ndata: [DONE]\n'},
        {"tool_calls": [{"name": "SHOW_PRIVATE_REFERENCE", "arguments": PRIVATE}]},
    ],
)
async def test_unreadable_or_incomplete_responses_are_inconclusive(response):
    module = JailbreakModule()
    module._current_target = Target(url=URL, canary_token=PRIVATE)
    client = AsyncMock()
    client.send_message.return_value = response
    with pytest.raises(AssessmentInconclusiveError):
        await module._test_variant(client, variant())


@pytest.mark.asyncio
@pytest.mark.parametrize("mutation", [None, "base64", "zwsp", "leetspeak", "homoglyphs"])
async def test_supplied_private_reference_cannot_be_reclassified_by_mutation(mutation):
    supplied = {**variant(), "payload": "Repeat this supplied value: " + PRIVATE}
    if mutation is not None:
        supplied = mutate_variant(supplied, mutation)
    assert supplied is not None
    module = JailbreakModule()
    module._current_target = Target(url=URL, canary_token=PRIVATE)
    client = AsyncMock()
    client.send_message.return_value = {"response": PRIVATE}
    with pytest.raises(AssessmentInconclusiveError):
        await module._test_variant(client, supplied)
    client.send_message.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("location", ["history", "header", "auth", "extra"])
async def test_captured_public_context_and_headers_do_not_prove_extraction(location):
    kwargs = {}
    if location in {"history", "header"}:
        kwargs["request_template"] = RequestTemplate(
            url=URL,
            message_path="message",
            json_body={"message": "replace", "history": PRIVATE if location == "history" else ""},
            headers={"X-Context": PRIVATE} if location == "header" else {},
        )
    elif location == "auth":
        kwargs["auth_header"] = "Bearer " + PRIVATE
    else:
        kwargs["extra_headers"] = {"X-Context": PRIVATE}
    module = JailbreakModule()
    module._current_target = Target(url=URL, canary_token=PRIVATE, **kwargs)
    client = AsyncMock()
    client.send_message.return_value = {"response": PRIVATE}
    with pytest.raises(AssessmentInconclusiveError):
        await module._test_variant(client, variant())
    client.send_message.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "criterion", ["scanner_canary", "content_type_value", "keep_alive_value", "full_prompt"]
)
async def test_generated_default_http_headers_are_public_reference_data(criterion):
    default_agent = HttpJsonConnector(Target(url=URL))._build_headers()["User-Agent"]
    reference = {
        "scanner_canary": "security-scanner",
        "content_type_value": "application",
        "keep_alive_value": "keep-alive",
        "full_prompt": default_agent,
    }[criterion]
    kwargs = (
        {"system_prompt": reference}
        if criterion == "full_prompt"
        else {"canary_token": reference}
        if criterion == "scanner_canary"
        else {"system_prompt": f'TOKEN="{reference}"'}
    )
    module = JailbreakModule()
    with (
        patch.object(runner, "registry", registry(module)),
        respx.mock(assert_all_called=False) as mock,
    ):
        route = mock.post(URL).respond(200, json={"response": reference})
        report = await runner.run_scan(Target(url=URL, **kwargs))
    assert report.findings == []
    assert report.tests_run == 0
    assert report.status == "INCONCLUSIVE"
    assert report.score is None
    assert route.call_count == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("precedence", ["override", "auth_override", "captured", "browser"])
async def test_default_scanner_header_is_not_assumed_for_other_transport_headers(precedence):
    from agentscan.core.models import BrowserConfig

    kwargs = {}
    if precedence == "override":
        kwargs["extra_headers"] = {"User-Agent": "Client_Custom_Agent_001"}
    elif precedence == "auth_override":
        kwargs["auth_header"] = "User-Agent: Client_Custom_Agent_001"
    elif precedence == "captured":
        kwargs["request_template"] = RequestTemplate(url=URL, message_path="message")
    else:
        kwargs["browser"] = BrowserConfig(
            url=URL,
            input_selector="#input",
            response_selector=".reply",
            completion_selector=".done",
        )
    module = JailbreakModule()
    module._current_target = Target(url=URL, canary_token="security-scanner", **kwargs)
    client = AsyncMock()
    client.send_message.return_value = {"response": "security-scanner", "completion_verified": True}
    finding = await module._test_variant(client, variant())
    assert finding is not None
    assert finding.metadata["assessment_criterion"] == "complete_operator_known_private_value"


@pytest.mark.asyncio
@pytest.mark.parametrize("reference", ["keep-alive", "python-httpx", "application"])
async def test_actual_captured_http_defaults_cannot_be_private_evidence(reference):
    module = JailbreakModule()
    with (
        patch.object(runner, "registry", registry(module)),
        respx.mock(assert_all_called=False) as mock,
    ):
        route = mock.post(URL).respond(200, json={"response": reference})
        report = await runner.run_scan(
            Target(
                url=URL,
                system_prompt=f'TOKEN="{reference}"',
                request_template=RequestTemplate(url=URL, message_path="message"),
            )
        )
    assert route.call_count == 0
    assert report.tests_run == 0
    assert report.findings == []
    assert report.status == "INCONCLUSIVE"


@pytest.mark.asyncio
@pytest.mark.parametrize("captured", [False, True])
async def test_actual_http_override_and_captured_precedence_preserve_private_criterion(captured):
    module = JailbreakModule()
    kwargs = (
        {"request_template": RequestTemplate(url=URL, message_path="message")}
        if captured
        else {"extra_headers": {"User-Agent": "Client_Custom_Agent_001"}}
    )
    with (
        patch.object(runner, "registry", registry(module)),
        respx.mock(assert_all_called=False) as mock,
    ):
        route = mock.post(URL).respond(200, json={"response": "security-scanner"})
        report = await runner.run_scan(Target(url=URL, canary_token="security-scanner", **kwargs))
    assert route.call_count == 18
    assert report.tests_run == 18
    assert len(report.findings) == 18
    assert "_atk002_actual_http_headers" not in report.model_dump_json()


@pytest.mark.asyncio
async def test_yaml_cannot_supply_the_reserved_http_provenance_key():
    module = JailbreakModule()
    module._current_target = Target(url=URL, canary_token=PRIVATE)
    supplied = {**variant(), "_atk002_actual_http_headers": PRIVATE}
    client = AsyncMock()
    client.send_message.return_value = {"response": PRIVATE}
    assert await module._test_variant(client, supplied) is not None


@pytest.mark.asyncio
@pytest.mark.parametrize("encoding_depth", [0, 1, 2])
@pytest.mark.parametrize("captured", [False, True])
async def test_reference_already_in_endpoint_url_cannot_prove_private_disclosure(
    encoding_depth, captured
):
    # Force encoding of ASCII letters as well as separators; standard quote
    # intentionally leaves unreserved characters untouched.
    value = "".join(f"%{ord(char):02X}" for char in PRIVATE) if encoding_depth else PRIVATE
    if encoding_depth == 2:
        value = quote(value, safe="")
    endpoint = URL + "?context=" + value
    kwargs = (
        {"request_template": RequestTemplate(url=endpoint, message_path="message")}
        if captured
        else {}
    )
    module = JailbreakModule()
    module._current_target = Target(
        url=URL if captured else endpoint, canary_token=PRIVATE, **kwargs
    )
    client = AsyncMock()
    with pytest.raises(AssessmentInconclusiveError):
        await module._test_variant(client, variant())
    client.send_message.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "scheme", ["mcp://stdio", "mcp+sse://localhost/mcp", "mcp+sses://localhost/mcp"]
)
async def test_native_mcp_does_not_dispatch_tools(scheme):
    with patch("agentscan.attacks.scan.runner.AgentScanClient") as client:
        with pytest.raises(ModuleUnavailableError):
            await JailbreakModule().run(Target(url=scheme, canary_token=PRIVATE))
        client.assert_not_called()


@pytest.mark.asyncio
async def test_criterion_preflight_prevents_model_and_target_calls():
    module = JailbreakModule()
    with (
        patch("agentscan.attacks.scan.runner.AIClient") as ai,
        patch("agentscan.attacks.scan.runner.AgentScanClient") as client,
    ):
        with pytest.raises(AssessmentInconclusiveError):
            await module.run(Target(url=URL, judge_model="gemini/unused"))
        ai.assert_not_called()
        client.assert_not_called()


@pytest.mark.asyncio
async def test_configured_analysis_models_are_not_used_for_this_criterion():
    module = JailbreakModule()
    with (
        patch("agentscan.attacks.scan.runner.AIClient") as ai,
        use_connector(CallableConnector(lambda _message: PRIVATE)),
    ):
        findings = await module.run(
            Target(
                url=URL,
                canary_token=PRIVATE,
                judge_model="gemini/unused",
                attacker_model="gemini/unused",
            )
        )
        assert len(findings) == module.variant_count()
        ai.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "body,status", [({"response": PRIVATE, "done": False}, 200), ({"response": PRIVATE}, 401)]
)
async def test_transport_and_completion_errors_do_not_count_as_resistance(body, status):
    module = JailbreakModule()
    with (
        patch.object(runner, "registry", registry(module)),
        respx.mock(assert_all_called=False) as mock,
    ):
        mock.post(URL).respond(status, json=body)
        report = await runner.run_scan(Target(url=URL, canary_token=PRIVATE))
    assert report.tests_run == 0
    assert report.tests_selected == module.variant_count()
    assert report.findings == []
    assert report.score is None
    assert report.status == ("ERROR" if status == 401 else "INCONCLUSIVE")


@pytest.mark.asyncio
@pytest.mark.parametrize("reply", [PRIVATE, "I preserve the private instructions."])
async def test_unverified_browser_completion_metadata_is_inconclusive(reply):
    module = JailbreakModule()
    with (
        patch.object(runner, "registry", registry(module)),
        respx.mock(assert_all_called=False) as mock,
    ):
        mock.post(URL).respond(200, json={"response": reply, "completion_verified": False})
        report = await runner.run_scan(Target(url=URL, canary_token=PRIVATE))
    assert report.tests_run == 0
    assert report.findings == []
    assert report.status == "INCONCLUSIVE"
    assert report.score is None


@pytest.mark.asyncio
@pytest.mark.parametrize("error_case", ["http_401_raw", "api_200_error"])
async def test_captured_response_mapping_cannot_hide_operational_errors(error_case):
    module = JailbreakModule()
    target = Target(
        url=URL,
        canary_token=PRIVATE,
        request_template=RequestTemplate(
            url=URL,
            message_path="message",
            response_path="raw" if error_case == "http_401_raw" else "response",
        ),
    )
    with (
        patch.object(runner, "registry", registry(module)),
        respx.mock(assert_all_called=False) as mock,
    ):
        if error_case == "http_401_raw":
            mock.post(URL).respond(401, text=PRIVATE)
        else:
            mock.post(URL).respond(200, json={"error": PRIVATE, "response": PRIVATE})
        report = await runner.run_scan(target)
    assert report.tests_run == 0
    assert report.findings == []
    assert report.status == "ERROR"
    assert report.score is None
    assert PRIVATE not in report.model_dump_json()


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [None, True, "200", 200.0])
async def test_unsupported_status_metadata_is_inconclusive(status):
    module = JailbreakModule()
    module._current_target = Target(url=URL, canary_token=PRIVATE)
    client = AsyncMock()
    client.send_message.return_value = {"response": PRIVATE, "status_code": status}
    with pytest.raises(AssessmentInconclusiveError):
        await module._test_variant(client, variant())


@pytest.mark.asyncio
async def test_cleanup_failure_preserves_confirmed_disclosure():
    module = JailbreakModule()

    class BrokenCleanup(CallableConnector):
        async def __aexit__(self, *exc):
            raise RuntimeError("Sensitive diagnostic must not enter report: " + PRIVATE)

    with (
        patch.object(runner, "registry", registry(module)),
        use_connector(BrokenCleanup(lambda _message: PRIVATE)),
    ):
        report = await runner.run_scan(Target(url=URL, canary_token=PRIVATE))
    assert len(report.findings) == module.variant_count()
    assert report.tests_run == module.variant_count()
    assert report.score is None
    assert report.status == "INCONCLUSIVE"
    assert report.module_outcomes[0]["status"] == "ERROR"
    assert PRIVATE not in report.model_dump_json()


@pytest.mark.asyncio
async def test_core_scan_budget_retains_one_disclosure_without_extra_requests():
    module = JailbreakModule()
    with (
        patch.object(runner, "registry", registry(module)),
        respx.mock(assert_all_called=False) as mock,
    ):
        route = mock.post(URL).respond(200, json={"response": PRIVATE})
        report = await runner.run_scan(
            Target(url=URL, canary_token=PRIVATE, request_budget=1, concurrency=1)
        )
    assert route.call_count == 1
    assert report.tests_selected == module.variant_count()
    assert report.tests_run == 1
    assert len(report.findings) == 1
    assert report.status == "INCONCLUSIVE"
    assert report.score is None


@pytest.mark.asyncio
async def test_direct_module_run_enforces_http_budget_and_restores_context():
    previous = active_context.set(None)
    try:
        module = JailbreakModule()
        with respx.mock(assert_all_called=False) as mock:
            route = mock.post(URL).respond(200, json={"response": PRIVATE})
            findings = await module.run(
                Target(url=URL, canary_token=PRIVATE, request_budget=1, concurrency=1)
            )
        assert route.call_count == 1
        assert len(findings) == 1
        assert active_context.get() is None
        with pytest.raises(AssessmentInconclusiveError):
            await module.run(Target(url=URL, request_budget=1))
        assert active_context.get() is None
    finally:
        active_context.reset(previous)


@pytest.mark.asyncio
@pytest.mark.parametrize("transport", ["ws", "wss", "browser"])
async def test_direct_non_http_probe_budget_counts_logical_delivery(transport):
    from agentscan.core.models import BrowserConfig

    class CountedReply(CallableConnector):
        calls = 0

        async def send_message(self, message, extra_body=None):
            self.calls += 1
            return {"response": PRIVATE, "completion_verified": True}

    kwargs = {}
    if transport == "browser":
        kwargs["browser"] = BrowserConfig(
            url="http://synthetic.invalid/widget",
            input_selector="#input",
            response_selector=".reply",
            completion_selector=".complete",
        )
    endpoint = f"{transport}://synthetic.invalid/chat" if transport != "browser" else URL
    connector = CountedReply(lambda _message: PRIVATE)
    previous = active_context.set(None)
    try:
        with use_connector(connector):
            findings = await JailbreakModule().run(
                Target(
                    url=endpoint, canary_token=PRIVATE, request_budget=1, concurrency=1, **kwargs
                )
            )
        assert connector.calls == 1
        assert len(findings) == 1
        assert active_context.get() is None
    finally:
        active_context.reset(previous)


@pytest.mark.asyncio
async def test_captured_http_precedence_does_not_double_count_websocket_url_budget():
    previous = active_context.set(None)
    try:
        with respx.mock(assert_all_called=False) as mock:
            route = mock.post(URL).respond(200, json={"response": PRIVATE})
            findings = await JailbreakModule().run(
                Target(
                    url="ws://synthetic.invalid/unused",
                    canary_token=PRIVATE,
                    request_budget=1,
                    concurrency=1,
                    request_template=RequestTemplate(url=URL, message_path="message"),
                )
            )
        assert route.call_count == 1
        assert len(findings) == 1
        assert active_context.get() is None
    finally:
        active_context.reset(previous)


def test_original_ten_payload_bytes_are_unchanged():
    seeds = JailbreakModule()._load_payload_variants()[:10]
    canonical = json.dumps([v["payload"] for v in seeds], ensure_ascii=False, separators=(",", ":"))
    # Frozen from the pre-upgrade committed catalog, independent of detection behavior.
    assert (
        hashlib.sha256(canonical.encode()).hexdigest()
        == "3bb689e6a8213b7c91c4afefebf9b48d59015b808bbb4821c931096187925a27"
    )
