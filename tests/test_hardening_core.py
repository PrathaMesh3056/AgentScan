from __future__ import annotations

import asyncio
import contextlib
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
from time import sleep
from unittest.mock import AsyncMock, patch

import pytest
import respx

from agentscan.attacks.base import AttackModule
from agentscan.attacks.registry import AttackRegistry
from agentscan.attacks.scan.runner import YamlScanRunner
from agentscan.core.circuit_breaker import AsyncCircuitBreaker, CircuitState
from agentscan.core.client import AgentScanClient
from agentscan.core.connectors.base import parse_sse
from agentscan.core.connectors.browser import BrowserConnector
from agentscan.core.evaluator import _parse_judgment
from agentscan.core.models import BrowserConfig, Finding, Severity, Target
from agentscan.core.outcomes import ModuleUnavailableError, TargetRequestError
from agentscan.core.runner import run_scan
from agentscan.core.scorer import calculate_score, score_band
from agentscan.core.trajectory import trajectory_recorder
from agentscan.neural.execution import serialized_reference_call


class CleanAttack(AttackModule):
    attack_id = "ATK-901"
    attack_name = "Clean test"
    owasp_id = "LLM01"

    def variant_count(self):
        return 2

    async def run(self, target):
        return []


def registry_with(*modules):
    result = AttackRegistry()
    for module in modules:
        result.register(module)
    result._loaded = True
    return result


@pytest.mark.asyncio
async def test_no_modules_is_unscored_and_inconclusive():
    with patch("agentscan.core.runner.registry", registry_with()):
        report = await run_scan(Target(url="http://target.test/chat"))
    assert report.status == "INCONCLUSIVE"
    assert report.score is None
    assert report.tests_run == report.tests_selected == 0


@pytest.mark.asyncio
async def test_unavailable_dependency_is_skipped_not_a_clean_pass():
    class Unavailable(CleanAttack):
        async def run(self, target):
            raise ModuleUnavailableError("required model absent")

    with patch("agentscan.core.runner.registry", registry_with(Unavailable())):
        report = await run_scan(Target(url="http://target.test/chat"))
    assert report.status == "INCONCLUSIVE"
    assert report.score is None
    assert report.tests_selected == 2 and report.tests_run == 0
    assert report.module_outcomes[0]["status"] == "SKIPPED"


@pytest.mark.asyncio
async def test_error_hidden_by_legacy_module_is_retained():
    class Catching(CleanAttack):
        async def run(self, target):
            async with AgentScanClient(target) as client:
                with contextlib.suppress(TargetRequestError):
                    await client.send_message("test")
            return []

    with respx.mock() as mock:
        mock.post("http://target.test/chat").respond(401, json={"response": "refusal"})
        with patch("agentscan.core.runner.registry", registry_with(Catching())):
            report = await run_scan(Target(url="http://target.test/chat"))
    assert report.status == "ERROR"
    assert report.score is None and report.tests_run == 0
    assert "401" in report.module_errors[0]["error"]


@pytest.mark.asyncio
async def test_sibling_scans_keep_trajectory_and_plugin_state_separate():
    arrived = 0
    barrier = asyncio.Event()

    class Recording(CleanAttack):
        async def run(self, target):
            nonlocal arrived
            self.current_target = target.url
            trajectory_recorder.record(target.url, {"response": target.url})
            arrived += 1
            if arrived == 2:
                barrier.set()
            await asyncio.wait_for(barrier.wait(), 1)
            assert self.current_target == target.url
            return []

    with patch("agentscan.core.runner.registry", registry_with(Recording())):
        a, b = await asyncio.gather(
            run_scan(Target(url="http://a.test/chat")),
            run_scan(Target(url="http://b.test/chat")),
        )
    assert len(a.trajectory) == len(b.trajectory) == 1
    assert a.trajectory[0].response == a.target_url
    assert b.trajectory[0].response == b.target_url


@pytest.mark.asyncio
async def test_reference_model_observations_do_not_score_remote_target():
    class Reference(CleanAttack):
        assessment_scope = "local_reference_model"

        async def run(self, target):
            return [
                self.make_finding(
                    severity=Severity.HIGH, description="Local model experimental observation"
                )
            ]

    with patch("agentscan.core.runner.registry", registry_with(Reference())):
        report = await run_scan(Target(url="http://target.test/chat"))
    assert report.findings == []
    assert len(report.reference_observations) == 1
    assert report.score is None
    assert report.assessment_scope == "local_reference_model"


@pytest.mark.asyncio
async def test_cancellation_propagates():
    class Cancelled(CleanAttack):
        async def run(self, target):
            raise asyncio.CancelledError()

    with (
        patch("agentscan.core.runner.registry", registry_with(Cancelled())),
        pytest.raises(asyncio.CancelledError),
    ):
        await run_scan(Target(url="http://target.test/chat"))


def test_duplicate_registration_is_an_error():
    registry = registry_with(CleanAttack())
    with pytest.raises(ValueError, match="Duplicate"):
        registry.register(CleanAttack())


@pytest.mark.parametrize("value", ['"false"', '"true"', "0", "1", "null", "[]", "{}"])
def test_judge_success_must_be_a_json_boolean(value):
    verdict = _parse_judgment('{"success":' + value + "}")
    assert verdict.status == "INVALID" and verdict.success is False


def test_unrecognized_judge_reply_is_invalid():
    assert _parse_judgment("yesterday this was permitted").status == "INVALID"
    assert _parse_judgment('{"success":false}').status == "VALID"


def test_refusal_mention_is_not_tool_execution():
    assert not YamlScanRunner._check_tool_call_contains("I cannot execute rm -rf", "rm -rf", {})
    assert YamlScanRunner._check_tool_call_contains(
        "", "rm -rf", {"tool_calls": [{"function": {"arguments": "rm -rf"}}]}
    )


def test_openai_sse_nested_deltas_are_reassembled():
    raw = 'data: {"choices":[{"delta":{"content":"hello "}}]}\n\ndata: {"choices":[{"delta":{"content":"world"}}]}\n\ndata: [DONE]\n'
    assert parse_sse(raw) == "hello world"


def test_critical_cannot_be_diluted_into_safe_score():
    finding = Finding(
        attack_id="ATK-001",
        attack_name="test",
        severity=Severity.CRITICAL,
        owasp_id="LLM01",
        description="Confirmed critical vulnerability here",
    )
    assert score_band(calculate_score([finding], 10000)) == "CRITICAL RISK"
    assert score_band(calculate_score([], 0)) == "INCONCLUSIVE"


@pytest.mark.asyncio
async def test_coroutine_factory_and_async_callable_are_awaited():
    breaker = AsyncCircuitBreaker("factory")

    async def operation():
        return 42

    class Callable:
        async def __call__(self):
            return 43

    assert await breaker.call(lambda: operation()) == 42
    assert await breaker.call(Callable()) == 43


@pytest.mark.asyncio
async def test_cancelled_half_open_probe_releases_trial():
    breaker = AsyncCircuitBreaker(
        "cancel", failure_threshold=1, recovery_timeout=0, half_open_max_trials=1
    )

    async def fail():
        raise RuntimeError("unavailable")

    with pytest.raises(RuntimeError):
        await breaker.call(fail)

    async def cancel():
        raise asyncio.CancelledError()

    with pytest.raises(asyncio.CancelledError):
        await breaker.call(cancel)
    assert await breaker.call(lambda: "recovered") == "recovered"
    assert breaker.state == CircuitState.CLOSED


@pytest.mark.asyncio
async def test_enrollment_blocks_redirect_before_contact():
    target = Target(url="http://allowed.test/chat", allowed_hosts=["allowed.test"])
    with respx.mock(assert_all_called=False) as mock:
        mock.post(target.url).respond(307, headers={"Location": "http://blocked.test/chat"})
        forbidden = mock.post("http://blocked.test/chat").respond(200, json={"response": "bad"})
        async with AgentScanClient(target) as client:
            with pytest.raises(TargetRequestError, match="not enrolled"):
                await client.send_message("test")
        assert not forbidden.called


@pytest.mark.asyncio
async def test_enrolled_same_host_redirect_still_works():
    target = Target(url="http://allowed.test/chat", allowed_hosts=["allowed.test"])
    with respx.mock() as mock:
        mock.post(target.url).respond(307, headers={"Location": "/new"})
        mock.post("http://allowed.test/new").respond(200, json={"response": "ok"})
        async with AgentScanClient(target) as client:
            assert (await client.send_message("test"))["response"] == "ok"


@pytest.mark.asyncio
async def test_browser_does_not_read_stale_bubble_after_timeout():
    cfg = BrowserConfig(url="http://widget.test", input_selector="#input", response_selector=".bot")
    connector = BrowserConnector(Target(url=cfg.url, browser=cfg))
    page = AsyncMock()
    locator = AsyncMock()
    locator.count.return_value = 1
    page.locator = lambda _: locator
    page.wait_for_function.side_effect = TimeoutError("new bubble absent")
    connector._page = page
    result = await connector.send_message("test")
    assert result["status_code"] == 0
    locator.last.inner_text.assert_not_awaited()


@pytest.mark.asyncio
async def test_browser_waits_for_explicit_completion():
    cfg = BrowserConfig(
        url="http://widget.test",
        input_selector="#input",
        response_selector=".bot",
        completion_selector="[data-complete=true]",
    )
    connector = BrowserConnector(Target(url=cfg.url, browser=cfg))
    page = AsyncMock()
    locator = AsyncMock()
    locator.count.return_value = 1
    locator.last.inner_text.return_value = "COMPLETE REPLY"
    page.locator = lambda _: locator
    connector._page = page
    result = await connector.send_message("test")
    assert page.wait_for_function.await_count == 2
    assert result["response"] == "COMPLETE REPLY" and result["completion_verified"]


def test_shared_neural_calls_are_serialized():
    guard = Lock()
    active = maximum = 0

    @serialized_reference_call
    def forward(value):
        nonlocal active, maximum
        with guard:
            active += 1
            maximum = max(maximum, active)
        sleep(0.005)
        with guard:
            active -= 1
        return value

    with ThreadPoolExecutor(max_workers=4) as pool:
        assert list(pool.map(forward, range(8))) == list(range(8))
    assert maximum == 1


@pytest.mark.asyncio
async def test_variant_count_failure_does_not_abort_healthy_plugins():
    class BadCount(CleanAttack):
        attack_id = "ATK-902"

        def variant_count(self):
            raise ValueError("broken payload configuration")

    with patch("agentscan.core.runner.registry", registry_with(BadCount(), CleanAttack())):
        report = await run_scan(Target(url="http://target.test/chat"))
    assert report.tests_run == 2
    assert report.status == "INCONCLUSIVE"
    assert report.module_outcomes[0]["status"] == "ERROR"


@pytest.mark.asyncio
async def test_plugin_copy_failure_is_retained_without_losing_healthy_plugins():
    class BadCopy(CleanAttack):
        attack_id = "ATK-902"

        def __deepcopy__(self, memo):
            raise RuntimeError("plugin state cannot be copied")

    with patch("agentscan.core.runner.registry", registry_with(BadCopy(), CleanAttack())):
        report = await run_scan(Target(url="http://target.test/chat"))
    assert report.status == "INCONCLUSIVE" and report.tests_run == 2
    assert "cannot be copied" in report.module_errors[0]["error"]


@pytest.mark.asyncio
async def test_child_cancellation_joins_siblings_before_returning():
    started, stopped = asyncio.Event(), asyncio.Event()

    class Waiting(CleanAttack):
        attack_id = "ATK-902"

        async def run(self, target):
            started.set()
            try:
                await asyncio.Event().wait()
            finally:
                stopped.set()

    class Cancelling(CleanAttack):
        async def run(self, target):
            await started.wait()
            raise asyncio.CancelledError()

    with (
        patch("agentscan.core.runner.registry", registry_with(Waiting(), Cancelling())),
        pytest.raises(asyncio.CancelledError),
    ):
        await run_scan(Target(url="http://target.test/chat"))
    assert stopped.is_set()


@pytest.mark.asyncio
async def test_browser_cleanup_failure_preserves_findings_and_coverage():
    cfg = BrowserConfig(url="http://widget.test", input_selector="#i", response_selector=".bot")
    target = Target(url=cfg.url, browser=cfg)
    with (
        patch("agentscan.core.runner.registry", registry_with(CleanAttack())),
        patch("agentscan.core.runner.browser_session_active", return_value=False),
        patch("agentscan.core.runner.open_browser_session", new=AsyncMock()),
        patch(
            "agentscan.core.runner.close_browser_session",
            new=AsyncMock(side_effect=RuntimeError("cleanup failed")),
        ),
    ):
        report = await run_scan(target)
    assert report.tests_run == 2 and report.status == "INCONCLUSIVE"
    assert report.module_errors[-1]["module_id"] == "cleanup"
