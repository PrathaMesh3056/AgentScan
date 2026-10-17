"""Independent MCP catalog boundaries, with every transport kept in process."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock

import httpx
import pytest
import respx
from loguru import logger
from pydantic import ValidationError

from agentscan.attacks.scan.mcp_shadow import McpShadowModule
from agentscan.core import runner
from agentscan.core.connectors import Connector, use_connector
from agentscan.core.models import BrowserConfig, ScanMode, Target
from agentscan.core.outcomes import ExecutionLedger, execution_ledger

ENDPOINT = "mcp+sse://127.0.0.1:9/mcp"
KNOWN_SECRET = "synthetic-atk006-auth-credential-never-real"
REMOTE_DETAIL = "synthetic-private-remote-error-context"


@pytest.fixture
def isolated_module(monkeypatch):
    module = McpShadowModule()
    monkeypatch.setattr(runner.registry, "load_all", lambda: None)
    monkeypatch.setattr(runner.registry, "select_for_target", lambda target: ([module], []))
    monkeypatch.setattr(runner.registry, "load_errors", [])
    return module


@pytest.mark.parametrize(
    "endpoint",
    [
        "mcp+sse://operator:synthetic-password@127.0.0.1:9/mcp",
        "mcp+sse://127.0.0.1:9/mcp#synthetic-fragment",
    ],
    ids=["userinfo", "fragment"],
)
def test_catalog_remote_endpoint_rejects_unusable_identity_before_client(endpoint):
    """A matching baseline must not legalize credentials or a URI fragment."""
    with pytest.raises(ValidationError):
        Target(
            url=endpoint,
            mcp_inventory_baseline={"endpoint": endpoint, "tools": {}},
        )


@pytest.mark.parametrize(
    "override",
    [
        {"mutate": True},
        {"indirect_adapter": "document_v1"},
        {"attacker_model": "ollama/synthetic-local-model"},
        {"judge_model": "ollama/synthetic-local-model"},
        {"escalation_model": "ollama/synthetic-local-model"},
    ],
    ids=["mutation", "document-adapter", "attacker", "judge", "escalation"],
)
def test_catalog_sdk_constructor_rejects_non_catalog_features(override):
    with pytest.raises(ValidationError):
        Target(
            url=ENDPOINT,
            mcp_inventory_baseline={"endpoint": ENDPOINT, "tools": {}},
            **override,
        )


@pytest.mark.parametrize(
    "override",
    [
        {"url": "mcp+sse://operator:synthetic-password@127.0.0.1:9/mcp"},
        {"url": "mcp+sse://127.0.0.1:9/mcp#synthetic-fragment"},
        {"mutate": True},
        {"indirect_adapter": "document_v1"},
        {"attacker_model": "ollama/synthetic-local-model"},
        {"judge_model": "ollama/synthetic-local-model"},
        {"escalation_model": "ollama/synthetic-local-model"},
    ],
    ids=["userinfo", "fragment", "mutation", "document-adapter", "attacker", "judge", "escalation"],
)
async def test_direct_catalog_module_revalidates_copied_profile_before_client(
    monkeypatch, override
):
    """The module's public entry point must retain the SDK boundary itself."""
    target = Target(
        url=ENDPOINT,
        mcp_inventory_baseline={"endpoint": ENDPOINT, "tools": {}},
    )
    copied = dict(override)
    if "url" in copied:
        copied["mcp_inventory_baseline"] = target.mcp_inventory_baseline.model_copy(
            update={"endpoint": copied["url"]}
        )
    target = target.model_copy(update=copied)
    client = AsyncMock(side_effect=AssertionError("No connector construction is allowed"))
    monkeypatch.setattr("agentscan.attacks.scan.mcp_shadow.AgentScanClient", client)
    monkeypatch.setattr(
        "httpx.AsyncClient.request",
        AsyncMock(side_effect=AssertionError("No network request is allowed")),
    )
    ledger = ExecutionLedger()
    token = execution_ledger.set(ledger)
    try:
        findings = await McpShadowModule().run(target)
    finally:
        execution_ledger.reset(token)

    client.assert_not_called()
    assert findings == []
    assert ledger.selected == 1
    assert ledger.evaluated == 0
    assert ledger.inconclusive_reasons
    assert ledger.errors == []
    assert ledger.assessment_scope == "mcp_catalog_policy"


@pytest.mark.parametrize("multi_mode", [False, True], ids=["single-scan", "multi-mode"])
async def test_copied_browser_catalog_profile_is_rejected_before_any_transport(
    monkeypatch, isolated_module, multi_mode
):
    """Pydantic model_copy bypasses validators; scan entry points must not."""
    target = Target(
        url=ENDPOINT,
        mcp_inventory_baseline={"endpoint": ENDPOINT, "tools": {}},
    ).model_copy(
        update={
            "browser": BrowserConfig(
                url="http://127.0.0.1:9/",
                input_selector="textarea",
                response_selector=".reply",
            )
        }
    )
    opened = AsyncMock()
    closed = AsyncMock()
    client = AsyncMock(side_effect=AssertionError("No connector construction is allowed"))
    monkeypatch.setattr(runner, "open_browser_session", opened)
    monkeypatch.setattr(runner, "close_browser_session", closed)
    monkeypatch.setattr(runner, "browser_session_active", lambda: False)
    monkeypatch.setattr("agentscan.attacks.scan.mcp_shadow.AgentScanClient", client)
    monkeypatch.setattr("agentscan.attacks.scan.runner.AgentScanClient", client)
    monkeypatch.setattr(
        "agentscan.core.client.select_connector",
        lambda target: pytest.fail("A rejected catalog profile must not select a transport"),
    )
    monkeypatch.setattr(
        "httpx.AsyncClient.request",
        AsyncMock(side_effect=AssertionError("No network request is allowed")),
    )

    if multi_mode:
        report = await runner.run_scan_multi(target, [ScanMode.SCAN])
    else:
        report = await runner.run_scan(target)

    opened.assert_not_awaited()
    closed.assert_not_awaited()
    client.assert_not_called()
    assert report.status == "INCONCLUSIVE"
    assert report.tests_run == 0
    assert report.findings == []
    assert report.score is None
    assert report.assessment_scope == "mcp_catalog_policy"


class ErrorConnector(Connector):
    """Untrusted responses from an in-process endpoint; never opens sockets."""

    def __init__(self, status, prefix):
        self.status = status
        self.prefix = prefix
        self.calls = 0

    async def send_message(self, message, extra_body=None):
        self.calls += 1
        response = {"error": f"{self.prefix} {KNOWN_SECRET}; {REMOTE_DETAIL}"}
        if self.status is not None:
            response["status_code"] = self.status
        return response

    async def send_conversation(self, messages):
        return await self.send_message("synthetic conversation")


@pytest.mark.parametrize(
    ("status", "prefix"),
    [
        (None, "Provider says"),
        (401, "Provider says"),
        (0, "Target or redirect host is not enrolled"),
    ],
    ids=["error-body-only", "http-401", "allowlisted-text-with-private-suffix"],
)
async def test_untrusted_error_body_never_reaches_scan_reasons_or_variant_logs(
    monkeypatch, isolated_module, status, prefix
):
    """A known secret and arbitrary private body must disappear before logging."""
    target = Target(
        url="http://127.0.0.1:9/chat",
        auth_header=f"Bearer {KNOWN_SECRET}",
        attacks=["ATK-006"],
    )
    connector = ErrorConnector(status, prefix)
    messages = []
    sink = logger.add(lambda message: messages.append(str(message)), format="{message}")
    monkeypatch.setattr(
        "httpx.AsyncClient.request",
        AsyncMock(side_effect=AssertionError("No network request is allowed")),
    )
    try:
        with use_connector(connector):
            report = await runner.run_scan(target)
    finally:
        logger.remove(sink)

    reasons = json.dumps(
        {"errors": report.module_errors, "outcomes": report.module_outcomes}, sort_keys=True
    )
    rendered_logs = "\n".join(messages)
    assert connector.calls == 8
    assert report.status == "ERROR"
    assert report.tests_run == 0
    assert report.findings == []
    assert report.score is None
    assert report.module_errors
    assert KNOWN_SECRET not in reasons
    assert REMOTE_DETAIL not in reasons
    assert KNOWN_SECRET not in rendered_logs
    assert REMOTE_DETAIL not in rendered_logs
    if status == 401:
        assert "401" in reasons
        assert "401" in rendered_logs


@pytest.mark.parametrize("failure", [401, 403, 429, "timeout"])
async def test_catalog_transport_failure_retains_safe_diagnostic_without_private_text(
    isolated_module, failure
):
    """Real connector error classes are useful; remote error content is private."""
    target = Target(
        url=ENDPOINT,
        mcp_inventory_baseline={"endpoint": ENDPOINT, "tools": {}},
    )
    messages = []
    sink = logger.add(lambda message: messages.append(str(message)), format="{message}")
    try:
        with respx.mock(assert_all_called=False) as mock:
            route = mock.post("http://127.0.0.1:9/mcp")
            if failure == "timeout":
                route.mock(side_effect=httpx.ReadTimeout(f"{KNOWN_SECRET}; {REMOTE_DETAIL}"))
            else:
                route.respond(failure, text=f"{KNOWN_SECRET}; {REMOTE_DETAIL}")
            report = await runner.run_scan(target)
            assert route.call_count == 1
    finally:
        logger.remove(sink)

    reasons = json.dumps(
        {"errors": report.module_errors, "outcomes": report.module_outcomes}, sort_keys=True
    )
    assert report.status == "ERROR"
    assert report.tests_run == 0
    assert report.findings == []
    assert report.score is None
    for text in (reasons, "\n".join(messages)):
        assert KNOWN_SECRET not in text
        assert REMOTE_DETAIL not in text
    expected = "timed out" if failure == "timeout" else f"http {failure}"
    assert expected in reasons.lower()
