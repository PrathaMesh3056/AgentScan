from __future__ import annotations

from agentscan.gateway.errors import GatewayError, http_error, jsonrpc_error, tool_error_result
from agentscan.gateway.metrics import MetricsRegistry
from agentscan.gateway.models import ErrorCode


def test_error_maps_every_code_to_stable_jsonrpc_shape() -> None:
    for code in ErrorCode:
        assert jsonrpc_error(code)["code"] == -32000
        assert jsonrpc_error(code)["data"]["agentscan_code"] == code.value
    status, body = http_error(ErrorCode.IDENTITY_MISMATCH)
    assert status == 403 and body["agentscan_code"] == "IDENTITY_MISMATCH"
    exc = GatewayError(ErrorCode.POLICY_DENIED, "safe")
    assert exc.as_jsonrpc_data() == {"agentscan_code": "POLICY_DENIED"}


def test_tool_error_helper_is_error_and_does_not_include_exception_details() -> None:
    for code in (ErrorCode.UPSTREAM_ERROR, ErrorCode.TIMEOUT):
        result = tool_error_result(code)
        assert result.isError is True
        assert code.value in result.content[0].text
        assert "secret/path" not in result.content[0].text


def test_metrics_bound_labels_and_samples() -> None:
    metrics = MetricsRegistry(sample_limit=2)
    metrics.increment("auth_failures", reason="principal-secret-token")
    metrics.increment("decisions", tool="tool-secret", decision="allow", reason="unknown-value")
    metrics.observe("policy_latency_seconds", 0.2)
    metrics.observe("policy_latency_seconds", 0.4)
    metrics.observe("policy_latency_seconds", 0.6)
    assert metrics.quantile("policy_latency_seconds", 0.5) == 0.4
    assert metrics.quantile("policy_latency_seconds", 0.99) == 0.6
    exposition = metrics.render()
    assert "# HELP" in exposition and "# TYPE" in exposition
    assert "principal-secret-token" not in exposition and "tool-secret" not in exposition
    assert 'quantile="0.99"' in exposition
