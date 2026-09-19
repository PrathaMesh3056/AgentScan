"""Telemetry and observability module for AgentScan."""

from agentscan.telemetry.otel import (
    OTEL_AVAILABLE,
    PROMETHEUS_AVAILABLE,
    get_metrics_response,
    record_connector_request,
    record_finding,
    record_scan_end,
    record_scan_start,
    tracer,
)

__all__ = [
    "OTEL_AVAILABLE",
    "PROMETHEUS_AVAILABLE",
    "get_metrics_response",
    "record_connector_request",
    "record_finding",
    "record_scan_end",
    "record_scan_start",
    "tracer",
]
