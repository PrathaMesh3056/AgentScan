# agentscan/telemetry/otel.py
#
# OpenTelemetry Tracing + Prometheus Metrics for AgentScan Enterprise.
# Provides unified observability across API servers, worker processes, and runner pipelines.

from __future__ import annotations

import os

# Prometheus metrics setup (graceful fallback if optional dependency not yet installed)
try:
    from prometheus_client import (
        CONTENT_TYPE_LATEST,
        Counter,
        Gauge,
        Histogram,
        generate_latest,
    )

    SCANS_TOTAL = Counter(
        "agentscan_scans_total",
        "Total number of scans processed",
        ["tenant_id", "mode", "status"],
    )
    SCAN_DURATION = Histogram(
        "agentscan_scan_duration_seconds",
        "Duration of security scans in seconds",
        ["mode"],
        buckets=[1, 5, 10, 30, 60, 120, 300, 600],
    )
    FINDINGS_TOTAL = Counter(
        "agentscan_findings_total",
        "Total vulnerabilities found",
        ["severity", "owasp_id"],
    )
    ACTIVE_SCANS = Gauge(
        "agentscan_active_scans",
        "Number of scans currently running",
    )
    CONNECTOR_REQUESTS = Counter(
        "agentscan_connector_requests_total",
        "HTTP requests sent to target agents",
        ["status"],
    )
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False
    SCANS_TOTAL = None  # type: ignore
    SCAN_DURATION = None  # type: ignore
    FINDINGS_TOTAL = None  # type: ignore
    ACTIVE_SCANS = None  # type: ignore
    CONNECTOR_REQUESTS = None  # type: ignore

# OpenTelemetry setup
try:
    from opentelemetry import trace
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter

    resource = Resource.create({"service.name": "agentscan", "service.version": "0.1.0"})
    provider = TracerProvider(resource=resource)
    if os.environ.get("AGENTSCAN_OTEL_CONSOLE_EXPORT", "").lower() in ("1", "true"):
        provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))
    trace.set_tracer_provider(provider)
    tracer = trace.get_tracer("agentscan")
    OTEL_AVAILABLE = True
except ImportError:
    OTEL_AVAILABLE = False
    tracer = None  # type: ignore


def record_scan_start() -> None:
    if PROMETHEUS_AVAILABLE and ACTIVE_SCANS:
        ACTIVE_SCANS.inc()


def record_scan_end(tenant_id: str, mode: str, status: str, duration_sec: float) -> None:
    if PROMETHEUS_AVAILABLE:
        if ACTIVE_SCANS:
            ACTIVE_SCANS.dec()
        if SCANS_TOTAL:
            SCANS_TOTAL.labels(tenant_id=tenant_id, mode=mode, status=status).inc()
        if SCAN_DURATION:
            SCAN_DURATION.labels(mode=mode).observe(duration_sec)


def record_finding(severity: str, owasp_id: str) -> None:
    if PROMETHEUS_AVAILABLE and FINDINGS_TOTAL:
        FINDINGS_TOTAL.labels(severity=severity, owasp_id=owasp_id).inc()


def record_connector_request(status: int) -> None:
    if PROMETHEUS_AVAILABLE and CONNECTOR_REQUESTS:
        CONNECTOR_REQUESTS.labels(status=str(status)).inc()


def get_metrics_response() -> tuple[bytes, str]:
    """Generate latest Prometheus metrics."""
    if PROMETHEUS_AVAILABLE:
        return generate_latest(), CONTENT_TYPE_LATEST
    return b"# Prometheus metrics not available. Install [telemetry] extra.\n", "text/plain"
