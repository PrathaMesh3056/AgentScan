# agentscan/telemetry/otel.py
#
# OpenTelemetry Tracing + Prometheus Metrics for AgentScan Enterprise.
# Provides unified observability across API servers, worker processes, and runner pipelines.

from __future__ import annotations

import contextlib
import os
from functools import wraps
from time import monotonic

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
        ["mode", "status"],
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
except Exception:  # Optional instrumentation must not prevent scanner startup.
    PROMETHEUS_AVAILABLE = False
    SCANS_TOTAL = None  # type: ignore
    SCAN_DURATION = None  # type: ignore
    FINDINGS_TOTAL = None  # type: ignore
    ACTIVE_SCANS = None  # type: ignore
    CONNECTOR_REQUESTS = None  # type: ignore

# OpenTelemetry setup
try:
    if os.environ.get("AGENTSCAN_OTEL_ENABLED", "").lower() not in {"1", "true"}:
        raise ImportError("Tracing is explicitly opt-in.")
    from opentelemetry import trace
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter

    from agentscan.core.models import _installed_version

    resource = Resource.create(
        {"service.name": "agentscan", "service.version": _installed_version()}
    )
    provider = TracerProvider(resource=resource)
    if os.environ.get("AGENTSCAN_OTEL_CONSOLE_EXPORT", "").lower() in ("1", "true"):
        provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))
    trace.set_tracer_provider(provider)
    tracer = trace.get_tracer("agentscan")
    OTEL_AVAILABLE = True
except Exception:  # Invalid exporter configuration also fails safely.
    OTEL_AVAILABLE = False
    tracer = None  # type: ignore


def record_scan_start() -> None:
    if PROMETHEUS_AVAILABLE and ACTIVE_SCANS:
        ACTIVE_SCANS.inc()


def record_scan_end(
    tenant_id: str, mode: str, status: str, duration_sec: float, *, active_started: bool = True
) -> None:
    if PROMETHEUS_AVAILABLE:
        if ACTIVE_SCANS and active_started:
            ACTIVE_SCANS.dec()
        if SCANS_TOTAL:
            mode = mode if mode in {"SCAN", "EXPLOIT", "DEEP", "AUDIT"} else "other"
            status = (
                status if status in {"COMPLETE", "INCONCLUSIVE", "ERROR", "cancelled"} else "other"
            )
            SCANS_TOTAL.labels(mode=mode, status=status).inc()
        if SCAN_DURATION:
            SCAN_DURATION.labels(mode=mode).observe(duration_sec)


def record_finding(severity: str, owasp_id: str) -> None:
    if PROMETHEUS_AVAILABLE and FINDINGS_TOTAL:
        severity = (
            severity
            if severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "PASS"}
            else "other"
        )
        owasp_id = owasp_id if owasp_id in {f"LLM{i:02}" for i in range(1, 11)} else "unmapped"
        FINDINGS_TOTAL.labels(severity=severity, owasp_id=owasp_id).inc()


def record_connector_request(status: int) -> None:
    if PROMETHEUS_AVAILABLE and CONNECTOR_REQUESTS:
        CONNECTOR_REQUESTS.labels(status=str(status) if 100 <= status <= 599 else "error").inc()


def observe_scan(function):
    """Optional instrumentation never changes results or suppresses cancellation."""

    @wraps(function)
    async def observed(target, *args, **kwargs):
        started = monotonic()
        outcome = "ERROR"
        active_started = False
        span = None
        with contextlib.suppress(Exception):
            if OTEL_AVAILABLE and tracer is not None:
                mode = target.mode.value
                span = tracer.start_span(
                    "agentscan.scan",
                    attributes={
                        "scan.mode": mode
                        if mode in {"SCAN", "EXPLOIT", "DEEP", "AUDIT"}
                        else "other"
                    },
                )
        with contextlib.suppress(Exception):
            record_scan_start()
            active_started = True
        try:
            report = await function(target, *args, **kwargs)
            outcome = report.status
            for finding in report.findings:
                with contextlib.suppress(Exception):
                    record_finding(finding.severity.value, finding.owasp_id)
            return report
        except BaseException as exc:
            import asyncio

            if isinstance(exc, asyncio.CancelledError):
                outcome = "cancelled"
            raise
        finally:
            with contextlib.suppress(Exception):
                if span is not None:
                    span.set_attribute(
                        "scan.status",
                        outcome
                        if outcome in {"COMPLETE", "INCONCLUSIVE", "ERROR", "cancelled"}
                        else "other",
                    )
                    span.end()
            with contextlib.suppress(Exception):
                record_scan_end(
                    "",
                    target.mode.value,
                    outcome,
                    monotonic() - started,
                    active_started=active_started,
                )

    return observed


def get_metrics_response() -> tuple[bytes, str]:
    """Generate latest Prometheus metrics."""
    if PROMETHEUS_AVAILABLE:
        return generate_latest(), CONTENT_TYPE_LATEST
    return b"# Prometheus metrics not available. Install [telemetry] extra.\n", "text/plain"
