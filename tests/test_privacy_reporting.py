from __future__ import annotations

import asyncio
import json
import sys
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from agentscan.api.data_policy import sanitize_report
from agentscan.api.limits import RequestBodyLimit
from agentscan.core.models import Finding, ScanMode, ScanReport, Severity, Target
from agentscan.reporting.sarif_report import to_sarif
from agentscan.supply_chain.aibom import build_cyclonedx_aibom
from agentscan.telemetry import otel


def test_service_report_omits_raw_evidence_and_preserves_report_schema():
    report = ScanReport(
        target_url="https://owned.invalid/chat?key=synthetic-private",
        scan_mode=ScanMode.SCAN,
        findings=[
            Finding(
                attack_id="ATK-001",
                attack_name="Probe",
                severity=Severity.HIGH,
                owasp_id="LLM01",
                description="synthetic-header-secret appeared",
                evidence="private response",
                payload_used="private prompt",
            )
        ],
    )
    raw = report.model_dump(mode="json")
    raw["trajectory"] = [{"request": "private prompt", "response": "private response"}]
    sanitized = sanitize_report(raw, ("synthetic-header-secret",))
    restored = ScanReport.model_validate(sanitized)
    assert restored.trajectory == [] and "?" not in restored.target_url
    assert "private prompt" not in json.dumps(sanitized) and "private response" not in json.dumps(
        sanitized
    )
    assert "synthetic-header-secret" not in json.dumps(sanitized)


def test_sarif_uses_only_known_locations_and_does_not_claim_calibrated_precision():
    report = ScanReport(target_url="https://owned.invalid/chat", scan_mode=ScanMode.SCAN)
    for metadata in ({}, {"file": "src/private file.py", "line": 47, "column": 3}):
        report.findings.append(
            Finding(
                attack_id="SC-011",
                attack_name="Model loader",
                severity=Severity.HIGH,
                owasp_id="LLM03",
                description="Unsafe model load detected",
                evidence="synthetic",
                metadata=metadata,
            )
        )
    run = to_sarif(report)["runs"][0]
    assert "locations" not in run["results"][0]
    location = run["results"][1]["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "src/private%20file.py"
    assert location["region"] == {"startLine": 47, "startColumn": 3}
    assert run["tool"]["driver"]["rules"][0]["properties"]["precision"] == "low"


def test_aibom_marks_unresolved_versions_and_invalid_inventory(tmp_path):
    (tmp_path / "requirements.txt").write_text("httpx>=0.27\n")
    (tmp_path / "bad.mcp.json").write_text("[]")
    doc = build_cyclonedx_aibom(str(tmp_path))
    package = next(c for c in doc["components"] if c["name"] == "httpx")
    assert "version" not in package and "purl" not in package
    config = next(c for c in doc["components"] if c["name"] == "bad.mcp.json")
    assert {p["name"]: p["value"] for p in config["properties"]}[
        "agentscan:inventory-status"
    ] == "unavailable"
    assert not any(c["type"] == "machine-learning-model" for c in doc["components"])
    declared = build_cyclonedx_aibom(str(tmp_path), reference_model="synthetic/reference")
    assert any(c["name"] == "synthetic/reference" for c in declared["components"])


def test_pdf_fetcher_denies_file_and_network_assets(monkeypatch, tmp_path):
    from agentscan.reporting.pdf_report import render_pdf_report

    observed = {}

    def html(**kwargs):
        observed.update(kwargs)
        return SimpleNamespace(write_pdf=lambda path: None)

    monkeypatch.setitem(
        sys.modules,
        "weasyprint",
        SimpleNamespace(HTML=html, default_url_fetcher=lambda url: {"url": url}),
    )
    render_pdf_report(
        ScanReport(target_url="https://owned.invalid", scan_mode=ScanMode.SCAN),
        tmp_path / "report.pdf",
    )
    for url in ("file:///etc/passwd", "https://owned.invalid/image.png"):
        with pytest.raises(ValueError):
            observed["url_fetcher"](url)
    assert observed["url_fetcher"]("data:text/plain,fixture")


@pytest.mark.parametrize("cancel", [False, True])
async def test_instrumentation_balances_scan_lifecycle_and_does_not_suppress_errors(
    monkeypatch, cancel
):
    starts, ends = Mock(), Mock()
    monkeypatch.setattr(otel, "record_scan_start", starts)
    monkeypatch.setattr(otel, "record_scan_end", ends)
    monkeypatch.setattr(
        otel, "record_finding", Mock(side_effect=RuntimeError("exporter unavailable"))
    )

    @otel.observe_scan
    async def scan(target):
        if cancel:
            raise asyncio.CancelledError()
        return ScanReport(target_url=target.url, scan_mode=target.mode)

    if cancel:
        with pytest.raises(asyncio.CancelledError):
            await scan(Target(url="https://owned.invalid"))
    else:
        assert isinstance(await scan(Target(url="https://owned.invalid")), ScanReport)
    starts.assert_called_once()
    ends.assert_called_once()
    assert ends.call_args.kwargs["active_started"] is True


async def test_failed_metric_start_never_decrements_a_gauge(monkeypatch):
    monkeypatch.setattr(otel, "record_scan_start", Mock(side_effect=RuntimeError("unavailable")))
    end = Mock()
    monkeypatch.setattr(otel, "record_scan_end", end)
    scan = otel.observe_scan(
        lambda target: asyncio.sleep(
            0, result=ScanReport(target_url=target.url, scan_mode=target.mode)
        )
    )
    assert await scan(Target(url="https://owned.invalid"))
    assert end.call_args.kwargs["active_started"] is False


async def test_body_limit_rejects_chunked_oversize_and_slow_clients():
    app = Mock()
    scope = {"type": "http", "method": "POST", "path": "/scans", "headers": []}
    for chunks, deadline, expected in ([b"123", b"456"], 1, 413), ([b"1"], 0.01, 408):
        sent = []

        async def receive(chunks=chunks):
            if chunks:
                return {"type": "http.request", "body": chunks.pop(0), "more_body": True}
            await asyncio.sleep(1)

        async def send(message, sent=sent):
            sent.append(message)

        await RequestBodyLimit(app, maximum=4, deadline=deadline)(scope, receive, send)
        assert sent[0]["status"] == expected
    assert not app.called


async def test_optional_spans_record_only_bounded_scan_metadata(monkeypatch):
    span = Mock()
    tracer = Mock(start_span=Mock(return_value=span))
    monkeypatch.setattr(otel, "OTEL_AVAILABLE", True)
    monkeypatch.setattr(otel, "tracer", tracer)

    @otel.observe_scan
    async def scan(target):
        return ScanReport(target_url=target.url, scan_mode=target.mode, status="INCONCLUSIVE")

    await scan(Target(url="https://private.invalid/?private=synthetic"))
    assert tracer.start_span.call_args.kwargs["attributes"] == {"scan.mode": "SCAN"}
    span.set_attribute.assert_called_once_with("scan.status", "INCONCLUSIVE")
    span.end.assert_called_once()
    span.record_exception.assert_not_called()
    tracer.start_span.side_effect = RuntimeError("synthetic exporter failure")
    assert await scan(Target(url="https://private.invalid"))
