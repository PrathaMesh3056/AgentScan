import builtins
import sys

import pytest

from agentscan.core.models import Framework, ScanMode, ScanReport


def test_pdf_extra_declares_verified_pins():
    import tomllib
    from pathlib import Path

    data = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    pdf = data["project"]["optional-dependencies"]["pdf"]
    assert any(dep.startswith("weasyprint>=") and dep.split(">=")[1] >= "70.0" for dep in pdf)
    assert any(dep.startswith("pillow>=") and dep.split(">=")[1] >= "12.3.0" for dep in pdf)


def test_pdf_report_requires_extra(tmp_path, monkeypatch):
    monkeypatch.setitem(sys.modules, "weasyprint", None)
    from agentscan.reporting.pdf_report import render_pdf_report

    with pytest.raises(RuntimeError, match="unsupported in this build"):
        render_pdf_report(
            ScanReport(
                target_url="http://localhost", scan_mode=ScanMode.SCAN, framework=Framework.AUTO
            ),
            tmp_path / "report.pdf",
        )


def test_pdf_report_requires_native_libraries(tmp_path, monkeypatch):
    original_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "weasyprint":
            raise OSError("synthetic missing native library")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    from agentscan.reporting.pdf_report import render_pdf_report

    with pytest.raises(RuntimeError, match="unsupported in this build"):
        render_pdf_report(
            ScanReport(
                target_url="http://localhost", scan_mode=ScanMode.SCAN, framework=Framework.AUTO
            ),
            tmp_path / "report.pdf",
        )


def test_pdf_report_magic_bytes(tmp_path):
    pytest.importorskip("weasyprint")
    from agentscan.reporting.pdf_report import render_pdf_report

    report = ScanReport(
        target_url="http://localhost",
        scan_mode=ScanMode.SCAN,
        framework=Framework.AUTO,
        findings=[],
    )
    out = tmp_path / "test.pdf"
    render_pdf_report(report, out)
    assert out.exists()
    content = out.read_bytes()
    assert content.startswith(b"%PDF-")


def test_pdf_report_empty_findings(tmp_path):
    pytest.importorskip("weasyprint")
    from agentscan.reporting.pdf_report import render_pdf_report

    report = ScanReport(
        target_url="http://localhost",
        scan_mode=ScanMode.SCAN,
        framework=Framework.AUTO,
        findings=[],
    )
    out = tmp_path / "test_empty.pdf"
    render_pdf_report(report, out)
    assert out.exists()
