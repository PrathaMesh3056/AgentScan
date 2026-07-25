from agentscan.core.models import Framework, ScanMode, ScanReport
from agentscan.reporting.pdf_report import render_pdf_report


def test_pdf_report_magic_bytes(tmp_path):
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
    report = ScanReport(
        target_url="http://localhost",
        scan_mode=ScanMode.SCAN,
        framework=Framework.AUTO,
        findings=[],
    )
    out = tmp_path / "test_empty.pdf"
    render_pdf_report(report, out)
    assert out.exists()
