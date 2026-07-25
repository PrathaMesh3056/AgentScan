from pathlib import Path

import weasyprint

from agentscan.core.models import ScanReport
from agentscan.identity.models import IdentityReport
from agentscan.reporting.html_report import render_html_report


def render_pdf_report(report: ScanReport | IdentityReport, output_path: Path) -> None:
    html_content = render_html_report(report)
    weasyprint.HTML(string=html_content).write_pdf(str(output_path))
