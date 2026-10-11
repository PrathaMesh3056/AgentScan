from pathlib import Path

from agentscan.core.models import ScanReport
from agentscan.identity.models import IdentityReport
from agentscan.reporting.html_report import render_html_report


def render_pdf_report(report: ScanReport | IdentityReport, output_path: Path) -> None:
    try:
        import weasyprint
    except ImportError as e:
        raise RuntimeError(
            "PDF report generation requires the 'pdf' extra: pip install 'agentscan[pdf]'"
        ) from e
    html_content = render_html_report(report)

    def local_assets_only(url: str):
        if not url.startswith("data:"):
            raise ValueError("PDF rendering permits embedded assets only.")
        return weasyprint.default_url_fetcher(url)

    weasyprint.HTML(string=html_content, url_fetcher=local_assets_only).write_pdf(str(output_path))
