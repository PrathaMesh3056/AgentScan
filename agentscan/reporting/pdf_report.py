from pathlib import Path

from agentscan.core.models import ScanReport
from agentscan.identity.models import IdentityReport
from agentscan.reporting.html_report import render_html_report


def render_pdf_report(report: ScanReport | IdentityReport, output_path: Path) -> None:
    try:
        import weasyprint
    except (ImportError, OSError) as e:
        raise RuntimeError(
            "PDF report generation is unsupported in this build: install the 'pdf' extra "
            "(pip install 'agentscan[pdf]') and the required WeasyPrint native libraries."
        ) from e
    html_content = render_html_report(report)

    class local_assets_only:
        _fail_on_errors = True

        def __init__(self) -> None:
            fetcher_cls = getattr(weasyprint, "URLFetcher", None)
            if fetcher_cls is not None:
                self._default = fetcher_cls()
            else:
                self._default = getattr(weasyprint, "default_url_fetcher", None)

        def __call__(self, url: str):
            if not url.startswith("data:"):
                raise ValueError("PDF rendering permits embedded assets only.")
            if self._default is None:
                return None
            if callable(self._default):
                return self._default(url)
            return self._default

    url_fetcher = local_assets_only()

    try:
        weasyprint.HTML(string=html_content, url_fetcher=url_fetcher).write_pdf(str(output_path))
    except (ImportError, OSError, ValueError) as e:
        # ValueError from the fetcher restriction is a programming error; keep
        # dependency/native failures bounded.
        if isinstance(e, ValueError):
            raise
        raise RuntimeError(
            "PDF report generation is unsupported in this build: install the 'pdf' extra "
            "(pip install 'agentscan[pdf]') and the required WeasyPrint native libraries."
        ) from e
