from __future__ import annotations

import base64
from datetime import UTC, datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from agentscan.core.models import ScanReport
from agentscan.core.scorer import score_band
from agentscan.identity.models import IdentityReport
from agentscan.reporting.compliance_mapper import generate_compliance_summary

TEMPLATES_DIR = Path(__file__).parent / "templates"
LOGO_PATH = Path(__file__).resolve().parent.parent / "ui" / "static" / "logo.svg"


def _get_logo_data_uri() -> str:
    if LOGO_PATH.exists():
        data = LOGO_PATH.read_bytes()
        b64 = base64.b64encode(data).decode("ascii")
        return f"data:image/svg+xml;base64,{b64}"
    return ""


def render_html_report(report: ScanReport | IdentityReport) -> str:
    env = Environment(loader=FileSystemLoader(TEMPLATES_DIR), autoescape=True)
    logo_data_uri = _get_logo_data_uri()
    generated_at = datetime.now(UTC).strftime("%B %d, %Y · %H:%M UTC")

    if isinstance(report, ScanReport):
        template = env.get_template("scan_report.html.j2")
        compliance_summary = generate_compliance_summary(report.findings)
        score_val = report.score if report.score is not None else 0
        band = score_band(score_val)
        return template.render(
            report=report,
            compliance_summary=compliance_summary,
            logo_data_uri=logo_data_uri,
            generated_at=generated_at,
            score_band=band,
        )
    else:
        template = env.get_template("identity_report.html.j2")
        score_val = getattr(report, "identity_score", 100)
        band = score_band(score_val)
        return template.render(
            report=report,
            logo_data_uri=logo_data_uri,
            generated_at=generated_at,
            score_band=band,
        )
