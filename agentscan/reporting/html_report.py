from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from agentscan.core.models import ScanReport
from agentscan.identity.models import IdentityReport
from agentscan.reporting.compliance_mapper import generate_compliance_summary

TEMPLATES_DIR = Path(__file__).parent / "templates"


def render_html_report(report: ScanReport | IdentityReport) -> str:
    env = Environment(loader=FileSystemLoader(TEMPLATES_DIR), autoescape=True)
    if isinstance(report, ScanReport):
        template = env.get_template("scan_report.html.j2")
        compliance_summary = generate_compliance_summary(report.findings)
        return template.render(report=report, compliance_summary=compliance_summary)
    else:
        template = env.get_template("identity_report.html.j2")
        return template.render(report=report)
