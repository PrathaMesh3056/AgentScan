"""Structure checks for the modularized dashboard UI."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient

from agentscan.ui.app import PAGE_ROUTES, create_app

REPO_ROOT = Path(__file__).resolve().parents[1]
STATIC_DIR = REPO_ROOT / "agentscan" / "ui" / "static"
INDEX_PATH = STATIC_DIR / "index.html"


@pytest.fixture
def client(tmp_path: Path):
    from agentscan.ui.state import state

    previous = (state.report, state.report_path)
    app = create_app(project_root=tmp_path)
    with TestClient(app) as instance:
        yield instance
    state.report, state.report_path = previous


def test_page_routes_return_html(client: TestClient) -> None:
    for path in PAGE_ROUTES:
        response = client.get(path)
        assert response.status_code == 200, path
        assert "text/html" in response.headers.get("content-type", ""), path


def test_index_has_single_small_inline_script() -> None:
    html = INDEX_PATH.read_text(encoding="utf-8")
    inline_scripts = re.findall(
        r"<script\b(?![^>]*\bsrc=)[^>]*>(.*?)</script>", html, re.DOTALL | re.IGNORECASE
    )
    assert len(inline_scripts) == 1
    # The full inline script element (including tags) stays small.
    full_match = re.search(
        r"<script\b(?![^>]*\bsrc=)[^>]*>.*?</script>", html, re.DOTALL | re.IGNORECASE
    )
    assert full_match is not None
    assert len(full_match.group(0)) < 1000


def test_index_references_dashboard_scripts_in_order() -> None:
    html = INDEX_PATH.read_text(encoding="utf-8")
    expected = [
        "/static/dashboard-app-core.js",
        "/static/dashboard-app-renderers.js",
        "/static/dashboard-app-actions.js",
    ]
    positions = [html.find(item) for item in expected]
    assert all(pos != -1 for pos in positions)
    assert positions == sorted(positions)


def test_referenced_static_scripts_exist() -> None:
    html = INDEX_PATH.read_text(encoding="utf-8")
    referenced = re.findall(r"""src=["'](/static/[^"']+\.js)["']""", html)
    assert referenced, "no referenced scripts found"
    for ref in referenced:
        path = REPO_ROOT / "agentscan" / "ui" / ref.lstrip("/")
        assert path.is_file(), ref


def test_external_scripts_contain_expected_functions() -> None:
    combined = ""
    for name in ("dashboard-app-core.js", "dashboard-app-renderers.js", "dashboard-app-actions.js"):
        combined += (STATIC_DIR / name).read_text(encoding="utf-8")
    for needle in (
        "switchTab",
        "loadAllTelemetry",
        "renderOverview",
        "renderFindings",
        "openScanModal",
        "initEventStream",
    ):
        assert needle in combined
