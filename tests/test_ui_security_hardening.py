"""Regression tests for issue #45: dashboard headers and secret handling.

Covers QA-189 (absolute paths in 4xx bodies), QA-190 (headers on early
returns), QA-191 (CSP depth), QA-192 (secret retention in the DOM and browser
storage) and QA-193 (secret_key accepted on GET). All fixtures are synthetic and
loopback-only.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient

from agentscan.core.models import ScanMode, ScanReport
from agentscan.ui.app import create_app
from agentscan.ui.state import state

ROOT = Path(__file__).resolve().parents[1]
STATIC_DIR = ROOT / "agentscan" / "ui" / "static"
SYNTHETIC_KEY = "synthetic-qa045-signing-key-0123456789"


@pytest.fixture
def client(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("AGENTSCAN_UI_TOKEN", raising=False)
    previous = (state.report, state.report_path)
    with TestClient(
        create_app(project_root=tmp_path), base_url="http://127.0.0.1:8765"
    ) as instance:
        yield instance
    state.report, state.report_path = previous


def _report() -> ScanReport:
    return ScanReport(
        target_url="http://127.0.0.1:8811/chat",
        scan_mode=ScanMode.SCAN,
        status="COMPLETE",
        score=90,
        tests_selected=1,
    )


def assert_hardened_headers(response, *, dashboard_csp: bool = True) -> None:
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["cross-origin-opener-policy"] == "same-origin"
    assert response.headers["cross-origin-resource-policy"] == "same-origin"
    assert response.headers["x-permitted-cross-domain-policies"] == "none"
    assert "camera=()" in response.headers["permissions-policy"]
    assert "microphone=()" in response.headers["permissions-policy"]
    if not dashboard_csp:
        return
    csp = response.headers["content-security-policy"]
    for directive in (
        "default-src 'self'",
        "object-src 'none'",
        "base-uri 'none'",
        "form-action 'self'",
        "frame-ancestors 'none'",
    ):
        assert directive in csp


def assert_no_absolute_path(body: str, project_root: Path) -> None:
    assert str(project_root) not in body
    assert project_root.name not in body
    assert re.search(r"[A-Za-z]:[\\/]", body) is None
    assert "\\\\" not in body
    assert re.search(r"(?<![\w:/])/(?:[\w.@%+-]+/)+[\w.@%+-]+", body) is None


# ── QA-189: absolute paths never reach a 4xx body ────────────────────────────


@pytest.mark.parametrize(
    "leaked",
    [
        r"C:\Users\synthetic\project\escape.yaml",
        "C:/Users/synthetic/project/escape.yaml",
        r"\\fileserver\share\project\escape.yaml",
        "/home/synthetic/project/escape.yaml",
        "/tmp/pytest-of-synthetic/project",
    ],
)
def test_redact_absolute_paths_removes_every_path_shape(leaked: str) -> None:
    from agentscan.ui.security import REDACTED_PATH, redact_absolute_paths

    message = f"File changed since remediation was planned: {leaked}"
    redacted = redact_absolute_paths(message)
    assert leaked not in redacted
    assert REDACTED_PATH in redacted
    assert redacted.startswith("File changed since remediation was planned:")


def test_redact_absolute_paths_keeps_ordinary_messages() -> None:
    from agentscan.ui.security import redact_absolute_paths

    for message in (
        "This field is required.",
        "Connect to http://127.0.0.1:8765/chat failed",
        "Target returned HTTP 401",
        "Choose a path inside the dashboard's configured project directory.",
    ):
        assert redact_absolute_paths(message) == message


def test_containment_violation_body_hides_project_paths(client: TestClient, tmp_path: Path) -> None:
    response = client.get("/api/identity", params={"path": "../escape"})
    assert response.status_code == 403
    assert_no_absolute_path(response.text, tmp_path)
    assert "configured project directory" in response.json()["error"]


def test_http_exception_detail_is_redacted(tmp_path: Path) -> None:
    from fastapi import HTTPException

    from agentscan.ui.security import REDACTED_PATH

    app = create_app(project_root=tmp_path)

    @app.get("/api/qa045-path-leak")
    async def qa045_path_leak() -> None:
        raise HTTPException(
            status_code=409,
            detail=f"File changed since remediation was planned: {tmp_path / 'synthetic.yaml'}",
        )

    with TestClient(app) as instance:
        response = instance.get("/api/qa045-path-leak")
    assert response.status_code == 409
    assert_no_absolute_path(response.text, tmp_path)
    assert REDACTED_PATH in response.text


def test_heal_failure_body_hides_project_paths(
    client: TestClient, monkeypatch, tmp_path: Path
) -> None:
    from agentscan.guard.path import PathSecurityError
    from agentscan.remediation.engine import RemediationEngine

    def fail_plan(self, *args, **kwargs):
        raise PathSecurityError(
            f"Path containment violation: Target '{tmp_path / 'escape'}' "
            f"escapes containment boundary '{tmp_path}'"
        )

    monkeypatch.setattr(RemediationEngine, "plan", fail_plan)
    for response in (
        client.get("/api/heal"),
        client.post("/api/heal/apply", json={"root_path": "."}),
    ):
        assert response.status_code == 403
        assert_no_absolute_path(response.text, tmp_path)
        assert "configured project" in response.json()["error"]


# ── QA-190: headers on every response, including early returns ───────────────


def test_page_response_carries_standard_headers(client: TestClient) -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert_hardened_headers(response)
    assert "strict-transport-security" not in response.headers


def test_https_response_adds_hsts(tmp_path: Path) -> None:
    app = create_app(project_root=tmp_path)
    with TestClient(app, base_url="https://127.0.0.1:8765") as instance:
        response = instance.get("/api/features")
    assert response.status_code == 200
    assert response.headers["strict-transport-security"] == "max-age=31536000"


@pytest.mark.parametrize(
    "path,request_kwargs,expected_status",
    [
        ("/api/features", {"headers": {"Host": "evil.example"}}, 403),
        ("/api/features", {"headers": {"Host": "127.0.0.1:not-a-port"}}, 403),
        ("/api/features", {"headers": {"Origin": "https://evil.example"}}, 403),
        ("/api/features", {"headers": {"Sec-Fetch-Site": "cross-site"}}, 403),
        ("/api/scan", {"headers": {"Origin": "https://evil.example"}}, 403),
    ],
)
def test_early_return_denials_carry_standard_headers(
    client: TestClient, path: str, request_kwargs: dict, expected_status: int
) -> None:
    response = client.get(path, **request_kwargs)
    assert response.status_code == expected_status
    assert_hardened_headers(response)


def test_unauthenticated_early_return_carries_standard_headers(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("AGENTSCAN_UI_TOKEN", raising=False)
    with TestClient(create_app(token="synthetic-ui-token", project_root=tmp_path)) as instance:
        response = instance.get("/api/features")
    assert response.status_code == 401
    assert_hardened_headers(response)


def test_dashboard_target_denial_carries_standard_headers(client: TestClient) -> None:
    assert client.get("/").status_code == 200  # Establish the local session cookie.
    response = client.post("/api/scan", json={"target_url": "http://127.0.0.1:8765/chat"})
    assert response.status_code == 400
    assert "dashboard, not an agent endpoint" in response.json()["error"]
    assert_hardened_headers(response)


def test_unexpected_error_response_carries_standard_headers(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("AGENTSCAN_UI_TOKEN", raising=False)
    app = create_app(project_root=tmp_path)

    @app.get("/api/qa045-failure-fixture")
    async def qa045_failure_fixture() -> None:
        raise RuntimeError("synthetic failure")

    with TestClient(app, raise_server_exceptions=False) as instance:
        response = instance.get("/api/qa045-failure-fixture")
    assert response.status_code == 500
    assert_hardened_headers(response)


def test_missing_route_error_carries_standard_headers(client: TestClient) -> None:
    response = client.get("/api/qa045-missing-route")
    assert response.status_code == 404
    assert_hardened_headers(response)


# ── QA-191: CSP depth and route-provided policies ────────────────────────────


@pytest.mark.parametrize(
    "directive",
    [
        "default-src 'self'",
        "script-src 'self' 'unsafe-inline'",
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data:",
        "font-src 'self'",
        "connect-src 'self'",
        "object-src 'none'",
        "frame-src 'none'",
        "base-uri 'none'",
        "form-action 'self'",
        "frame-ancestors 'none'",
    ],
)
def test_dashboard_page_csp_contains_directive(client: TestClient, directive: str) -> None:
    assert directive in client.get("/").headers["content-security-policy"]


def test_no_external_origin_is_allowed() -> None:
    from agentscan.ui.security import DASHBOARD_CSP

    assert "default-src 'self'" in DASHBOARD_CSP
    assert "connect-src 'self'" in DASHBOARD_CSP
    assert "http://" not in DASHBOARD_CSP
    assert "https://" not in DASHBOARD_CSP
    assert "*" not in DASHBOARD_CSP.replace("'unsafe-inline'", "")


def test_html_report_download_keeps_its_stricter_policy(client: TestClient, monkeypatch) -> None:
    monkeypatch.setattr(state, "report", _report())
    response = client.get("/api/report/download", params={"format": "html"})
    assert response.status_code == 200
    policy = response.headers["content-security-policy"]
    assert policy.startswith("sandbox;")
    assert "default-src 'none'" in policy
    assert "frame-ancestors 'none'" in policy
    assert response.headers["x-content-type-options"] == "nosniff"
    assert_hardened_headers(response, dashboard_csp=False)


# ── QA-193: signing keys are not accepted in the URL ─────────────────────────


def test_get_certificate_rejects_secret_key(client: TestClient, monkeypatch) -> None:
    monkeypatch.setattr(state, "report", _report())
    response = client.get("/api/certificate", params={"secret_key": SYNTHETIC_KEY})
    assert response.status_code == 400
    assert SYNTHETIC_KEY not in response.text
    field_errors = response.json()["field_errors"]
    assert "secret_key" in field_errors
    assert "POST /api/certificate" in field_errors["secret_key"]


def test_get_certificate_without_secret_key_still_signs(client: TestClient, monkeypatch) -> None:
    monkeypatch.setattr(state, "report", _report())
    monkeypatch.setenv("AGENTSCAN_HMAC_KEY", SYNTHETIC_KEY)
    response = client.get("/api/certificate")
    assert response.status_code == 200
    assert response.json()["signature"]


def test_post_certificate_still_accepts_a_private_key(client: TestClient, monkeypatch) -> None:
    monkeypatch.setattr(state, "report", _report())
    assert client.get("/").status_code == 200  # Establish the local session cookie.
    response = client.post("/api/certificate", json={"secret_key": SYNTHETIC_KEY})
    assert response.status_code == 200
    assert SYNTHETIC_KEY not in response.text
    assert response.json()["signature"]


# ── QA-192: secret retention in the DOM and browser storage ──────────────────


def _node(script: str) -> str:
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is required for dashboard secret-retention contracts")
    completed = subprocess.run(
        [node, "-e", script],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    return completed.stdout


def test_secret_fields_and_storage_are_cleared() -> None:
    _node(
        r"""
const assert = require('node:assert/strict');
const field = (id, attrs) => ({
  id,
  value: 'synthetic-secret-value',
  attrs: { ...attrs },
  removeAttribute(name) { delete this.attrs[name]; },
});
const fields = [field('scan-canary-token', { type: 'password' }), field('cert-secret-key', { 'data-secret-field': 'true' })];
const state = new Map([
  ['agentscan_theme', 'dark'],
  ['agentscan_font', 'geist-pixel'],
  ['agentscan_secret_key', 'leak'],
  ['agentscan_ui_token', 'leak'],
  ['agentscan_canary_token', 'leak'],
  ['agentscan_certificate_signature', 'leak'],
]);
const storage = {
  get length() { return state.size; },
  key(index) { return [...state.keys()][index] ?? null; },
  removeItem(key) { state.delete(key); },
};
let selector = '';
global.document = { querySelectorAll(value) { selector = value; return fields; } };
global.localStorage = storage;
global.sessionStorage = storage;
const dashboard = require('./agentscan/ui/static/dashboard.js');
assert.deepEqual(dashboard.clearSecretFields(), ['scan-canary-token', 'cert-secret-key']);
assert.equal(fields[0].value, '');
assert.equal(fields[1].value, '');
assert.ok(!('value' in fields[0].attrs));
assert.ok(selector.includes('input[type="password"]'));
assert.ok(selector.includes('[data-secret-field]'));
assert.deepEqual([...state.keys()], ['agentscan_theme', 'agentscan_font']);
assert.deepEqual(dashboard.scrubStoredSecrets({}), []);
assert.deepEqual(dashboard.clearSecretFields(undefined), []);
"""
    )


def test_scan_and_certificate_flows_clear_secret_fields() -> None:
    actions = (STATIC_DIR / "dashboard-app-actions.js").read_text(encoding="utf-8")
    renderers = (STATIC_DIR / "dashboard-app-renderers.js").read_text(encoding="utf-8")
    assert actions.count("DashboardSemantics.clearSecretFields()") >= 2
    assert "DashboardSemantics.clearSecretFields()" in renderers
    assert re.search(
        r'<input type="password" id="cert-secret-key" data-secret-field="true"', renderers
    )


def test_dashboard_scripts_persist_no_secret_storage_keys() -> None:
    persisted = set()
    for path in STATIC_DIR.glob("*.js"):
        text = path.read_text(encoding="utf-8")
        persisted.update(
            re.findall(r"""(?:local|session)Storage\.setItem\(\s*['"]([^'"]+)['"]""", text)
        )
        persisted.update(
            re.findall(r"""(?:local|session)Storage\[\s*['"]([^'"]+)['"]\s*\]""", text)
        )
    assert persisted == {"agentscan_theme", "agentscan_font"}


def test_secret_inputs_are_marked_and_not_persisted() -> None:
    index_html = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    assert 'id="scan-canary-token"' in index_html
    assert 'type="password"' in index_html
    renderers = (STATIC_DIR / "dashboard-app-renderers.js").read_text(encoding="utf-8")
    assert 'data-secret-field="true"' in renderers
    assert "localStorage" not in renderers
    assert "sessionStorage" not in renderers
