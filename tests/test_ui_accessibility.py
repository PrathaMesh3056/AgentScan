"""Accessibility contract for issue #40: drawer, toasts, nav state, and target sizes."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "agentscan" / "ui" / "static"
INDEX = STATIC / "index.html"
MODULE = STATIC / "dashboard-a11y.js"
CORE = STATIC / "dashboard-app-core.js"
CSS = STATIC / "dashboard.css"


def static_text(path: Path) -> str:
    assert path.is_file(), path
    return path.read_text(encoding="utf-8")


def tag_attributes(tag: str) -> dict[str, str]:
    return {name: value or "" for name, value in re.findall(r"([\w-]+)=\"([^\"]*)\"", tag)}


def test_accessibility_module_loads_before_dashboard_core() -> None:
    html = static_text(INDEX)
    module_position = html.find("/static/dashboard-a11y.js")
    core_position = html.find("/static/dashboard-app-core.js")
    assert module_position != -1, "dashboard-a11y.js must be loaded"
    assert core_position != -1, "dashboard-app-core.js must be loaded"
    assert module_position < core_position, "accessibility helpers must load before core wiring"


def test_mobile_menu_button_exposes_drawer_state() -> None:
    html = static_text(INDEX)
    match = re.search(r'<button\b[^>]*id="btn-mobile-menu"[^>]*>', html, re.S)
    assert match is not None, "mobile menu button is missing"
    attributes = tag_attributes(match.group(0))
    assert attributes.get("aria-controls") == "sidebar"
    assert attributes.get("aria-expanded") == "false"


def test_sidebar_is_a_labelled_navigation_landmark() -> None:
    html = static_text(INDEX)
    sidebar = re.search(r'<aside\b[^>]*id="sidebar"[^>]*>', html, re.S)
    nav = re.search(r"<nav\b[^>]*>", html, re.S)
    assert sidebar is not None
    assert nav is not None
    assert tag_attributes(sidebar.group(0)).get("aria-label") == "Primary navigation"
    assert tag_attributes(nav.group(0)).get("aria-label") == "Primary"


def test_only_the_active_nav_item_starts_with_aria_current() -> None:
    html = static_text(INDEX)
    items = re.findall(r'<a\b[^>]*class="[^"]*sidebar-nav-item[^"]*"[^>]*>', html, re.S)
    assert items, "navigation items are missing"
    current = [tag for tag in items if 'aria-current="page"' in tag]
    assert len(current) == 1, "exactly one nav item is the current page"
    assert 'data-tab="overview"' in current[0]


def test_switch_tab_syncs_aria_current_and_closes_the_drawer() -> None:
    core = static_text(CORE)
    assert "setActiveNavItem" in core
    assert "aria-current" in core
    assert "mobileDrawerController" in core
    assert "toggleSidebarMobile" in core


def test_drawer_module_implements_focus_management_and_semantics() -> None:
    module = static_text(MODULE)
    for needle in (
        "createDrawerController",
        "'role', 'dialog'",
        "'aria-modal', 'true'",
        "'aria-expanded'",
        "'Escape'",
        "event.shiftKey",
        "focusElement",
    ):
        assert needle in module, needle


def test_toast_container_is_a_polite_atomic_live_region() -> None:
    html = static_text(INDEX)
    match = re.search(r'<div\b[^>]*id="toast-notification"[^>]*>', html, re.S)
    assert match is not None, "toast live region is missing"
    attributes = tag_attributes(match.group(0))
    assert attributes.get("role") == "status"
    assert attributes.get("aria-live") == "polite"
    assert attributes.get("aria-atomic") == "true"


def test_show_toast_delegates_to_the_live_region_module() -> None:
    core = static_text(CORE)
    assert "AgentScanA11y" in core
    assert "AgentScanA11y.toast" in core


def test_inline_actions_meet_the_24px_target_size() -> None:
    css = static_text(CSS)
    control_rule = re.search(
        r'html body button,\s*html body \[role="button"\],\s*html body summary \{([^}]*)\}',
        css,
        re.S,
    )
    assert control_rule is not None, "24px target-size rule for controls is missing"
    declarations = control_rule.group(1)
    assert re.search(r"min-height:\s*24px", declarations)
    assert re.search(r"min-width:\s*24px", declarations)
    inline_rule = re.search(
        r"html body :is\(\.coverage-link, \.hero-secondary\) \{([^}]*)\}", css, re.S
    )
    assert inline_rule is not None, "inline action target-size rule is missing"
    assert re.search(r"min-height:\s*24px", inline_rule.group(1))
    coverage_rule = re.search(r"html body \.coverage-link \{([^}]*)\}", css, re.S)
    assert coverage_rule is not None, "coverage link box rule is missing"
    assert re.search(r"display:\s*inline-flex", coverage_rule.group(1))


def test_node_keyboard_and_dom_regressions_pass() -> None:
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is required for the dashboard keyboard and DOM tests")
    result = subprocess.run(
        [node, "tests/js/test_dashboard_a11y.mjs"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=60,
    )
    output = result.stdout + result.stderr
    assert result.returncode == 0, output
    assert re.search(r"pass \d+", output), output
    assert re.search(r"fail 0", output), output
