# agentscan/cli/_preflight.py
#
# Bounded pre-work checks and operator-facing failure guidance for CLI commands
# (QA-038). These helpers keep expected operator errors short and actionable
# instead of surfacing dependency tracebacks or raw connector exceptions.

from __future__ import annotations

import importlib.util
import re
from collections import Counter
from typing import Any

import typer

BROWSER_SETUP_GUIDANCE = (
    "Browser scanning requires the Playwright package and its Chromium build. "
    "Install the browser extra (uv sync --extra browser, or pip install 'agentscan[browser]'), "
    "then run: python -m playwright install chromium."
)

# Profile keys whose CLI consumers assume a single string (or path-like string).
PROFILE_STRING_FIELDS = frozenset({
    "analysis_mode",
    "attacker_goal",
    "attacker_model",
    "auth_header",
    "canary_token",
    "data_classification",
    "escalation_model",
    "external_model",
    "fail_on",
    "framework",
    "indirect_adapter",
    "judge_model",
    "llm_log",
    "output",
    "system_prompt",
    "trajectory_log",
    "transcript",
    "url",
})

PROFILE_BOOLEAN_FIELDS = frozenset({
    "calibrate",
    "calibrate_required",
    "deep",
    "exploit",
    "mutate",
    "verbose",
})

PROFILE_INTEGER_FIELDS = frozenset({"attacker_turns", "escalation_turns"})

PROFILE_MAPPING_FIELDS = frozenset({
    "browser",
    "factuality_baseline",
    "mcp_inventory_baseline",
    "request_template",
})

_HTTP_TARGET_ERROR = re.compile(r"Target returned HTTP (\d{3})")


def playwright_available() -> bool:
    """Return whether the optional Playwright package can be imported."""
    try:
        return importlib.util.find_spec("playwright") is not None
    except (ImportError, ValueError):  # pragma: no cover - broken interpreter state
        return False


def require_browser_runtime() -> None:
    """Fail early, with install guidance, when browser work is requested."""
    if not playwright_available():
        raise typer.BadParameter(BROWSER_SETUP_GUIDANCE)


def validate_profile_fields(config: dict[str, Any]) -> None:
    """Reject wrong-typed profile values before any scan work starts."""
    for key in sorted(PROFILE_STRING_FIELDS & config.keys()):
        if not isinstance(config[key], str):
            raise typer.BadParameter(f"Profile field '{key}' must be a single string value.")
    for key in sorted(PROFILE_BOOLEAN_FIELDS & config.keys()):
        if not isinstance(config[key], bool):
            raise typer.BadParameter(f"Profile field '{key}' must be true or false.")
    for key in sorted(PROFILE_INTEGER_FIELDS & config.keys()):
        value = config[key]
        valid = isinstance(value, int) and not isinstance(value, bool)
        if isinstance(value, str) and value.strip().isdigit():
            valid = True
        if not valid:
            raise typer.BadParameter(f"Profile field '{key}' must be a whole number.")
    for key in sorted(PROFILE_MAPPING_FIELDS & config.keys()):
        if not isinstance(config[key], dict):
            raise typer.BadParameter(
                f"Profile field '{key}' must be a mapping of settings."
            )


def bounded_error_detail(error: BaseException, limit: int = 240) -> str:
    """Return one line of exception detail, capped so terminal output stays bounded."""
    detail = " ".join(str(error).split())
    if not detail:
        return type(error).__name__
    if len(detail) > limit:
        detail = detail[: limit - 3].rstrip() + "..."
    return f"{type(error).__name__}: {detail}"


def _module_error_texts(report: Any) -> list[str]:
    errors = getattr(report, "module_errors", None) or []
    return [str(item.get("error") or "") for item in errors if isinstance(item, dict)]


def scan_failure_guidance(report: Any) -> str | None:
    """Summarise the dominant known cause of an incomplete scan, if one is clear."""
    texts = _module_error_texts(report)
    if not texts:
        return None
    joined = " | ".join(texts)
    if "No module named 'playwright'" in joined:
        return BROWSER_SETUP_GUIDANCE
    if "Executable doesn't exist" in joined:
        return (
            "Playwright is installed but its Chromium build is missing. Run: "
            "python -m playwright install chromium."
        )
    statuses = Counter(_HTTP_TARGET_ERROR.findall(joined))
    if statuses:
        code, failures = statuses.most_common(1)[0]
        if code.startswith("5"):
            return (
                f"Target-side failure: HTTP {code} dominated the {failures} recorded module "
                "error line(s). Check that the target service is healthy and that the endpoint "
                "matches the expected request contract, then retry."
            )
        return (
            f"Request-side rejection: HTTP {code} dominated the {failures} recorded module "
            "error line(s). Check authentication, route and request format before retrying."
        )
    if "Connection failed" in joined or "ConnectError" in joined:
        return (
            "The target could not be reached: recorded requests failed to connect. Check that "
            "the service is running, the URL scheme and port are correct, and network egress "
            "is permitted, then retry."
        )
    if "timed out" in joined.lower():
        return (
            "The target did not answer within the request deadline for recorded requests. "
            "Check target latency and retry once it responds."
        )
    return None