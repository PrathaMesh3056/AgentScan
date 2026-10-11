# agentscan/core/context.py
#
# Per-scan execution context — replaces all module-level singletons.
# Pass one ScanContext instance through the entire scan lifecycle so that
# concurrent scans running in the same process are fully isolated.

from __future__ import annotations

import uuid
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from agentscan.core.models import Target


def target_redaction_secrets(target: Target) -> tuple[str, ...]:
    """Protect known credentials even when a target echoes only their bare value."""
    from agentscan.core.evidence import private_redaction_values

    secrets = [value for value in (target.auth_header,) if value]
    secrets.extend(private_redaction_values(target))
    headers = dict(target.extra_headers)
    if target.request_template is not None:
        headers.update(target.request_template.headers)
    if target.auth_header:
        if ":" in target.auth_header:
            name, _, value = target.auth_header.partition(":")
            headers[name.strip()] = value.strip()
        else:
            headers["Authorization"] = target.auth_header
    for name, value in headers.items():
        if value:
            secrets.append(value)
        if name.lower() == "authorization":
            scheme, separator, token = value.partition(" ")
            if separator and scheme.lower() in {"bearer", "basic"} and token.strip():
                secrets.append(token.strip())
        elif name.lower() == "cookie":
            for cookie in value.split(";"):
                _, separator, token = cookie.partition("=")
                if separator and token.strip():
                    secrets.append(token.strip())
    return tuple(dict.fromkeys(secrets))


@dataclass
class ScanContext:
    """Immutable identity + mutable per-scan state for one isolated scan."""

    scan_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "local"

    # Per-scan recorder state (replaces the global recorder singleton)
    # These are plain lists — the API layer writes them to the DB after the scan.
    traffic_entries: list[dict[str, Any]] = field(default_factory=list)
    llm_calls: list[dict[str, Any]] = field(default_factory=list)

    # Progress tracking for SSE streaming
    modules_total: int = 0
    modules_done: int = 0
    current_module: str = ""
    recorder: Any = None
    trajectory: Any = None
    browser: Any = None
    target_requests: int = 0
    request_budget: int | None = None
    analysis_mode: str = "deterministic"
    local_model: str = "ollama/llama3.2"
    external_model: str = ""
    data_classification: str = "sensitive"
    analysis_requests: int = 0
    external_keys_from_dotenv: bool = True
    redaction_secrets: tuple[str, ...] = ()

    def progress_pct(self) -> int:
        if self.modules_total == 0:
            return 0
        return int(self.modules_done / self.modules_total * 100)


active_context: ContextVar[ScanContext | None] = ContextVar("agentscan_context", default=None)


class ContextLocal:
    """Compatibility facade backed by state belonging to the current scan task."""

    def __init__(self, name: str, factory: Any) -> None:
        object.__setattr__(self, "_name", name)
        object.__setattr__(self, "_factory", factory)
        object.__setattr__(self, "_fallback", factory())

    def _get(self) -> Any:
        context = active_context.get()
        if context is None:
            return self._fallback
        value = getattr(context, self._name)
        if value is None:
            value = self._factory()
            setattr(context, self._name, value)
        return value

    def __getattr__(self, name: str) -> Any:
        return getattr(self._get(), name)

    def __setattr__(self, name: str, value: Any) -> None:
        setattr(self._get(), name, value)


def begin_scan_context() -> ScanContext:
    """Start isolated state, retaining caller-selected transcript settings.

    State remains available to the caller after await run_scan() for transcript
    export. Sibling asyncio tasks receive their own context when starting scans.
    """
    from agentscan.core.trace import TrafficRecorder, recorder

    traffic = TrafficRecorder(redact=recorder.redact)
    traffic.enabled = recorder.enabled
    traffic.live = recorder.live
    context = ScanContext(recorder=traffic)
    active_context.set(context)
    return context
