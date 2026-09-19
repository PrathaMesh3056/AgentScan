# agentscan/core/context.py
#
# Per-scan execution context — replaces all module-level singletons.
# Pass one ScanContext instance through the entire scan lifecycle so that
# concurrent scans running in the same process are fully isolated.

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any


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

    def progress_pct(self) -> int:
        if self.modules_total == 0:
            return 0
        return int(self.modules_done / self.modules_total * 100)
