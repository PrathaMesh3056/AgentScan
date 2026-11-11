"""Small in-process metrics with bounded labels and histogram samples."""

from __future__ import annotations

import math
import threading
from collections import Counter, deque

_COUNTERS = (
    "decisions",
    "chain_verification_failures",
    "pending_decisions",
    "unknown_outcomes",
    "identity_mismatches",
    "writer_conflicts",
    "upstream_errors",
    "upstream_timeouts",
    "auth_failures",
    "approval_required",
    "protocol_failures",
)
_LABEL_VALUES = {
    "tool": {"unknown", "tools_list", "tools_call"},
    "decision": {"allow", "deny", "require_approval", "unknown"},
    "reason": {
        "missing_token",
        "malformed_token",
        "identity_missing",
        "identity_mismatch",
        "unsupported_protocol_version",
        "gateway_unavailable",
        "unknown",
    },
}


class MetricsRegistry:
    def __init__(self, *, sample_limit: int = 2048) -> None:
        if sample_limit < 1:
            raise ValueError("sample_limit must be positive")
        self._lock = threading.Lock()
        self._counters: Counter[tuple[str, tuple[tuple[str, str], ...]]] = Counter()
        self._samples: dict[str, deque[float]] = {
            "policy_latency_seconds": deque(maxlen=sample_limit),
            "receipt_append_latency_seconds": deque(maxlen=sample_limit),
        }

    @staticmethod
    def _labels(labels: dict[str, str]) -> tuple[tuple[str, str], ...]:
        safe: list[tuple[str, str]] = []
        for key in ("tool", "decision", "reason"):
            value = labels.get(key)
            allowed = _LABEL_VALUES[key]
            safe.append((key, value if value in allowed else "unknown"))
        return tuple(safe)

    def increment(self, name: str, amount: int = 1, **labels: str) -> None:
        if name not in _COUNTERS or amount < 0:
            return
        with self._lock:
            self._counters[(name, self._labels(labels))] += amount

    def observe(self, name: str, value: float) -> None:
        if name not in self._samples or not math.isfinite(value) or value < 0:
            return
        with self._lock:
            self._samples[name].append(value)

    def quantile(self, name: str, q: float) -> float:
        if name not in self._samples or not 0 <= q <= 1:
            raise ValueError("unknown histogram or quantile")
        with self._lock:
            values = sorted(self._samples[name])
        if not values:
            return 0.0
        return values[min(len(values) - 1, max(0, math.ceil(q * len(values)) - 1))]

    def render(self) -> str:
        with self._lock:
            counters = list(self._counters.items())
            samples = {name: list(values) for name, values in self._samples.items()}
        lines: list[str] = []
        for name in _COUNTERS:
            metric = f"agentscan_gateway_{name}_total"
            lines.extend(
                (f"# HELP {metric} Gateway {name.replace('_', ' ')}.", f"# TYPE {metric} counter")
            )
            for (counter_name, labels), value in counters:
                if counter_name != name:
                    continue
                label_text = ",".join(f'{key}="{val}"' for key, val in labels if val != "unknown")
                lines.append(
                    f"{metric}{{{label_text}}} {value}" if label_text else f"{metric} {value}"
                )
        for name, values in samples.items():
            metric = f"agentscan_gateway_{name}"
            lines.extend(
                (f"# HELP {metric} Gateway {name.replace('_', ' ')}.", f"# TYPE {metric} summary")
            )
            for quantile, value in (
                ("0.5", self.quantile(name, 0.5)),
                ("0.99", self.quantile(name, 0.99)),
            ):
                lines.append(f'{metric}{{quantile="{quantile}"}} {value}')
            lines.append(f"{metric}_count {len(values)}")
            lines.append(f"{metric}_sum {sum(values)}")
        return "\n".join(lines) + "\n"
