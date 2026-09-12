# agentscan/swarm/blackboard.py
#
# Shared blackboard memory space for collaborative multi-agent swarms.

from __future__ import annotations

from typing import Any

from agentscan.swarm.models import IntelItem


class SwarmBlackboard:
    """Thread-safe shared intelligence memory for collaborative swarm agents."""

    def __init__(self) -> None:
        self._items: dict[str, IntelItem] = {}
        self._history: list[IntelItem] = []

    def add_intel(
        self,
        key: str,
        value: Any,
        discovered_by: str,
        confidence: float = 1.0,
    ) -> IntelItem:
        """Store or update an intelligence item on the blackboard."""
        item = IntelItem(
            key=key,
            value=value,
            discovered_by=discovered_by,
            confidence=confidence,
        )
        self._items[key] = item
        self._history.append(item)
        return item

    def append_list_intel(self, key: str, item: Any, discovered_by: str) -> None:
        """Append an item to a list-valued intelligence entry."""
        current = self.get_intel(key, default=[])
        if not isinstance(current, list):
            current = [current]
        if item not in current:
            current.append(item)
        self.add_intel(key, current, discovered_by=discovered_by)

    def get_intel(self, key: str, default: Any = None) -> Any:
        """Retrieve the value of an intelligence item."""
        if key in self._items:
            return self._items[key].value
        return default

    def has_intel(self, key: str) -> bool:
        """True if the blackboard contains an entry for key."""
        return key in self._items

    def get_summary(self) -> str:
        """Format a markdown intelligence brief for injection into agent prompts."""
        if not self._items:
            return "No target intelligence collected yet."

        lines = ["### Shared Swarm Intelligence:"]
        for key, item in sorted(self._items.items()):
            val_str = str(item.value)
            if len(val_str) > 200:
                val_str = val_str[:197] + "..."
            lines.append(f"- **{key}** (via {item.discovered_by}): {val_str}")
        return "\n".join(lines)

    def export_dict(self) -> dict[str, Any]:
        """Export all current blackboard intelligence as a dictionary."""
        return {k: item.value for k, item in self._items.items()}

    def get_all_items(self) -> list[IntelItem]:
        """Return all historical intel items."""
        return list(self._history)
