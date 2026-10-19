# agentscan/attacks/registry.py
#
# Auto-discovery system for attack modules.
#
# How it works:
# 1. You drop a .py file anywhere inside agentscan/attacks/scan/, exploit/, or deep/
# 2. Call registry.load_all() once at startup
# 3. Every AttackModule subclass in those files is registered automatically
# 4. No manual registration. No central list to maintain.
#
# This is the same pattern used by pytest (plugin discovery) and Flask (blueprint auto-loading).

from __future__ import annotations

import copy
import importlib
import pkgutil
from types import ModuleType

from loguru import logger

import agentscan.attacks.deep as deep_pkg
import agentscan.attacks.exploit as exploit_pkg
import agentscan.attacks.scan as scan_pkg
from agentscan.attacks.base import AttackModule
from agentscan.core.models import ScanMode, Target


class AttackRegistry:
    """
    Central registry of all available attack modules.
    Singleton — use the module-level `registry` instance.
    """

    def __init__(self) -> None:
        self._modules: dict[str, AttackModule] = {}
        self._loaded = False
        self.load_errors: list[dict[str, str]] = []

    def register(self, module: AttackModule) -> None:
        """Manually register an attack module instance."""
        if module.attack_id in self._modules:
            raise ValueError(f"Duplicate attack ID {module.attack_id!r}")
        self._modules[module.attack_id] = module
        logger.debug(f"Registered: {module!r}")

    def load_all(self) -> None:
        """
        Auto-discover and register all attack modules.
        Scans scan/, exploit/, and deep/ subpackages.
        Safe to call multiple times — only loads once.
        """
        if self._loaded:
            return

        for package in [scan_pkg, exploit_pkg, deep_pkg]:
            self._load_package(package)

        self._loaded = True
        logger.info(f"Registry loaded: {len(self._modules)} attack modules registered.")

    def _load_package(self, package: ModuleType) -> None:
        """Import every module in a subpackage, triggering class registration."""
        for _, module_name, _ in pkgutil.walk_packages(
            path=package.__path__,
            prefix=package.__name__ + ".",
        ):
            try:
                imported = importlib.import_module(module_name)
                # Find all AttackModule subclasses defined in this file
                for attr_name in dir(imported):
                    attr = getattr(imported, attr_name)
                    if (
                        isinstance(attr, type)
                        and issubclass(attr, AttackModule)
                        and attr is not AttackModule
                        and not getattr(attr, "__abstractmethods__", None)
                        and getattr(attr, "__module__", None) == module_name
                    ):
                        self.register(attr())
            except Exception as e:
                if package is deep_pkg and isinstance(e, ModuleNotFoundError) and e.name == "torch":
                    logger.warning(
                        "Optional DEEP module {} is unavailable: torch is not installed. "
                        "Standard scans remain available; install the deep extra for neural checks.",
                        module_name,
                    )
                else:
                    logger.error(f"Failed to load module {module_name!r}: {e}")
                self.load_errors.append(
                    {
                        "module_id": module_name,
                        "module_name": module_name,
                        "error": str(e),
                        "mode": package.__name__.rsplit(".", 1)[-1],
                    }
                )

    def get(self, attack_id: str) -> AttackModule | None:
        """Return a specific module by ID, or None if not found."""
        return self._modules.get(attack_id)

    def get_all(self) -> list[AttackModule]:
        """Return all registered modules."""
        return list(self._modules.values())

    def get_for_target(self, target: Target) -> list[AttackModule]:
        """
        Return only modules applicable to this target.
        Respects is_applicable() and supported_modes on each module.
        """
        # Constructors create independent mutable state; deepcopy preserves
        # explicitly configured plugin instances supplied by callers.
        return self.select_for_target(target)[0]

    def select_for_target(self, target: Target) -> tuple[list[AttackModule], list[dict[str, str]]]:
        """Select independent plugins while retaining individual selection failures."""
        modules = []
        errors = []
        for module in self._modules.values():
            # A baseline requests catalog-only assessment, never dispatch through
            # the server's first tool via another attack module.
            if target.mcp_inventory_baseline is not None and module.attack_id != "ATK-006":
                continue
            if target.factuality_baseline is not None and module.attack_id != "ATK-009":
                continue
            try:
                if module.is_applicable(target):
                    modules.append(copy.deepcopy(module))
            except Exception as exc:
                errors.append(
                    {
                        "module_id": module.attack_id,
                        "module_name": module.attack_name,
                        "error": str(exc) or type(exc).__name__,
                    }
                )
        return modules, errors

    def get_by_mode(self, mode: ScanMode) -> list[AttackModule]:
        """Return all modules that support a specific scan mode."""
        return [m for m in self._modules.values() if mode in m.supported_modes]

    @property
    def count(self) -> int:
        return len(self._modules)

    def __repr__(self) -> str:
        return f"<AttackRegistry modules={self.count} loaded={self._loaded}>"


# ── Module-level singleton ────────────────────────────────────────────────────
# Import this in any file that needs access to attack modules:
#   from agentscan.attacks.registry import registry

registry = AttackRegistry()
