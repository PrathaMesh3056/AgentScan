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

import importlib
import pkgutil

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

    def register(self, module: AttackModule) -> None:
        """Manually register an attack module instance."""
        if module.attack_id in self._modules:
            logger.warning(
                f"Attack ID {module.attack_id!r} already registered. "
                f"Overwriting {self._modules[module.attack_id].__class__.__name__} "
                f"with {module.__class__.__name__}."
            )
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

    def _load_package(self, package: object) -> None:
        """Import every module in a subpackage, triggering class registration."""
        for _, module_name, _ in pkgutil.walk_packages(
            path=package.__path__,  # type: ignore[attr-defined]
            prefix=package.__name__ + ".",  # type: ignore[attr-defined]
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
                    ):
                        self.register(attr())
            except Exception as e:
                logger.error(f"Failed to load module {module_name!r}: {e}")

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
        return [m for m in self._modules.values() if m.is_applicable(target)]

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
