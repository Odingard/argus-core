"""PROMETHEUS module registry.

The registry discovers, indexes, and loads PROMETHEUS modules. Modules
auto-register on import via subclass detection.

Usage:
    from argus.prometheus import registry

    # All loaded modules
    print(registry.all())

    # Filter modules
    inj = registry.find(category=ModuleCategory.INJECTION)
    direct = registry.find(subcategory_prefix="direct")
    by_surface = registry.find(target_surface="user_input")

    # Load a specific module by ID
    mod = registry.load("prom-pi-001")
"""

from __future__ import annotations

import importlib
import logging
import pkgutil
from typing import Any

from argus.prometheus.modules import (
    ModuleCategory,
    PrometheusModule,
)

logger = logging.getLogger(__name__)


# Hard restriction — auto-discovered classes must come from this package prefix.
# Prevents a module file from registering classes imported from elsewhere
# (e.g., a malicious file that does `from somewhere import EvilClass`).
ALLOWED_MODULE_PREFIX = "argus.prometheus.modules_lib."


class ModuleCollisionError(RuntimeError):
    """Raised when two PROMETHEUS modules declare the same meta.id."""


class ModuleRegistry:
    """Discovers and indexes all PROMETHEUS modules.

    On first access, walks the `argus.prometheus.modules_lib` namespace
    package and imports every submodule. Each subclass of PrometheusModule
    is auto-registered by ID.
    """

    def __init__(self) -> None:
        self._modules: dict[str, type[PrometheusModule]] = {}
        self._loaded = False

    def _autoload(self) -> None:
        """Walk the modules_lib package and import every module file.

        Each import side-effect-registers PrometheusModule subclasses.
        """
        if self._loaded:
            return

        try:
            from argus.prometheus import modules_lib  # noqa: F401
        except ImportError:
            logger.debug("argus.prometheus.modules_lib not yet present")
            self._loaded = True
            return

        package = modules_lib
        for _, name, _is_pkg in pkgutil.walk_packages(package.__path__, package.__name__ + "."):
            try:
                mod = importlib.import_module(name)
                self._discover_in_module(mod)
            except Exception as exc:
                logger.warning("Failed to import PROMETHEUS module %s: %s", name, exc)

        self._loaded = True
        logger.info("PROMETHEUS registry loaded %d modules", len(self._modules))

    def _discover_in_module(self, module: Any) -> None:
        """Find PrometheusModule subclasses in an imported module.

        Security: only registers classes whose `__module__` starts with
        the allowed prefix (`argus.prometheus.modules_lib.`). This blocks
        a discovered file from registering classes imported from external
        packages.
        """
        for attr_name in dir(module):
            obj = getattr(module, attr_name)
            if not isinstance(obj, type):
                continue
            if not issubclass(obj, PrometheusModule) or obj is PrometheusModule:
                continue
            if obj.__name__.endswith("Module"):
                # skip the abstract bases (InjectionModule, AuxiliaryModule, etc)
                continue
            if not hasattr(obj, "meta") or obj.meta is None:
                continue
            # Restrict to allowed namespace
            if not obj.__module__.startswith(ALLOWED_MODULE_PREFIX):
                logger.warning(
                    "Refusing to register class %s.%s — outside allowed prefix %s",
                    obj.__module__, obj.__name__, ALLOWED_MODULE_PREFIX,
                )
                continue
            self.register(obj)

    def register(self, module_class: type[PrometheusModule]) -> None:
        """Register a module class. Called by autoloader or manually.

        Security: raises ModuleCollisionError on ID collision instead of
        silently dropping — fail-loud rather than silently disable a module
        and let an attacker shadow legitimate modules.
        """
        if not hasattr(module_class, "meta") or module_class.meta is None:
            logger.warning("Module class %s has no meta, skipping", module_class.__name__)
            return

        module_id = module_class.meta.id
        if module_id in self._modules:
            existing = self._modules[module_id]
            if existing is not module_class:
                raise ModuleCollisionError(
                    f"PROMETHEUS module ID collision: '{module_id}' "
                    f"(existing={existing.__module__}.{existing.__name__}, "
                    f"new={module_class.__module__}.{module_class.__name__}). "
                    f"Module IDs must be globally unique."
                )
            return  # idempotent re-registration of the same class

        self._modules[module_id] = module_class
        logger.debug("Registered PROMETHEUS module: %s (%s)", module_id, module_class.meta.name)

    def all(self) -> list[type[PrometheusModule]]:
        """Return all registered module classes."""
        self._autoload()
        return list(self._modules.values())

    def get(self, module_id: str) -> type[PrometheusModule] | None:
        """Get a module class by ID."""
        self._autoload()
        return self._modules.get(module_id)

    def load(self, module_id: str, **options: Any) -> PrometheusModule | None:
        """Get a module by ID and instantiate it with options."""
        cls = self.get(module_id)
        if cls is None:
            return None
        return cls(**options)

    def find(
        self,
        category: ModuleCategory | None = None,
        subcategory: str | None = None,
        subcategory_prefix: str | None = None,
        target_surface: str | None = None,
        technique: str | None = None,
        owasp_agentic: str | None = None,
        requires_llm: bool | None = None,
        requires_session: bool | None = None,
        tags: list[str] | None = None,
        severity: str | None = None,
    ) -> list[type[PrometheusModule]]:
        """Filter modules by metadata.

        All filters are AND-combined. Returns module classes (not instances).
        """
        self._autoload()
        results = list(self._modules.values())

        if category is not None:
            results = [m for m in results if m.meta.category == category]
        if subcategory is not None:
            results = [m for m in results if m.meta.subcategory == subcategory]
        if subcategory_prefix is not None:
            results = [m for m in results if m.meta.subcategory.startswith(subcategory_prefix)]
        if target_surface is not None:
            results = [m for m in results if target_surface in m.meta.target_surfaces]
        if technique is not None:
            results = [m for m in results if m.meta.technique == technique]
        if owasp_agentic is not None:
            results = [m for m in results if m.meta.owasp_agentic == owasp_agentic]
        if requires_llm is not None:
            results = [m for m in results if m.meta.requires_llm == requires_llm]
        if requires_session is not None:
            results = [m for m in results if m.meta.requires_session == requires_session]
        if tags is not None:
            results = [m for m in results if any(t in m.meta.tags for t in tags)]
        if severity is not None:
            results = [m for m in results if m.meta.severity == severity]

        return results

    def stats(self) -> dict[str, Any]:
        """Registry statistics."""
        self._autoload()
        by_category: dict[str, int] = {}
        for m in self._modules.values():
            cat = m.meta.category.value
            by_category[cat] = by_category.get(cat, 0) + 1
        return {
            "total": len(self._modules),
            "by_category": by_category,
            "loaded": self._loaded,
        }

    def reset(self) -> None:
        """Reset the registry — mostly for tests."""
        self._modules.clear()
        self._loaded = False


# Global singleton
registry = ModuleRegistry()
