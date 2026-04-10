"""PROMETHEUS — ARGUS Attack Module Framework.

PROMETHEUS is the module framework that holds all attack logic for the
ARGUS attack agents. Modeled after Metasploit's module system: each
attack technique is a self-contained module that can be loaded, configured,
fired against a target, and report a result.

Module categories (mirroring Metasploit's structure):
- INJECTION: exploits — payloads that attempt to compromise the target
- PAYLOAD: what executes inside the model after injection succeeds
- AUXILIARY: reconnaissance without exploitation
- POST: post-exploitation — what happens after initial compromise

Each module ships as a Python class subclassing one of the four base
classes, with metadata declared via class attributes.

Usage:
    from argus.prometheus import registry

    # Discover modules
    modules = registry.find(category="injection.direct")

    # Load a specific module
    mod = registry.load("injection.direct.role_hijack_classic")

    # Configure and run
    mod.set_target(target)
    result = await mod.run()
"""

from argus.prometheus.modules import (
    AuxiliaryModule,
    InjectionModule,
    ModuleCategory,
    ModuleMetadata,
    ModuleResult,
    PayloadModule,
    PostExploitationModule,
    PrometheusModule,
)
from argus.prometheus.registry import (
    ALLOWED_MODULE_PREFIX,
    ModuleCollisionError,
    ModuleRegistry,
    registry,
)

__all__ = [
    "ALLOWED_MODULE_PREFIX",
    "AuxiliaryModule",
    "InjectionModule",
    "ModuleCategory",
    "ModuleCollisionError",
    "ModuleMetadata",
    "ModuleRegistry",
    "ModuleResult",
    "PayloadModule",
    "PostExploitationModule",
    "PrometheusModule",
    "registry",
]
