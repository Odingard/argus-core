"""External attack-class plugin discovery.

ARGUS-ENGINE supports third-party attack classes shipped as their own
distributions. A plugin advertises its class(es) via the
``argus_engine.classes`` entry-point group::

    # pyproject.toml of a downstream package
    [project.entry-points."argus_engine.classes"]
    my-class = "my_pkg.my_class:CLASS"
    my-bundle = "my_pkg.bundle:CLASSES"

Each loaded entry-point must resolve to one of:

* an :class:`~argus.engine.core.registry.AttackClass` instance, or
* a callable returning ``AttackClass`` / ``Iterable[AttackClass]``, or
* an iterable of ``AttackClass`` instances.

The loader is deterministic (entry-points are sorted by name before
loading) and rule-#9 compliant — every loaded plugin and every failure
is reported in the structured ``PluginLoadReport`` so callers can audit
which classes were registered and which were rejected.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from importlib.metadata import EntryPoint, entry_points
from typing import Any

from .registry import AttackClass, register

PLUGIN_GROUP = "argus_engine.classes"


@dataclass(frozen=True, slots=True)
class PluginLoadFailure:
    """Structured record of a plugin that failed to load.

    ``error_type`` is the class name of the underlying exception; the
    full message is captured in ``error_message``. We deliberately do
    not re-raise so a single broken third-party plugin cannot disable
    the whole engine — but per rule #9 every failure is surfaced.
    """

    entry_point: str
    """Distribution-qualified name, e.g. ``my-pkg:my-class``."""
    value: str
    """The ``module:attr`` string as declared by the plugin."""
    error_type: str
    error_message: str


@dataclass(frozen=True, slots=True)
class PluginLoadReport:
    """Result of an ``autoload_plugins()`` call.

    ``registered`` is the list of ``class_id`` strings that were
    successfully added to the registry on this invocation (existing
    duplicates are skipped, not re-registered). ``skipped_existing``
    captures the duplicates so callers can distinguish ``"already
    present"`` from ``"failed to load"``. ``failures`` carries any
    structured load errors.
    """

    registered: tuple[str, ...] = ()
    skipped_existing: tuple[str, ...] = ()
    failures: tuple[PluginLoadFailure, ...] = ()
    discovered: tuple[str, ...] = field(default_factory=tuple)
    """All entry-point names found in the group, in deterministic order."""


def _coerce_attack_classes(payload: Any) -> tuple[AttackClass, ...]:
    """Normalise an entry-point payload to a tuple of ``AttackClass``.

    Accepts a single ``AttackClass``, a callable returning one or many,
    or an iterable of them. Any other shape raises ``TypeError``.
    """
    if callable(payload) and not isinstance(payload, AttackClass):
        payload = payload()
    if isinstance(payload, AttackClass):
        return (payload,)
    if isinstance(payload, Iterable):
        items = tuple(payload)
        for item in items:
            if not isinstance(item, AttackClass):
                raise TypeError(f"plugin payload contained non-AttackClass element: {type(item).__name__}")
        return items
    raise TypeError(f"plugin payload is not an AttackClass / iterable / factory: {type(payload).__name__}")


def _iter_entry_points(group: str) -> tuple[EntryPoint, ...]:
    eps = entry_points(group=group)
    # importlib.metadata returns EntryPoints (set-like, unordered prior
    # to 3.10 patches). Sort by (name, value) for deterministic load
    # order across runs — rule #7.
    return tuple(sorted(eps, key=lambda ep: (ep.name, ep.value)))


def autoload_plugins(
    *,
    group: str = PLUGIN_GROUP,
    on_register: Callable[[AttackClass], None] | None = None,
) -> PluginLoadReport:
    """Discover and register every plugin in ``group``.

    Returns a structured :class:`PluginLoadReport`. The function does
    not raise on individual plugin failures — broken plugins are
    captured in ``report.failures`` so the caller (typically the CLI)
    can decide whether to log, warn, or hard-fail.

    ``on_register`` is invoked for every newly-registered class — useful
    for the CLI's ``thought`` channel.
    """
    discovered: list[str] = []
    registered: list[str] = []
    skipped: list[str] = []
    failures: list[PluginLoadFailure] = []

    for ep in _iter_entry_points(group):
        discovered.append(ep.name)
        try:
            loaded = ep.load()
            classes = _coerce_attack_classes(loaded)
        except Exception as exc:  # noqa: BLE001 — defensive, plugin code is third-party
            failures.append(
                PluginLoadFailure(
                    entry_point=ep.name,
                    value=ep.value,
                    error_type=type(exc).__name__,
                    error_message=str(exc),
                )
            )
            continue
        for cls in classes:
            try:
                register(cls)
            except ValueError:
                # Already registered (built-in class with same id, or
                # the same plugin imported twice). Skip silently in the
                # registry, but surface it in the report.
                skipped.append(cls.class_id)
                continue
            registered.append(cls.class_id)
            if on_register is not None:
                on_register(cls)

    return PluginLoadReport(
        registered=tuple(registered),
        skipped_existing=tuple(skipped),
        failures=tuple(failures),
        discovered=tuple(discovered),
    )
