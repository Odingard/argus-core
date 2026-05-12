"""Backwards-compatibility shim — ``argus_engine`` is an alias of ``argus.engine``.

Added in argus-core 1.0.0 when the standalone ARGUS-ENGINE substrate was
folded into argus-core (Φ_Ω of the integration arc; previous home:
``github.com/Odingard/ARGUS-ENGINE``).

Every public symbol is now canonically published under :mod:`argus.engine`.
This shim keeps existing imports of the form ::

    from argus_engine.runtime.supervisor import Supervisor
    from argus_engine.core.registry import get

resolving to the same module object as the canonical ``argus.engine.X``
path so attack-class self-registration (rule #7 determinism, rule #9 no
silent failures) does not fire twice. A naïve ``sys.modules[__name__] =
argus.engine`` alias would re-execute :mod:`argus.engine.layers` on
``argus_engine.layers`` access and trip
:func:`argus.engine.core.registry.register`'s duplicate-id guard with
``ValueError: duplicate registration: ...``.

The shim is implemented as a single
:class:`importlib.abc.MetaPathFinder` that maps ``argus_engine`` and
every ``argus_engine.X.Y.…`` to the corresponding ``argus.engine.X.Y.…``
module object already loaded under the canonical name. The finder is
idempotent — repeated imports of this package leave ``sys.meta_path``
with at most one alias finder.

New code should prefer ``import argus.engine`` directly. This shim is
retained through the argus-core 1.x line and will be removed no earlier
than 2.0.
"""

from __future__ import annotations

import importlib
import importlib.abc
import importlib.machinery
import sys

import argus.engine as _engine  # noqa: F401 -- anchors the canonical package

_OLD_PREFIX = "argus_engine"
_NEW_PREFIX = "argus.engine"


class _EngineAliasLoader(importlib.abc.Loader):
    """Loader that returns the already-executed canonical module."""

    def __init__(self, real_module: object) -> None:
        self._real_module = real_module

    def create_module(self, spec: importlib.machinery.ModuleSpec) -> object:
        del spec
        return self._real_module

    def exec_module(self, module: object) -> None:
        del module
        # Canonical module body already executed under ``argus.engine.*``.


class _EngineAliasFinder(importlib.abc.MetaPathFinder):
    """Map ``argus_engine[.X.Y…]`` → ``argus.engine[.X.Y…]``."""

    def find_spec(
        self,
        fullname: str,
        path: object,
        target: object = None,
    ) -> importlib.machinery.ModuleSpec | None:
        del path, target
        if fullname != _OLD_PREFIX and not fullname.startswith(_OLD_PREFIX + "."):
            return None
        tail = fullname[len(_OLD_PREFIX) :]
        canonical = _NEW_PREFIX + tail
        real = importlib.import_module(canonical)
        sys.modules[fullname] = real
        loader = _EngineAliasLoader(real)
        spec = importlib.machinery.ModuleSpec(fullname, loader)
        spec.has_location = False
        return spec


def _install_finder() -> None:
    """Insert the alias finder at the head of ``sys.meta_path`` (idempotent)."""
    for existing in sys.meta_path:
        if isinstance(existing, _EngineAliasFinder):
            return
    sys.meta_path.insert(0, _EngineAliasFinder())


_install_finder()

# Top-level package alias — keeps ``argus_engine.__version__`` etc. resolving
# to the canonical module object so attribute lookups stay consistent with
# import-statement results.
sys.modules[__name__] = _engine
