"""Tests for the third-party attack-class plugin loader."""

from __future__ import annotations

from collections.abc import Iterable

import pytest

import argus.engine  # noqa: F401  -- ensures built-in registry populated
from argus.engine.core import plugins as plugin_mod
from argus.engine.core.generator import Generator
from argus.engine.core.plugins import (
    PLUGIN_GROUP,
    PluginLoadFailure,
    PluginLoadReport,
    autoload_plugins,
)
from argus.engine.core.registry import AttackClass, get
from argus.engine.core.seed import Seed
from argus.engine.layers.layer2_contextual_injection.common import (
    LAYER as LAYER2_LAYER,
)
from argus.engine.layers.layer2_contextual_injection.common import (
    make_layer2_render,
)


def _make_class(class_id: str, *, title: str = "plugin test class") -> AttackClass:
    """Build a minimal but valid AttackClass usable by the registry."""

    class _Mut:
        name = "plugin"

        def mutate(self, seed, rng):  # noqa: ANN001 — duck-typed protocol
            yield (
                {"messages": [{"role": "user", "content": f"{seed.seed_id} {{canary}}"}]},
                "plugin:0",
                {"index": 0},
            )

    def _seeds() -> tuple[Seed, ...]:
        return (
            Seed(
                seed_id=f"{class_id}.s0",
                attack_class=class_id,
                layer=LAYER2_LAYER,
                version=1,
                template="plugin scaffold seed",
                target_surface=frozenset({"chat"}),
                meta={},
            ),
        )

    def factory(seed_value: int) -> Generator:
        return Generator(
            seeds=_seeds(),
            mutators=(_Mut(),),
            seed_value=seed_value,
            render=make_layer2_render(),
            matcher_ids=("canary-echo",),
            max_variants=1,
        )

    return AttackClass(
        class_id=class_id,
        layer=LAYER2_LAYER,
        title=title,
        target_variants=1,
        factory=factory,
        description="plugin test class",
        target_surface=frozenset({"chat"}),
    )


class _FakeEntryPoint:
    """Lightweight stand-in for importlib.metadata.EntryPoint."""

    def __init__(self, name: str, value: str, payload):  # noqa: ANN001
        self.name = name
        self.value = value
        self._payload = payload

    def load(self):  # noqa: ANN001
        if isinstance(self._payload, BaseException):
            raise self._payload
        return self._payload


@pytest.fixture
def isolated_registry(monkeypatch: pytest.MonkeyPatch):
    """Snapshot the registry and restore on teardown."""
    from argus.engine.core import registry as reg

    snapshot = dict(reg._REGISTRY)
    yield reg
    reg._REGISTRY.clear()
    reg._REGISTRY.update(snapshot)


def _install_fake_eps(
    monkeypatch: pytest.MonkeyPatch,
    eps: Iterable[_FakeEntryPoint],
) -> None:
    monkeypatch.setattr(
        plugin_mod,
        "_iter_entry_points",
        lambda group: tuple(sorted(eps, key=lambda ep: (ep.name, ep.value))),
    )


def test_autoload_registers_single_class(monkeypatch: pytest.MonkeyPatch, isolated_registry) -> None:
    cls = _make_class("ci-plugin-single")
    _install_fake_eps(monkeypatch, [_FakeEntryPoint("single", "pkg:CLS", cls)])

    report = autoload_plugins()

    assert isinstance(report, PluginLoadReport)
    assert report.registered == ("ci-plugin-single",)
    assert report.skipped_existing == ()
    assert report.failures == ()
    assert report.discovered == ("single",)
    assert get("ci-plugin-single") is cls


def test_autoload_accepts_iterable_payload(monkeypatch: pytest.MonkeyPatch, isolated_registry) -> None:
    cls_a = _make_class("ci-plugin-bundle-a")
    cls_b = _make_class("ci-plugin-bundle-b")
    _install_fake_eps(
        monkeypatch,
        [_FakeEntryPoint("bundle", "pkg:BUNDLE", [cls_a, cls_b])],
    )

    report = autoload_plugins()

    assert set(report.registered) == {"ci-plugin-bundle-a", "ci-plugin-bundle-b"}
    assert get("ci-plugin-bundle-a") is cls_a
    assert get("ci-plugin-bundle-b") is cls_b


def test_autoload_accepts_zero_arg_factory(monkeypatch: pytest.MonkeyPatch, isolated_registry) -> None:
    cls = _make_class("ci-plugin-factory")
    _install_fake_eps(
        monkeypatch,
        [_FakeEntryPoint("factory", "pkg:make", lambda: cls)],
    )

    report = autoload_plugins()

    assert report.registered == ("ci-plugin-factory",)
    assert report.failures == ()


def test_autoload_captures_load_failure(monkeypatch: pytest.MonkeyPatch, isolated_registry) -> None:
    boom = RuntimeError("import failed")
    _install_fake_eps(monkeypatch, [_FakeEntryPoint("broken", "pkg:nope", boom)])

    report = autoload_plugins()

    assert report.registered == ()
    assert len(report.failures) == 1
    failure = report.failures[0]
    assert isinstance(failure, PluginLoadFailure)
    assert failure.entry_point == "broken"
    assert failure.error_type == "RuntimeError"
    assert "import failed" in failure.error_message


def test_autoload_rejects_non_attack_class_payload(monkeypatch: pytest.MonkeyPatch, isolated_registry) -> None:
    _install_fake_eps(monkeypatch, [_FakeEntryPoint("wrong", "pkg:wrong", 42)])

    report = autoload_plugins()

    assert report.registered == ()
    assert len(report.failures) == 1
    assert report.failures[0].error_type == "TypeError"


def test_autoload_skips_existing_class(monkeypatch: pytest.MonkeyPatch, isolated_registry) -> None:
    # Use an existing built-in class_id so register() raises.
    builtin_id = next(iter(isolated_registry._REGISTRY))
    cls = _make_class(builtin_id, title="duplicate")
    _install_fake_eps(monkeypatch, [_FakeEntryPoint("dup", "pkg:dup", cls)])

    report = autoload_plugins()

    assert report.registered == ()
    assert report.skipped_existing == (builtin_id,)
    assert report.failures == ()


def test_autoload_deterministic_order(monkeypatch: pytest.MonkeyPatch, isolated_registry) -> None:
    cls_z = _make_class("ci-plugin-zeta")
    cls_a = _make_class("ci-plugin-alpha")
    _install_fake_eps(
        monkeypatch,
        [
            _FakeEntryPoint("zeta", "pkg:Z", cls_z),
            _FakeEntryPoint("alpha", "pkg:A", cls_a),
        ],
    )

    report = autoload_plugins()

    # Sort by entry-point name puts alpha before zeta.
    assert report.discovered == ("alpha", "zeta")
    assert report.registered == ("ci-plugin-alpha", "ci-plugin-zeta")


def test_autoload_invokes_on_register_callback(monkeypatch: pytest.MonkeyPatch, isolated_registry) -> None:
    cls = _make_class("ci-plugin-callback")
    _install_fake_eps(monkeypatch, [_FakeEntryPoint("cb", "pkg:CB", cls)])
    seen: list[str] = []

    autoload_plugins(on_register=lambda c: seen.append(c.class_id))

    assert seen == ["ci-plugin-callback"]


def test_plugin_group_constant_is_stable() -> None:
    # Downstream packages key off this exact string in their pyproject.toml.
    assert PLUGIN_GROUP == "argus_engine.classes"


def test_autoload_with_empty_group(monkeypatch: pytest.MonkeyPatch, isolated_registry) -> None:
    _install_fake_eps(monkeypatch, [])

    report = autoload_plugins()

    assert report == PluginLoadReport(
        registered=(),
        skipped_existing=(),
        failures=(),
        discovered=(),
    )
