"""Unit tests for ``argus.engine.core.recon_param.SeedParameterizer``.

Covers: token substitution, placeholder resolution, ``meta['recon']``
exposure, no-op semantics on empty profiles, type validation,
determinism contract.
"""

from __future__ import annotations

import pytest

from argus.engine.core.recon_param import SeedParameterizer
from argus.engine.core.recon_profile import ReconProfile
from argus.engine.core.seed import Seed


def _make_seed(template: str, placeholders: dict | None = None) -> Seed:
    return Seed(
        seed_id="test.seed.0",
        attack_class="test-class",
        layer="layer1_tool_poisoning",
        version=1,
        template=template,
        placeholders=placeholders or {},
        target_surface=frozenset({"chat"}),
        meta={},
    )


def test_no_recon_returns_seed_unchanged():
    seed = _make_seed("hello {recon:tool_names}")
    out = SeedParameterizer(None).parameterize(seed)
    assert out is seed


def test_empty_recon_returns_seed_unchanged():
    seed = _make_seed("hello {recon:tool_names}")
    out = SeedParameterizer(ReconProfile.empty()).parameterize(seed)
    assert out is seed


def test_resolves_first_artefact_in_template():
    seed = _make_seed("call {recon:tool_names} with {recon:resource_uris}")
    profile = ReconProfile(
        tool_names=("calculator", "search"),
        resource_uris=("file:///etc/auth",),
    )
    out = SeedParameterizer(profile).parameterize(seed)
    assert out is not seed
    assert "calculator" in out.template
    assert "file:///etc/auth" in out.template
    assert "{recon:" not in out.template


def test_unresolved_token_left_alone():
    seed = _make_seed("call {recon:tool_names} and {recon:auth_boundary_keys}")
    profile = ReconProfile(tool_names=("calc",))
    out = SeedParameterizer(profile).parameterize(seed)
    assert "calc" in out.template
    assert "{recon:auth_boundary_keys}" in out.template


def test_attaches_recon_to_meta():
    seed = _make_seed("noop")
    profile = ReconProfile(tool_names=("calc",))
    out = SeedParameterizer(profile).parameterize(seed)
    assert out.meta.get("recon") is profile


def test_populates_existing_recon_placeholders():
    seed = _make_seed(
        "call {recon:tool_names}",
        placeholders={"recon:tool_names": ("placeholder_default",)},
    )
    profile = ReconProfile(tool_names=("calculator", "search"))
    out = SeedParameterizer(profile).parameterize(seed)
    assert out.placeholders["recon:tool_names"] == ("calculator", "search")


def test_does_not_introduce_new_placeholder_keys():
    seed = _make_seed("noop", placeholders={"foo": ("bar",)})
    profile = ReconProfile(tool_names=("calculator",))
    out = SeedParameterizer(profile).parameterize(seed)
    assert "recon:tool_names" not in out.placeholders
    assert out.placeholders["foo"] == ("bar",)


def test_rejects_non_recon_profile():
    with pytest.raises(TypeError):
        SeedParameterizer({"tool_names": ("calc",)})  # type: ignore[arg-type]


def test_deterministic_same_input_same_output():
    seed = _make_seed("call {recon:tool_names}")
    profile = ReconProfile(tool_names=("calc",))
    a = SeedParameterizer(profile).parameterize(seed)
    b = SeedParameterizer(profile).parameterize(seed)
    assert a.template == b.template
    assert a.meta == b.meta


def test_parameterize_all_returns_same_tuple_when_recon_none():
    seeds = (
        _make_seed("a"),
        _make_seed("b"),
    )
    out = SeedParameterizer(None).parameterize_all(seeds)
    assert out is seeds


def test_parameterize_all_applies_per_seed():
    seeds = (
        _make_seed("first {recon:tool_names}"),
        _make_seed("second {recon:tool_names}"),
    )
    profile = ReconProfile(tool_names=("calculator",))
    out = SeedParameterizer(profile).parameterize_all(seeds)
    assert all("calculator" in s.template for s in out)
