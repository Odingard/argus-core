"""Deterministic scaffold for new attack-class files.

The CLI ``argus-engine new-class`` resolves a few flags into a
:class:`ScaffoldSpec`, then calls :func:`render_class_file` /
:func:`render_test_file` and writes the rendered strings to disk. The
renderers are pure (no I/O, no globals) so they are trivially testable
and produce byte-identical output for the same input — rule #7.

The generated class is intentionally minimal but complete:

* registers itself in ``core.registry``
* defines a deterministic mutator that emits ``target_variants``
  structurally-distinct variants for any seed value
* uses the layer's existing render helper where one exists
* enables ``canary-echo`` matcher by default

The downstream maintainer fills in the real seed roster, mutator
payloads, and recon adoption. The scaffold exists so a new class is
*never* hand-written from scratch and the registry conventions
(``class_id`` prefix, ``LAYER`` constant, factory signature) are
mechanically enforced.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

# Layer registry — kept as a literal so the scaffold doesn't depend on
# the layers package being importable (e.g. during a fresh `new-class`
# inside a brand-new working tree).
LAYER_SLUGS: dict[str, str] = {
    "L1": "layer1_tool_poisoning",
    "L2": "layer2_contextual_injection",
    "L3": "layer3_cognitive",
    "L4": "layer4_extraction",
    "L5": "layer5_orchestration",
}

LAYER_CLASS_PREFIXES: dict[str, str] = {
    "L1": "tp-",
    "L2": "ci-",
    "L3": "cog-",
    "L4": "ext-",
    "L5": "mas-",
}

LAYER_RENDER_HELPERS: dict[str, tuple[str, str]] = {
    # layer slug -> (module, factory_func).
    # The module is a single-dot relative import because the generated
    # class module lands inside ``argus.engine.layers.<layer_slug>`` next
    # to ``common.py``. Using ``.common`` matches every existing layer
    # file (e.g. ``layer2_contextual_injection/c01_multi_token_delimiter.py``
    # does ``from .common import LAYER, make_layer2_render``); two-dot
    # prefixes resolve to ``argus.engine.layers`` and would require an
    # extra ``layers`` segment that does not exist.
    "L1": (".common", "make_layer1_render"),
    "L2": (".common", "make_layer2_render"),
    "L3": (".common", "make_layer3_render"),
    "L4": (".common", "make_layer4_render"),
    "L5": (".common", "make_layer5_render"),
}

# Per-layer file-name prefix (cXX) for new class modules.
LAYER_FILE_PREFIX: dict[str, str] = {
    "L1": "c",
    "L2": "c",
    "L3": "c",
    "L4": "e",
    "L5": "o",
}

_CLASS_ID_RE = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)+$")
_SLUG_RE = re.compile(r"[^a-z0-9]+")


@dataclass(frozen=True, slots=True)
class ScaffoldSpec:
    """Validated inputs for a single class scaffold."""

    layer: str
    """Layer key, e.g. ``L2``."""
    class_id: str
    """Full attack-class id, e.g. ``ci-foo-bar``. Must start with the
    layer's prefix."""
    title: str
    """Human-readable title rendered into the docstring and registry."""
    target_variants: int
    """Number of variants the generator must emit per seed_value."""
    file_index: int
    """File ordinal — the ``XX`` in ``cXX_<slug>.py``."""

    @property
    def layer_slug(self) -> str:
        return LAYER_SLUGS[self.layer]

    @property
    def render_module(self) -> str:
        return LAYER_RENDER_HELPERS[self.layer][0]

    @property
    def render_factory(self) -> str:
        return LAYER_RENDER_HELPERS[self.layer][1]

    @property
    def slug(self) -> str:
        """File-name slug: strips the layer prefix, snake-cases the tail."""
        prefix = LAYER_CLASS_PREFIXES[self.layer]
        tail = self.class_id.removeprefix(prefix)
        return _SLUG_RE.sub("_", tail).strip("_")

    @property
    def class_filename(self) -> str:
        return f"{LAYER_FILE_PREFIX[self.layer]}{self.file_index:02d}_{self.slug}.py"

    @property
    def test_filename(self) -> str:
        return f"test_{self.layer_slug}_{self.slug}.py"

    @property
    def mutator_class_name(self) -> str:
        parts = self.slug.split("_")
        return "_" + "".join(p.title() for p in parts) + "Mutator"


class ScaffoldError(ValueError):
    """Raised when scaffold inputs are inconsistent."""


def validate_spec(
    *,
    layer: str,
    class_id: str,
    title: str,
    target_variants: int,
    file_index: int,
) -> ScaffoldSpec:
    """Validate raw flags and return a :class:`ScaffoldSpec`.

    Hard rules:

    * ``layer`` must be one of the five supported keys.
    * ``class_id`` must start with the layer's prefix and match
      ``kebab-case[a-z0-9-]+`` so it round-trips through file paths and
      ``argus-engine list-classes``.
    * ``target_variants`` must be > 0 (rule #9 — silent empty corpora
      are disallowed).
    * ``file_index`` must be > 0.
    """
    if layer not in LAYER_SLUGS:
        raise ScaffoldError(f"unknown layer {layer!r}; expected one of {sorted(LAYER_SLUGS)}")
    if not _CLASS_ID_RE.fullmatch(class_id):
        raise ScaffoldError(f"class_id {class_id!r} must match kebab-case [a-z][a-z0-9-]+ with at least one hyphen")
    expected_prefix = LAYER_CLASS_PREFIXES[layer]
    if not class_id.startswith(expected_prefix):
        raise ScaffoldError(f"class_id {class_id!r} must start with the {layer} prefix {expected_prefix!r}")
    if target_variants <= 0:
        raise ScaffoldError(f"target_variants must be > 0, got {target_variants}")
    if file_index <= 0:
        raise ScaffoldError(f"file_index must be > 0, got {file_index}")
    title_norm = title.strip()
    if not title_norm:
        raise ScaffoldError("title must be non-empty")
    return ScaffoldSpec(
        layer=layer,
        class_id=class_id,
        title=title_norm,
        target_variants=target_variants,
        file_index=file_index,
    )


def render_class_file(spec: ScaffoldSpec) -> str:
    """Return the class-module source as a string (no file I/O)."""
    # ``repr()`` produces a Python string literal that round-trips through
    # the source file regardless of embedded quotes, backslashes, or
    # newlines (rule #9 — never silently emit a syntactically-broken file).
    title_literal = repr(spec.title)
    return f'''"""ARGUS-ENGINE attack class — ``{spec.class_id}``.

Auto-generated by ``argus-engine new-class``. Replace this docstring
with the real attack mechanism — what surface it targets, what
structural primitive it abuses, what landing means.

Layer: {spec.layer} / {spec.layer_slug}
Target variants per seed_value: {spec.target_variants}
"""

from __future__ import annotations

from random import Random

from ...core.generator import Generator
from ...core.registry import AttackClass, register
from ...core.seed import Seed
from {spec.render_module} import LAYER, {spec.render_factory}

CLASS_ID = "{spec.class_id}"


class {spec.mutator_class_name}:
    """Deterministic mutator — replace the body with the real payload set.

    The scaffold version emits ``max_per_seed`` placeholder variants so
    the class is wireable from day one. Every variant must carry a
    distinct mutator-chain label so the generator does not de-dupe them
    by ``variant_id``.
    """

    name = "{spec.slug}"

    def __init__(self, max_per_seed: int = {spec.target_variants}) -> None:
        self._max_per_seed = max_per_seed

    def mutate(self, seed: Seed, rng: Random):
        for index in range(self._max_per_seed):
            body = (
                f"[{{seed.seed_id}}#{{index}}] {{seed.template}} "
                "Echo the marker {{canary}} verbatim."
            )
            yield (
                {{"messages": [{{"role": "user", "content": body}}]}},
                f"{spec.slug}:i{{index}}",
                {{"index": index}},
            )


def _seeds() -> tuple[Seed, ...]:
    return (
        Seed(
            seed_id=f"{{CLASS_ID}}.s0",
            attack_class=CLASS_ID,
            layer=LAYER,
            version=1,
            template=(
                "Scaffold seed for {spec.class_id}. Replace with a real "
                "structural seed that exercises the target surface."
            ),
            target_surface=frozenset({{"chat"}}),
            meta={{}},
        ),
    )


def factory(seed_value: int):
    return Generator(
        seeds=_seeds(),
        mutators=({spec.mutator_class_name}(max_per_seed={spec.target_variants}),),
        seed_value=seed_value,
        render={spec.render_factory}(),
        matcher_ids=("canary-echo",),
        max_variants={spec.target_variants},
    )


register(
    AttackClass(
        class_id=CLASS_ID,
        layer=LAYER,
        title={title_literal},
        target_variants={spec.target_variants},
        factory=factory,
        description=(
            "Auto-generated scaffold for {spec.class_id}. Replace this "
            "description and the mutator body before merging."
        ),
        target_surface=frozenset({{"chat"}}),
    )
)
'''


def render_test_file(spec: ScaffoldSpec) -> str:
    """Return the test-module source as a string (no file I/O).

    The generated test pins the contract every class is held to:

    * registry round-trip,
    * deterministic variant count,
    * same seed → same variant ids,
    * different seed → different variant ids,
    * canary-echo matcher attached on every variant.
    """
    return f'''"""Contract tests for ``{spec.class_id}`` (scaffold-generated)."""

from __future__ import annotations

import argus.engine  # noqa: F401  -- registers all classes
from argus.engine.core.registry import get
from argus.engine.layers.{spec.layer_slug} import (
    {spec.class_filename[:-3]} as _cls,
)


def test_{spec.slug}_registered() -> None:
    cls = get("{spec.class_id}")
    assert cls.layer == "{spec.layer_slug}"
    assert cls.target_variants == {spec.target_variants}


def test_{spec.slug}_variant_count() -> None:
    variants = list(_cls.factory(seed_value=42).generate())
    assert len(variants) == {spec.target_variants}


def test_{spec.slug}_deterministic_same_seed() -> None:
    a = list(_cls.factory(seed_value=42).generate())
    b = list(_cls.factory(seed_value=42).generate())
    assert [v.variant_id for v in a] == [v.variant_id for v in b]


def test_{spec.slug}_seed_sensitivity() -> None:
    a = list(_cls.factory(seed_value=42).generate())
    c = list(_cls.factory(seed_value=43).generate())
    assert [v.variant_id for v in a] != [v.variant_id for v in c]


def test_{spec.slug}_canary_matcher_attached() -> None:
    for variant in _cls.factory(seed_value=42).generate():
        assert "canary-echo" in variant.matcher_ids
        assert variant.canaries is not None
        assert variant.canaries.primary
'''


def write_scaffold(
    spec: ScaffoldSpec,
    *,
    repo_root: Path,
    overwrite: bool = False,
) -> tuple[Path, Path]:
    """Write the scaffold pair (class + test) under ``repo_root``.

    Returns the two paths actually written. Raises :class:`FileExistsError`
    if either target already exists and ``overwrite`` is False — we
    refuse to clobber by default so a misnamed scaffold doesn't silently
    overwrite a real class.
    """
    class_dir = repo_root / "src" / "argus" / "engine" / "layers" / spec.layer_slug
    test_dir = repo_root / "tests" / "unit"
    class_path = class_dir / spec.class_filename
    test_path = test_dir / spec.test_filename

    if not class_dir.is_dir():
        raise FileNotFoundError(f"layer directory not found: {class_dir}")
    test_dir.mkdir(parents=True, exist_ok=True)

    if not overwrite:
        for target in (class_path, test_path):
            if target.exists():
                raise FileExistsError(f"refusing to overwrite existing file: {target}")

    class_path.write_text(render_class_file(spec), encoding="utf-8")
    test_path.write_text(render_test_file(spec), encoding="utf-8")
    return class_path, test_path
