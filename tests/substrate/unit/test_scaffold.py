"""Tests for the ``argus-engine new-class`` scaffold."""

from __future__ import annotations

import ast
import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner

from argus.engine.cli import main
from argus.engine.core import registry as _registry
from argus.engine.core.scaffold import (
    LAYER_CLASS_PREFIXES,
    LAYER_SLUGS,
    ScaffoldError,
    ScaffoldSpec,
    render_class_file,
    render_test_file,
    validate_spec,
    write_scaffold,
)


def test_validate_spec_happy_path() -> None:
    spec = validate_spec(
        layer="L2",
        class_id="ci-foo-bar",
        title="Foo Bar",
        target_variants=120,
        file_index=12,
    )
    assert isinstance(spec, ScaffoldSpec)
    assert spec.layer_slug == "layer2_contextual_injection"
    assert spec.slug == "foo_bar"
    assert spec.class_filename == "c12_foo_bar.py"
    assert spec.mutator_class_name == "_FooBarMutator"
    assert spec.test_filename == "test_layer2_contextual_injection_foo_bar.py"


@pytest.mark.parametrize(
    ("layer", "expected"),
    [(layer, LAYER_SLUGS[layer]) for layer in sorted(LAYER_SLUGS)],
)
def test_validate_spec_supports_all_layers(layer: str, expected: str) -> None:
    spec = validate_spec(
        layer=layer,
        class_id=f"{LAYER_CLASS_PREFIXES[layer]}thing-a",
        title="t",
        target_variants=1,
        file_index=1,
    )
    assert spec.layer_slug == expected


def test_validate_spec_rejects_unknown_layer() -> None:
    with pytest.raises(ScaffoldError, match="unknown layer"):
        validate_spec(
            layer="L9",
            class_id="ci-foo-bar",
            title="t",
            target_variants=1,
            file_index=1,
        )


def test_validate_spec_rejects_wrong_prefix() -> None:
    with pytest.raises(ScaffoldError, match="must start with"):
        validate_spec(
            layer="L2",
            class_id="tp-foo-bar",
            title="t",
            target_variants=1,
            file_index=1,
        )


def test_validate_spec_rejects_invalid_class_id() -> None:
    with pytest.raises(ScaffoldError, match="kebab-case"):
        validate_spec(
            layer="L2",
            class_id="CI_Foo_Bar",
            title="t",
            target_variants=1,
            file_index=1,
        )


def test_validate_spec_requires_positive_variants() -> None:
    with pytest.raises(ScaffoldError, match="target_variants"):
        validate_spec(
            layer="L2",
            class_id="ci-foo-bar",
            title="t",
            target_variants=0,
            file_index=1,
        )


def test_validate_spec_requires_positive_file_index() -> None:
    with pytest.raises(ScaffoldError, match="file_index"):
        validate_spec(
            layer="L2",
            class_id="ci-foo-bar",
            title="t",
            target_variants=1,
            file_index=0,
        )


def test_validate_spec_requires_non_empty_title() -> None:
    with pytest.raises(ScaffoldError, match="title"):
        validate_spec(
            layer="L2",
            class_id="ci-foo-bar",
            title="   ",
            target_variants=1,
            file_index=1,
        )


def test_render_class_file_is_syntactically_valid() -> None:
    spec = validate_spec(
        layer="L2",
        class_id="ci-foo-bar",
        title="Foo Bar",
        target_variants=12,
        file_index=12,
    )
    source = render_class_file(spec)
    # Parse it — any SyntaxError fails the test.
    tree = ast.parse(source)
    # And the rendered module must declare CLASS_ID at module level.
    names = {
        node.targets[0].id
        for node in tree.body
        if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)
    }
    assert "CLASS_ID" in names


def test_render_test_file_is_syntactically_valid() -> None:
    spec = validate_spec(
        layer="L3",
        class_id="cog-foo-bar",
        title="Cog Foo Bar",
        target_variants=10,
        file_index=9,
    )
    source = render_test_file(spec)
    tree = ast.parse(source)
    funcs = {n.name for n in tree.body if isinstance(n, ast.FunctionDef)}
    # The five contract tests must all exist.
    expected = {
        "test_foo_bar_registered",
        "test_foo_bar_variant_count",
        "test_foo_bar_deterministic_same_seed",
        "test_foo_bar_seed_sensitivity",
        "test_foo_bar_canary_matcher_attached",
    }
    assert expected <= funcs


def test_render_is_deterministic() -> None:
    spec = validate_spec(
        layer="L4",
        class_id="ext-some-thing",
        title="x",
        target_variants=7,
        file_index=8,
    )
    assert render_class_file(spec) == render_class_file(spec)
    assert render_test_file(spec) == render_test_file(spec)


def test_write_scaffold_round_trip(tmp_path: Path) -> None:
    # Build a fake repo skeleton so write_scaffold can land files.
    layer_dir = tmp_path / "src" / "argus" / "engine" / "layers" / "layer2_contextual_injection"
    layer_dir.mkdir(parents=True)
    (tmp_path / "tests" / "unit").mkdir(parents=True)

    spec = validate_spec(
        layer="L2",
        class_id="ci-write-test",
        title="Write Test",
        target_variants=3,
        file_index=99,
    )
    class_path, test_path = write_scaffold(spec, repo_root=tmp_path)

    assert class_path.exists()
    assert test_path.exists()
    assert class_path.name == "c99_write_test.py"
    assert test_path.name == "test_layer2_contextual_injection_write_test.py"

    # py_compile guarantees the file is at least syntactically importable.
    rc = subprocess.run(
        [sys.executable, "-m", "py_compile", str(class_path)],
        check=False,
    ).returncode
    assert rc == 0


def test_generated_scaffold_actually_imports(tmp_path: Path) -> None:
    """Regression for BUG_0001: scaffold relative-import path.

    ``py_compile`` only validates syntax; it never resolves relative
    imports. A broken ``from ..layers.X.common import …`` line therefore
    passes the round-trip test above but explodes the first time the
    catalog tries to import the class. This test forces real import-time
    resolution by spec-loading the rendered file under its true fully-
    qualified module name so Python anchors relative imports against the
    already-loaded ``argus.engine.layers.<slug>`` package.
    """
    layer_dir = tmp_path / "src" / "argus" / "engine" / "layers" / "layer2_contextual_injection"
    layer_dir.mkdir(parents=True)
    (tmp_path / "tests" / "unit").mkdir(parents=True)

    spec = validate_spec(
        layer="L2",
        class_id="ci-regression-import",
        title="Regression Import",
        target_variants=2,
        file_index=96,
    )
    class_path, _ = write_scaffold(spec, repo_root=tmp_path)
    mod_name = f"argus.engine.layers.{spec.layer_slug}.{class_path.stem}"

    # The scaffold's top-level ``register(...)`` call mutates the global
    # registry. The class_id used here cannot collide with the shipped
    # catalog (no real class is named ``ci-regression-import``), so we
    # only need to clean up *that specific entry* on teardown — calling
    # ``_registry.reset()`` would nuke every attack class registered at
    # package-import time and break unrelated tests in the same session.
    assert spec.class_id not in _registry._REGISTRY
    try:
        loader_spec = importlib.util.spec_from_file_location(mod_name, class_path)
        assert loader_spec is not None and loader_spec.loader is not None
        module = importlib.util.module_from_spec(loader_spec)
        try:
            loader_spec.loader.exec_module(module)
        except ModuleNotFoundError as exc:
            pytest.fail(f"Generated scaffold cannot be imported; relative-import path is broken: {exc!r}")

        # Sanity-check the module exposes the expected scaffold surface.
        assert getattr(module, "CLASS_ID") == spec.class_id
        assert callable(getattr(module, "factory"))
        assert spec.class_id in _registry._REGISTRY
    finally:
        _registry._REGISTRY.pop(spec.class_id, None)
        sys.modules.pop(mod_name, None)


def test_render_class_file_handles_special_chars_in_title() -> None:
    """Regression for BUG_0002: ``spec.title`` interpolated raw into a
    Python string literal would emit a syntactically-broken file the
    moment the title contained a double quote, backslash, or newline.

    ``render_class_file`` now uses ``repr(spec.title)`` so the title is
    embedded as a safely-escaped Python string literal. We assert that
    the rendered source parses cleanly **and** that the recovered title
    literal round-trips back to the original value.
    """
    hostile_titles = [
        'Probe "X" via "Y"',
        r"Path\to\exploit",
        "Line 1\nLine 2",
        "Mix 'single' and \"double\" with \\backslash and \n newline",
    ]

    for title in hostile_titles:
        # ScaffoldSpec is frozen — instantiate directly so we keep the
        # exact title (validate_spec would otherwise strip surrounding
        # whitespace, but internal newlines/quotes/backslashes are kept
        # verbatim either way).
        spec = ScaffoldSpec(
            layer="L2",
            class_id="ci-hostile-title",
            title=title,
            target_variants=1,
            file_index=1,
        )
        source = render_class_file(spec)

        # AST parse must succeed — proves no unbalanced quotes/escapes.
        tree = ast.parse(source)

        # Locate the keyword arg ``title=<literal>`` inside the
        # ``register(AttackClass(...))`` call and verify it round-trips.
        recovered: object = None
        for node in ast.walk(tree):
            if isinstance(node, ast.keyword) and node.arg == "title":
                recovered = ast.literal_eval(node.value)
                break
        assert recovered == title, f"title round-trip failed for {title!r}: recovered {recovered!r}"


def test_write_scaffold_refuses_to_clobber(tmp_path: Path) -> None:
    layer_dir = tmp_path / "src" / "argus" / "engine" / "layers" / "layer2_contextual_injection"
    layer_dir.mkdir(parents=True)
    (tmp_path / "tests" / "unit").mkdir(parents=True)

    spec = validate_spec(
        layer="L2",
        class_id="ci-clobber-test",
        title="t",
        target_variants=1,
        file_index=77,
    )
    write_scaffold(spec, repo_root=tmp_path)

    with pytest.raises(FileExistsError):
        write_scaffold(spec, repo_root=tmp_path)


def test_write_scaffold_overwrite_flag(tmp_path: Path) -> None:
    layer_dir = tmp_path / "src" / "argus" / "engine" / "layers" / "layer2_contextual_injection"
    layer_dir.mkdir(parents=True)
    (tmp_path / "tests" / "unit").mkdir(parents=True)

    spec = validate_spec(
        layer="L2",
        class_id="ci-overwrite-test",
        title="t",
        target_variants=1,
        file_index=78,
    )
    class_path, _ = write_scaffold(spec, repo_root=tmp_path)
    original = class_path.read_text()
    # Mutate the target spec slightly to force a different render.
    spec2 = validate_spec(
        layer="L2",
        class_id="ci-overwrite-test",
        title="different title",
        target_variants=2,
        file_index=78,
    )
    write_scaffold(spec2, repo_root=tmp_path, overwrite=True)
    assert class_path.read_text() != original


def test_write_scaffold_missing_layer_dir(tmp_path: Path) -> None:
    # No src/.../layer2_contextual_injection on disk.
    (tmp_path / "tests" / "unit").mkdir(parents=True)
    spec = validate_spec(
        layer="L2",
        class_id="ci-no-layer-dir",
        title="t",
        target_variants=1,
        file_index=80,
    )
    with pytest.raises(FileNotFoundError, match="layer directory"):
        write_scaffold(spec, repo_root=tmp_path)


def test_cli_new_class_happy_path(tmp_path: Path) -> None:
    layer_dir = tmp_path / "src" / "argus" / "engine" / "layers" / "layer2_contextual_injection"
    layer_dir.mkdir(parents=True)
    (tmp_path / "tests" / "unit").mkdir(parents=True)

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "--no-plugins",
            "new-class",
            "--layer",
            "L2",
            "--class-id",
            "ci-cli-test",
            "--title",
            "CLI Test",
            "--file-index",
            "81",
            "--variants",
            "5",
            "--repo-root",
            str(tmp_path),
        ],
    )

    assert result.exit_code == 0, result.output
    assert (layer_dir / "c81_cli_test.py").exists()


def test_cli_new_class_validates_prefix(tmp_path: Path) -> None:
    layer_dir = tmp_path / "src" / "argus" / "engine" / "layers" / "layer2_contextual_injection"
    layer_dir.mkdir(parents=True)
    (tmp_path / "tests" / "unit").mkdir(parents=True)

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "--no-plugins",
            "new-class",
            "--layer",
            "L2",
            "--class-id",
            "tp-bad-prefix",
            "--title",
            "x",
            "--file-index",
            "82",
            "--repo-root",
            str(tmp_path),
        ],
    )
    assert result.exit_code != 0
    assert "must start with" in result.output
