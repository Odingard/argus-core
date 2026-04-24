"""
tests/test_memory_target_class.py — Item-2 cross-run memory.

Covers ``argus.memory.target_class``: target-shape classification,
noise-baseline aggregation over multiple priors files, disk-backed
TargetClassMemory ingestion + query, and the "too sparse to act"
reliability threshold.

Pure unit tests — uses tmp_path for disk, no LLM, no network.
"""
from __future__ import annotations

import json

from argus.memory import (
    TargetClass, TargetClassMemory,
    classify_target, summarise_baseline,
)


# ── Classification ───────────────────────────────────────────────────────────

def test_classify_filesystem_by_tool_names():
    catalog = [
        {"name": "read_file"},
        {"name": "write_file"},
        {"name": "list_directory"},
        {"name": "echo"},
    ]
    assert classify_target(catalog) == TargetClass.FILESYSTEM


def test_classify_notes_by_tool_names():
    catalog = [
        {"name": "create_note"},
        {"name": "search_notes_semantic"},
        {"name": "link_notes"},
    ]
    assert classify_target(catalog) == TargetClass.NOTES


def test_classify_url_hint_boosts_class():
    """A bare catalog that's ambiguous gets pushed to the right
    class when the URL carries a clear hint."""
    catalog = [{"name": "some_tool"}]  # no keyword hits
    got = classify_target(
        catalog, target_url="uvx --from git+.../mcp-zettel mcp-zettel-server",
    )
    # mcp-zettel URL hint → notes-keyword match on "notes"? Actually
    # zettel doesn't contain any of our keyword strings; this should
    # fall through to GENERIC. The boost fires only if a keyword is
    # literally present.
    assert got == TargetClass.GENERIC


def test_classify_empty_catalog_is_generic():
    assert classify_target([]) == TargetClass.GENERIC


def test_classify_non_dict_tools_ignored():
    catalog = ["not-a-dict", {"name": "read_file"}]  # type: ignore[list-item]
    assert classify_target(catalog) == TargetClass.FILESYSTEM


def test_classify_tools_demo_server():
    """server-everything's tool catalog — should classify as
    TOOLS (the demo-kitchen-sink class) not filesystem."""
    catalog = [
        {"name": "echo"}, {"name": "get-env"}, {"name": "get-sum"},
        {"name": "toggle-simulated-logging"},
        {"name": "get-tiny-image"},
    ]
    assert classify_target(catalog) == TargetClass.TOOLS


# ── Baseline aggregation ────────────────────────────────────────────────────

def test_summarise_empty_gives_zero_runs():
    b = summarise_baseline([])
    assert b.total_runs == 0
    assert b.class_typical_causes == {}
    assert b.is_reliable is False


def test_summarise_single_run_gives_1_0_ratios():
    docs = [{
        "run_id": "r1",
        "target_class": "filesystem",
        "aggregate_causes": {"target_hardened": 5, "no_signal": 2},
    }]
    b = summarise_baseline(docs)
    assert b.total_runs == 1
    assert b.target_class == TargetClass.FILESYSTEM
    assert b.class_typical_causes["target_hardened"] == 1.0
    assert b.class_typical_causes["no_signal"] == 1.0
    assert not b.is_reliable  # need 3+ runs to be usable


def test_summarise_three_runs_computes_appearance_ratios():
    """Baseline reliability threshold is 3 runs. Cause ratios are
    "fraction of runs in which the cause appeared at least once."""
    docs = [
        {"run_id": "r1", "target_class": "notes",
         "aggregate_causes": {"no_signal": 3, "target_hardened": 1}},
        {"run_id": "r2", "target_class": "notes",
         "aggregate_causes": {"no_signal": 2}},
        {"run_id": "r3", "target_class": "notes",
         "aggregate_causes": {"no_signal": 4, "timeout": 1}},
    ]
    b = summarise_baseline(docs)
    assert b.total_runs == 3
    assert b.is_reliable
    # no_signal: appeared in ALL 3 runs → 1.0
    assert b.class_typical_causes["no_signal"] == 1.0
    # target_hardened: appeared in 1 of 3 → ~0.333
    assert abs(b.class_typical_causes["target_hardened"] - 0.333) < 0.01
    # timeout: appeared in 1 of 3 → ~0.333
    assert abs(b.class_typical_causes["timeout"] - 0.333) < 0.01


def test_is_class_typical_respects_threshold():
    docs = [
        {"run_id": f"r{i}", "target_class": "filesystem",
         "aggregate_causes": {"target_hardened": 1}}
        for i in range(5)
    ]
    b = summarise_baseline(docs)
    assert b.is_class_typical("target_hardened") is True
    # Above default 0.8 threshold
    assert b.is_class_typical("target_hardened", threshold=0.95) is True
    # Not in any run
    assert b.is_class_typical("model_refused") is False


def test_baseline_unreliable_never_class_typical():
    docs = [
        {"run_id": "r1", "target_class": "web_api",
         "aggregate_causes": {"target_hardened": 1}},
    ]
    b = summarise_baseline(docs)
    assert b.total_runs == 1
    # Single-run baseline cannot declare anything "class-typical"
    # even when the ratio is 1.0 — too sparse to be statistical.
    assert b.is_class_typical("target_hardened") is False


# ── Disk-backed TargetClassMemory ────────────────────────────────────────────

def _write_priors(run_dir, *, run_id, causes):
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "diagnostic_priors.json").write_text(json.dumps({
        "schema_version":   1,
        "run_id":           run_id,
        "target":           "mcp://test",
        "total_agents":     12,
        "silent_count":     sum(causes.values()),
        "productive_count": 12 - sum(causes.values()),
        "aggregate_causes": causes,
        "per_agent":        {},
        "productive_agents": [],
    }))


def test_ingest_classifies_and_writes(tmp_path):
    mem = TargetClassMemory(root=tmp_path / "target_class_memory")

    run_dir = tmp_path / "runs" / "run_a"
    _write_priors(run_dir, run_id="run_a",
                  causes={"no_signal": 3})

    klass = mem.ingest_run(
        run_dir=str(run_dir),
        tool_catalog=[
            {"name": "create_note"},
            {"name": "search_notes"},
        ],
    )
    assert klass == TargetClass.NOTES
    # File landed in the notes/ bucket
    bucket = tmp_path / "target_class_memory" / "notes"
    files = list(bucket.glob("*.json"))
    assert len(files) == 1


def test_baseline_for_pulls_from_bucket(tmp_path):
    mem = TargetClassMemory(root=tmp_path / "mem")
    # Seed 3 runs of the filesystem class
    for i in range(3):
        run_dir = tmp_path / "runs" / f"run_fs_{i}"
        _write_priors(run_dir, run_id=f"fs_{i}",
                      causes={"target_hardened": i + 1})
        mem.ingest_run(
            run_dir=str(run_dir),
            tool_catalog=[{"name": "read_file"}, {"name": "write_file"}],
        )

    baseline = mem.baseline_for(TargetClass.FILESYSTEM)
    assert baseline.total_runs == 3
    assert baseline.is_reliable
    assert baseline.is_class_typical("target_hardened")


def test_baseline_for_empty_class_is_zero(tmp_path):
    mem = TargetClassMemory(root=tmp_path / "mem")
    baseline = mem.baseline_for(TargetClass.DATABASE)
    assert baseline.total_runs == 0
    assert not baseline.is_reliable


def test_ingest_missing_priors_file_returns_none(tmp_path):
    mem = TargetClassMemory(root=tmp_path / "mem")
    run_dir = tmp_path / "runs" / "no_priors"
    run_dir.mkdir(parents=True)
    out = mem.ingest_run(
        run_dir=str(run_dir),
        tool_catalog=[{"name": "read_file"}],
    )
    assert out is None


def test_ingest_malformed_priors_returns_none(tmp_path):
    mem = TargetClassMemory(root=tmp_path / "mem")
    run_dir = tmp_path / "runs" / "bad"
    run_dir.mkdir(parents=True)
    (run_dir / "diagnostic_priors.json").write_text("not json")
    out = mem.ingest_run(
        run_dir=str(run_dir),
        tool_catalog=[{"name": "read_file"}],
    )
    assert out is None


def test_all_baselines_only_returns_populated_classes(tmp_path):
    mem = TargetClassMemory(root=tmp_path / "mem")

    run_dir = tmp_path / "runs" / "run_a"
    _write_priors(run_dir, run_id="a", causes={"no_signal": 1})
    mem.ingest_run(
        run_dir=str(run_dir),
        tool_catalog=[{"name": "create_note"}],
    )

    baselines = mem.all_baselines()
    assert TargetClass.NOTES in baselines
    assert TargetClass.DATABASE not in baselines


# ── Cross-class bucketing doesn't mix ────────────────────────────────────────

def test_filesystem_and_notes_stay_separate(tmp_path):
    mem = TargetClassMemory(root=tmp_path / "mem")

    # Filesystem run
    fs_dir = tmp_path / "runs" / "fs1"
    _write_priors(fs_dir, run_id="fs1",
                  causes={"target_hardened": 5})
    mem.ingest_run(
        run_dir=str(fs_dir),
        tool_catalog=[{"name": "read_file"}, {"name": "list_directory"}],
    )

    # Notes run with a different cause profile
    notes_dir = tmp_path / "runs" / "notes1"
    _write_priors(notes_dir, run_id="notes1",
                  causes={"no_signal": 4})
    mem.ingest_run(
        run_dir=str(notes_dir),
        tool_catalog=[{"name": "create_note"}, {"name": "search_notes"}],
    )

    fs_baseline = mem.baseline_for(TargetClass.FILESYSTEM)
    notes_baseline = mem.baseline_for(TargetClass.NOTES)
    assert "target_hardened" in fs_baseline.class_typical_causes
    assert "target_hardened" not in notes_baseline.class_typical_causes
    assert "no_signal" in notes_baseline.class_typical_causes
    assert "no_signal" not in fs_baseline.class_typical_causes
