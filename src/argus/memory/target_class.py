"""
argus/memory/target_class.py — target-class noise baselines.

Reads every ``diagnostic_priors.json`` the outer loop has written,
classifies each run's target by shape (filesystem / notes / search
/ database / api / generic), and emits a per-class baseline of
what causes + cause frequencies are TYPICAL for that class.

On the next engagement, the recon phase loads the baseline for the
detected target class and passes it to the calibrator as a
suppression hint: a SilenceCause that shows up in ≥80% of prior
class runs is class-typical noise, not fresh signal.

Design tenets:

  - Pure. Reads JSON files; writes JSON files. No LLM in path.
  - Incremental. Adding a new run is O(1) — append to the class
    bucket and recompute ratios, don't rescan everything.
  - Conservative. Suppression only fires when a cause appears on
    ≥80% of prior runs in a class AND there are ≥3 prior runs.
    Fewer than 3 runs → unknown class, no suppression.
  - Testable. The classifier + aggregator are separate from the
    disk I/O, so unit tests can feed synthetic priors.

What this doesn't do:

  - No mutation-search. Just counts and classifies.
  - No cross-class generalisation. "filesystem" and "database"
    baselines are kept separate even if they share patterns.
  - No LLM-driven class detection. Heuristic keywords over tool
    catalog names — deterministic and fast.
"""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Iterable, Optional


# ── Target-class taxonomy ────────────────────────────────────────────────────

class TargetClass(str, Enum):
    """Shape categorisation of an MCP target. Derived from the tool
    catalog + URL — deterministic, no LLM."""
    FILESYSTEM = "filesystem"   # read_file, write_file, list_dir, etc.
    NOTES      = "notes"         # create_note, search_notes, link_notes
    SEARCH     = "search"        # search, query, retrieve (not notes)
    DATABASE   = "database"      # sql, db, query_db, select
    WEB_API    = "web_api"       # fetch, http, api_call
    TOOLS      = "tools"         # echo, toggle, log — demo kitchen-sink
    GENERIC    = "generic"       # falls through everything


# Keyword → class map. First match wins per tool name; the class with
# the most hits across the full catalog wins the target.
_CLASS_KEYWORDS: dict[TargetClass, tuple[str, ...]] = {
    TargetClass.FILESYSTEM: (
        "read_file", "write_file", "list_dir", "list_directory",
        "create_directory", "move_file", "delete_file",
        "get_file_info", "directory_tree", "search_files",
    ),
    TargetClass.NOTES: (
        "create_note", "read_note", "update_note", "delete_note",
        "list_notes", "search_notes", "link_notes", "get_backlinks",
        "linked_notes", "suggest_links",
    ),
    TargetClass.SEARCH: (
        "search", "query", "lookup", "retrieve", "find",
        "semantic",
    ),
    TargetClass.DATABASE: (
        "sql", "select", "insert", "update_row", "delete_row",
        "query_db", "db_", "database_",
    ),
    TargetClass.WEB_API: (
        "fetch_url", "http_get", "api_call", "web_fetch",
        "fetch_web",
    ),
    TargetClass.TOOLS: (
        "echo", "toggle", "simulate", "get-env", "get-sum",
        "get-tiny-image", "get-resource-",
    ),
}


def classify_target(
    tool_catalog: list[dict],
    *,
    target_url: Optional[str] = None,
) -> TargetClass:
    """Classify a target by its tool catalog + URL hint.

    Pure function. Scans every tool name for keywords in
    ``_CLASS_KEYWORDS``; the class with the most hits wins. Ties
    are broken by declaration order in the enum (filesystem > notes
    > search > database > web_api > tools > generic). URL hints
    (e.g. ``mcp-zettel`` in the URL → NOTES) add a small boost."""
    if not tool_catalog:
        return TargetClass.GENERIC

    scores: Counter[TargetClass] = Counter()
    for tool in tool_catalog:
        if not isinstance(tool, dict):
            continue
        name = (tool.get("name") or "").lower()
        if not name:
            continue
        for klass, kwds in _CLASS_KEYWORDS.items():
            if any(k in name for k in kwds):
                scores[klass] += 1

    # URL hint — a target URL that contains a class-keyword bumps
    # that class by 2 (stronger than a single tool-name hit).
    if target_url:
        low = target_url.lower()
        for klass, kwds in _CLASS_KEYWORDS.items():
            if any(k.replace("_", "-") in low for k in kwds):
                scores[klass] += 2

    if not scores:
        return TargetClass.GENERIC
    # Enum declaration order is the tiebreak.
    enum_order = list(TargetClass)
    ranked = sorted(
        scores.items(),
        key=lambda kv: (-kv[1], enum_order.index(kv[0])),
    )
    return ranked[0][0]


# ── Baseline ─────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class NoiseBaseline:
    """Per-target-class statistics derived from N prior runs.

    ``class_typical_causes`` maps SilenceCause -> ratio of runs in
    which that cause appeared at least once. Causes at ≥0.8 are
    considered class-typical noise for suppression purposes.

    ``total_runs`` is the number of prior runs aggregated; fewer
    than 3 makes the baseline too sparse to act on (the consumer
    should fall back to no suppression)."""
    target_class:           TargetClass
    total_runs:             int
    class_typical_causes:   dict[str, float] = field(default_factory=dict)
    sample_run_ids:         tuple[str, ...] = field(default_factory=tuple)

    @property
    def is_reliable(self) -> bool:
        return self.total_runs >= 3

    def is_class_typical(
        self, cause: str, *, threshold: float = 0.8,
    ) -> bool:
        if not self.is_reliable:
            return False
        return self.class_typical_causes.get(cause, 0.0) >= threshold


def summarise_baseline(priors_docs: Iterable[dict]) -> NoiseBaseline:
    """Build a single-class NoiseBaseline from an iterable of
    ``diagnostic_priors.json`` documents — caller has already
    filtered to one class. Aggregates cause counts across runs and
    computes ratios."""
    docs = list(priors_docs)
    n = len(docs)
    if n == 0:
        return NoiseBaseline(
            target_class=TargetClass.GENERIC, total_runs=0,
        )

    # For each run, which causes appeared at least once?
    appearance: Counter[str] = Counter()
    run_ids: list[str] = []
    target_classes: Counter[TargetClass] = Counter()
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        run_id = doc.get("run_id", "")
        if run_id:
            run_ids.append(str(run_id))
        tc_raw = doc.get("target_class")
        if isinstance(tc_raw, str):
            try:
                target_classes[TargetClass(tc_raw)] += 1
            except ValueError:
                pass
        for cause in (doc.get("aggregate_causes") or {}).keys():
            appearance[cause] += 1

    # Ratios — how many runs saw this cause at least once?
    ratios = {c: round(count / n, 3) for c, count in appearance.items()}

    # Target class — dominant class across the docs, or GENERIC if
    # none was recorded.
    dominant_class = (
        target_classes.most_common(1)[0][0]
        if target_classes else TargetClass.GENERIC
    )

    return NoiseBaseline(
        target_class=dominant_class,
        total_runs=n,
        class_typical_causes=ratios,
        sample_run_ids=tuple(run_ids[:10]),
    )


# ── TargetClassMemory (disk-backed aggregate) ────────────────────────────────

class TargetClassMemory:
    """Disk-backed aggregator over many engagements' priors files.

    Typical flow::

        mem = TargetClassMemory(root="~/.argus/target_class_memory")
        mem.ingest_run(
            run_dir="results/live/zettel-v3",
            tool_catalog=report.server_profile.tools,
            target_url="uvx --from git+... mcp-zettel-server",
        )
        baseline = mem.baseline_for(TargetClass.NOTES)
        if baseline.is_reliable and baseline.is_class_typical("no_signal"):
            # suppress class-typical "no_signal" downgrades

    Layout on disk::

        <root>/
          filesystem/
            run_<id>.json     # copy of diagnostic_priors.json
            ...
          notes/
          search/
          ...

    Fully graceful — missing dirs, missing priors, unknown classes
    all fall through to an empty baseline rather than raising."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).expanduser()
        self.root.mkdir(parents=True, exist_ok=True)

    # ── Ingest ──────────────────────────────────────────────────────

    def ingest_run(
        self,
        *,
        run_dir:      str | Path,
        tool_catalog: list[dict],
        target_url:   Optional[str] = None,
    ) -> Optional[TargetClass]:
        """Classify the run's target and copy its priors doc into
        the class bucket. No-op if the run_dir doesn't have a
        priors file yet. Returns the classified TargetClass, or
        None if nothing was ingested."""
        priors_path = Path(run_dir).expanduser() / "diagnostic_priors.json"
        if not priors_path.is_file():
            return None
        try:
            doc = json.loads(priors_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        klass = classify_target(tool_catalog, target_url=target_url)
        # Stamp the class into the copy for future readers.
        doc["target_class"] = klass.value
        # Run-id namespaced file name.
        run_id = doc.get("run_id") or Path(run_dir).name
        class_dir = self.root / klass.value
        class_dir.mkdir(parents=True, exist_ok=True)
        out = class_dir / f"{run_id}.json"
        try:
            out.write_text(
                json.dumps(doc, indent=2, default=str),
                encoding="utf-8",
            )
        except OSError:
            return None
        return klass

    # ── Query ───────────────────────────────────────────────────────

    def baseline_for(
        self, target_class: TargetClass,
    ) -> NoiseBaseline:
        """Load all priors in the class bucket and summarise. Empty
        baseline for unknown or under-populated classes."""
        class_dir = self.root / target_class.value
        if not class_dir.is_dir():
            return NoiseBaseline(
                target_class=target_class, total_runs=0,
            )
        docs: list[dict] = []
        for p in sorted(class_dir.glob("*.json")):
            try:
                docs.append(json.loads(p.read_text(encoding="utf-8")))
            except (OSError, json.JSONDecodeError):
                continue
        baseline = summarise_baseline(docs)
        # Override target_class so unknown-class documents don't
        # override the directory's class.
        return NoiseBaseline(
            target_class=target_class,
            total_runs=baseline.total_runs,
            class_typical_causes=baseline.class_typical_causes,
            sample_run_ids=baseline.sample_run_ids,
        )

    def all_baselines(self) -> dict[TargetClass, NoiseBaseline]:
        """Compute baselines for every class that has at least one
        recorded run. Useful for the ``argus --memory-report``
        flag (future)."""
        out: dict[TargetClass, NoiseBaseline] = {}
        for klass in TargetClass:
            b = self.baseline_for(klass)
            if b.total_runs > 0:
                out[klass] = b
        return out


# ── Helpers ──────────────────────────────────────────────────────────────────

def _bucket_priors_by_class(
    priors_docs: Iterable[dict],
) -> dict[TargetClass, list[dict]]:
    """Group docs by the target_class stamped in each (or GENERIC
    if unstamped). Used by tests + ad-hoc analysis."""
    by_class: dict[TargetClass, list[dict]] = defaultdict(list)
    for doc in priors_docs:
        if not isinstance(doc, dict):
            continue
        tc_raw = doc.get("target_class")
        if isinstance(tc_raw, str):
            try:
                by_class[TargetClass(tc_raw)].append(doc)
                continue
            except ValueError:
                pass
        by_class[TargetClass.GENERIC].append(doc)
    return dict(by_class)
