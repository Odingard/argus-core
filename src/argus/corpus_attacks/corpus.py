"""
argus/corpus_attacks/corpus.py — Template / Variant types and Corpus loader.
"""
from __future__ import annotations

import hashlib
import json
import os
import random
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Iterator, Optional


class CorpusError(Exception):
    """Raised on corpus-load failures or duplicate-id collisions."""


# ── Shapes ────────────────────────────────────────────────────────────────────

@dataclass
class Template:
    """
    A hand-written corpus entry. ``id`` must be globally unique across
    every seed file. ``text`` is the verbatim attack string the
    template emits when applied (subject to mutators).
    """
    id:           str
    category:    str          # role_hijack | instruction_override | jailbreak | ...
    text:        str
    tags:        list[str] = field(default_factory=list)
    surfaces:    list[str] = field(default_factory=list)  # user_message / system_prompt / tool_description / ...
    severity:    str = "MEDIUM"
    source:      str = "spec_v1"
    provenance:  str = ""
    notes:       str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Variant:
    """One concrete attack string ready to fire at a target surface."""
    template_id:  str
    mutator:      str                # mutator name; "identity" for unmodified
    text:         str
    category:     str
    severity:     str
    surfaces:     list[str] = field(default_factory=list)
    tags:         list[str] = field(default_factory=list)

    @property
    def fingerprint(self) -> str:
        """SHA-256 of the rendered text — collision = duplicate variant."""
        return hashlib.sha256(self.text.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["fingerprint"] = self.fingerprint
        return d


# ── Corpus ────────────────────────────────────────────────────────────────────

class Corpus:
    """
    Loads every seed JSON in ``seeds_dir`` (defaults to the package's
    ``seeds/`` directory) and exposes templated + mutated variants.
    """

    DEFAULT_SEEDS_DIR = Path(__file__).resolve().parent / "seeds"

    def __init__(
        self,
        seeds_dir:   Optional[str | Path] = None,
        mutators:    Optional[list] = None,
    ) -> None:
        from argus.corpus_attacks.mutators import default_mutators
        self.seeds_dir = Path(seeds_dir) if seeds_dir else self.DEFAULT_SEEDS_DIR
        self.mutators  = list(mutators) if mutators is not None else default_mutators()
        self._templates: list[Template] = []
        self._load()

    # ── Loading ──────────────────────────────────────────────────────────

    def _load(self) -> None:
        if not self.seeds_dir.exists():
            return
        seen_ids: set[str] = set()
        for path in sorted(self.seeds_dir.glob("*.json")):
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as e:
                raise CorpusError(
                    f"corpus seed {path.name} is not valid JSON: {e}"
                ) from e
            if not isinstance(raw, list):
                raise CorpusError(
                    f"corpus seed {path.name} must be a JSON list, "
                    f"got {type(raw).__name__}"
                )
            for entry in raw:
                t = Template(
                    id=entry["id"],
                    category=entry.get("category", path.stem),
                    text=entry["text"],
                    tags=list(entry.get("tags", []) or []),
                    surfaces=list(entry.get("surfaces", []) or []),
                    severity=entry.get("severity", "MEDIUM"),
                    source=entry.get("source", "spec_v1"),
                    provenance=entry.get("provenance", ""),
                    notes=entry.get("notes", ""),
                )
                if t.id in seen_ids:
                    raise CorpusError(
                        f"duplicate template id {t.id!r} (in {path.name})"
                    )
                seen_ids.add(t.id)
                self._templates.append(t)

    # ── Read API ─────────────────────────────────────────────────────────

    @property
    def template_count(self) -> int:
        return len(self._templates)

    def templates(
        self, *,
        category: Optional[str] = None,
        tag:      Optional[str] = None,
        surface:  Optional[str] = None,
    ) -> list[Template]:
        out = list(self._templates)
        if category:
            out = [t for t in out if t.category == category]
        if tag:
            out = [t for t in out if tag in t.tags]
        if surface:
            out = [t for t in out if surface in t.surfaces]
        return out

    def iter_variants(
        self, *,
        category: Optional[str] = None,
        tag:      Optional[str] = None,
        surface:  Optional[str] = None,
    ) -> Iterator[Variant]:
        """
        Yield every variant that passes the filter — one per
        (template, mutator) pair, deduplicated by fingerprint.
        """
        seen: set[str] = set()
        for tmpl in self.templates(category=category, tag=tag, surface=surface):
            for mut in self.mutators:
                try:
                    text = mut.apply(tmpl.text)
                except Exception:
                    continue
                if not text:
                    continue
                v = Variant(
                    template_id=tmpl.id,
                    mutator=mut.name,
                    text=text,
                    category=tmpl.category,
                    severity=tmpl.severity,
                    surfaces=list(tmpl.surfaces),
                    tags=list(tmpl.tags),
                )
                fp = v.fingerprint
                if fp in seen:
                    continue
                seen.add(fp)
                yield v

    def variant_count(self, **filters) -> int:
        return sum(1 for _ in self.iter_variants(**filters))

    def sample(
        self,
        n: int,
        *,
        category: Optional[str] = None,
        tag:      Optional[str] = None,
        surface:  Optional[str] = None,
        seed:     Optional[int] = None,
    ) -> list[Variant]:
        """
        Deterministic random sample of ``n`` variants for the filter.
        Seeded RNG so the same call returns the same variants — useful
        for replay / drift comparison.
        """
        all_v = list(self.iter_variants(
            category=category, tag=tag, surface=surface,
        ))
        if not all_v:
            return []
        if n >= len(all_v):
            return all_v
        rng = random.Random(seed if seed is not None else int.from_bytes(os.urandom(4), "big"))
        return rng.sample(all_v, n)
