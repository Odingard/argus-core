"""Parse a forensic JSONL run-log into an :class:`EngagementReport`.

The reader is intentionally tolerant of:

* unrecognised event ``type`` values (ignored — forward-compatible);
* malformed JSON lines (skipped + counted, never raised — a corrupt
  tail must not lose the rest of the run, AGENTS.md rule #9);
* missing optional metadata (the engagement may have crashed before
  the ``done`` event — partial reports are still valuable).

Deterministic ordering across all collections (AGENTS.md rule #7):

* ``classes`` sorted by ``attack_class``.
* ``findings`` sorted by ``(tier_rank, attack_class, variant_id)`` so
  IRREFUTABLE rows always lead.
* ``refusals`` sorted by descending occurrences, then signature.
* ``fallbacks`` sorted by ``(attack_class, recon_variant_id)``.
* ``emergence_links`` sorted by ``(chain_id, producer_class)``.
"""

from __future__ import annotations

import contextlib
import json
from collections import Counter, defaultdict
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

from .model import (
    TIER_ORDER,
    ChainEmergenceLink,
    ClassRollup,
    EngagementReport,
    FallbackEvent,
    FindingRow,
    RefusalRow,
    RunMetadata,
)

# Findings below this tier are dropped from the report's top-level
# ``findings`` tuple to keep the artefact focused on auditable events
# (AGENTS.md: external reports include only IRREFUTABLE + HIGH; we
# additionally keep MEDIUM as internal signal — LOW is statistical
# anomaly only and not actionable).
_KEPT_TIERS = ("IRREFUTABLE", "HIGH", "MEDIUM")

_TIER_RANK = {tier: idx for idx, tier in enumerate(TIER_ORDER)}


def parse_jsonl(path: Path | str) -> EngagementReport:
    """Read a JSONL file from disk and project it into a report."""
    path = Path(path)
    return parse_jsonl_text(path.read_text(encoding="utf-8"))


def parse_jsonl_text(text: str) -> EngagementReport:
    """Project an in-memory JSONL string into a report.

    Useful for tests and for piping forensic runs through stdin.
    """
    return _build_report(_iter_events(text.splitlines()))


def _iter_events(lines: Iterable[str]) -> Iterator[dict[str, Any]]:
    for raw in lines:
        raw = raw.strip()
        if not raw:
            continue
        try:
            event = json.loads(raw)
        except json.JSONDecodeError:
            # AGENTS.md rule #9: malformed lines must be explainable
            # at the source. We surface them as a synthetic event so
            # downstream readers can count them if they care, but we
            # do not raise — the rest of the run is still valuable.
            yield {"type": "_malformed", "raw": raw}
            continue
        if isinstance(event, dict):
            yield event


def _build_report(events: Iterator[dict[str, Any]]) -> EngagementReport:
    fire_counts: Counter[str] = Counter()
    landed_counts: Counter[str] = Counter()
    tier_counts: dict[str, Counter[str]] = defaultdict(Counter)
    top_lethality: dict[str, float] = defaultdict(float)
    findings: list[FindingRow] = []
    refusal_counter: Counter[str] = Counter()
    fallbacks: list[FallbackEvent] = []
    emergence_links: list[ChainEmergenceLink] = []

    target = "<unknown>"
    transport = "<unknown>"
    layer = "<unknown>"
    seed = 0
    duration = 0.0
    total_fired = 0
    total_findings = 0
    rehydrated = False
    fingerprint_id: str | None = None

    # Phase N — continuous-gradient signal samples per fire event.
    signal_samples: list[float] = []
    signal_summary: dict[str, float] = {}
    # Phase O — diversity gate counters from the engagement.
    diversity_stats: dict[str, int] = {}
    # Phase P — carrier-surface histogram.
    carrier_histogram: Counter[str] = Counter()
    # Phase Q — arc execution summary.
    arc_summary: dict[str, object] = {}

    for event in events:
        kind = event.get("type")
        if kind == "fire":
            class_id = str(event.get("attack_class", "<unknown>"))
            fire_counts[class_id] += 1
            with contextlib.suppress(TypeError, ValueError):
                top_lethality[class_id] = max(top_lethality[class_id], float(event.get("lethality", 0.0)))
            if event.get("landed"):
                landed_counts[class_id] += 1
            sig_raw = event.get("signal_strength")
            if isinstance(sig_raw, dict):
                with contextlib.suppress(TypeError, ValueError):
                    signal_samples.append(float(sig_raw.get("strength", 0.0)))
        elif kind == "finding":
            class_id = str(event.get("attack_class", "<unknown>"))
            tier = str(event.get("confidence", "LOW"))
            tier_counts[class_id][tier] += 1
            if tier in _KEPT_TIERS:
                evidence_raw = event.get("evidence")
                evidence_dict: dict[str, object]
                evidence_dict = dict(evidence_raw) if isinstance(evidence_raw, dict) else {}
                try:
                    lethality = float(event.get("lethality", 0.0))
                except (TypeError, ValueError):
                    lethality = 0.0
                try:
                    generation = int(event.get("generation", 0))
                except (TypeError, ValueError):
                    generation = 0
                findings.append(
                    FindingRow(
                        variant_id=str(event.get("variant_id", "")),
                        attack_class=class_id,
                        confidence=tier,
                        lethality=lethality,
                        phase=str(event.get("phase", "")),
                        generation=generation,
                        evidence=evidence_dict,
                    )
                )
        elif kind == "refusal":
            sig = event.get("signature")
            if isinstance(sig, str) and sig:
                refusal_counter[sig] += 1
        elif kind == "recon_plausibility_fallback":
            fallbacks.append(_parse_fallback(event))
        elif kind == "emergence_report":
            emergence_links.extend(_parse_emergence(event))
        elif kind == "phase":
            phase_name = event.get("phase")
            if phase_name == "rehydrate" and event.get("outcome") == "hit":
                rehydrated = True
                fp = event.get("fingerprint_id")
                if isinstance(fp, str):
                    fingerprint_id = fp
        elif kind == "engagement_memory_persisted":
            fp = event.get("fingerprint_id")
            if isinstance(fp, str) and fingerprint_id is None:
                fingerprint_id = fp
        elif kind == "signal_strength_summary":
            for key in ("count", "mean", "max", "p50", "p90", "p99"):
                if key in event:
                    with contextlib.suppress(TypeError, ValueError):
                        signal_summary[key] = float(event[key])
        elif kind == "diversity_stats":
            for key in ("observed", "accepted", "rejected"):
                if key in event:
                    with contextlib.suppress(TypeError, ValueError):
                        diversity_stats[key] = int(event[key])
        elif kind == "carrier_histogram":
            counts = event.get("counts")
            if isinstance(counts, dict):
                for surface, n in counts.items():
                    with contextlib.suppress(TypeError, ValueError):
                        carrier_histogram[str(surface)] += int(n)
        elif kind == "arc_summary":
            for key in (
                "arcs",
                "completed",
                "aborted",
                "total_rewinds",
                "stage_reach_counts",
            ):
                if key in event:
                    arc_summary[key] = event[key]
        elif kind == "engagement_started":
            target = str(event.get("target", target))
            transport = str(event.get("transport", transport))
            layer = str(event.get("layer", layer))
            with contextlib.suppress(TypeError, ValueError):
                seed = int(event.get("seed", seed))
        elif kind == "done":
            with contextlib.suppress(TypeError, ValueError):
                duration = float(event.get("duration_seconds", duration))
            with contextlib.suppress(TypeError, ValueError):
                total_fired = int(event.get("fired", total_fired))
            with contextlib.suppress(TypeError, ValueError):
                total_findings = int(event.get("findings", total_findings))

    # ------------------------------------------------------------------
    # Materialise the deterministic, sorted output collections.
    # ------------------------------------------------------------------
    class_ids = sorted(set(fire_counts) | set(tier_counts))
    classes = tuple(
        ClassRollup(
            attack_class=cid,
            fired=fire_counts.get(cid, 0),
            landed=landed_counts.get(cid, 0),
            tier_counts=dict(sorted(tier_counts.get(cid, Counter()).items())),
            top_lethality=top_lethality.get(cid, 0.0),
        )
        for cid in class_ids
    )

    findings.sort(
        key=lambda f: (
            _TIER_RANK.get(f.confidence, len(TIER_ORDER)),
            f.attack_class,
            f.variant_id,
        )
    )

    refusals = tuple(
        RefusalRow(signature=sig, occurrences=n)
        for sig, n in sorted(refusal_counter.items(), key=lambda kv: (-kv[1], kv[0]))
    )

    fallbacks.sort(key=lambda fb: (fb.attack_class, fb.recon_variant_id))
    emergence_links.sort(key=lambda link: (link.chain_id, link.producer_class))

    # Phase N — if the run pre-dates the summary emitter (e.g. crashed
    # before ``done``) but per-fire ``signal_strength`` blocks landed,
    # synthesise the summary from the raw samples so the report still
    # answers 'how close did the engine get?' (rule #9).
    if not signal_summary and signal_samples:
        ordered = sorted(signal_samples)
        n = len(ordered)

        def _pct(p: float) -> float:
            if n == 1:
                return ordered[0]
            k = (n - 1) * p
            lo = int(k)
            hi = min(lo + 1, n - 1)
            frac = k - lo
            return ordered[lo] + (ordered[hi] - ordered[lo]) * frac

        signal_summary = {
            "count": float(n),
            "mean": sum(ordered) / n,
            "max": ordered[-1],
            "p50": _pct(0.50),
            "p90": _pct(0.90),
            "p99": _pct(0.99),
        }

    metadata = RunMetadata(
        target=target,
        transport=transport,
        layer=layer,
        seed=seed,
        duration_seconds=duration,
        total_fired=total_fired or sum(fire_counts.values()),
        total_findings=total_findings or sum(sum(c.values()) for c in tier_counts.values()),
        rehydrated=rehydrated,
        target_fingerprint_id=fingerprint_id,
    )

    return EngagementReport(
        metadata=metadata,
        classes=classes,
        findings=tuple(findings),
        refusals=refusals,
        fallbacks=tuple(fallbacks),
        emergence_links=tuple(emergence_links),
        signal_strength_summary=dict(signal_summary),
        diversity_stats=dict(diversity_stats),
        carrier_histogram=dict(carrier_histogram),
        arc_summary=dict(arc_summary),
    )


def _parse_fallback(event: dict[str, Any]) -> FallbackEvent:
    def _num(key: str) -> float:
        try:
            return float(event.get(key, 0.0))
        except (TypeError, ValueError):
            return 0.0

    return FallbackEvent(
        attack_class=str(event.get("attack_class", "<unknown>")),
        recon_variant_id=str(event.get("recon_variant_id", "")),
        baseline_variant_id=str(event.get("baseline_variant_id", "")),
        recon_score=_num("recon_score"),
        baseline_score=_num("baseline_score"),
        margin=_num("margin"),
    )


def _parse_emergence(event: dict[str, Any]) -> list[ChainEmergenceLink]:
    chain_id = str(event.get("chain_id", "<unknown>"))
    links_raw = event.get("links")
    out: list[ChainEmergenceLink] = []
    if not isinstance(links_raw, list):
        return out
    for raw in links_raw:
        if not isinstance(raw, dict):
            continue
        out.append(
            ChainEmergenceLink(
                chain_id=chain_id,
                producer_class=str(raw.get("producer_class", "")),
                consumer_class=str(raw.get("consumer_class", "")),
                slot=str(raw.get("slot", "")),
                landed=bool(raw.get("landed", False)),
            )
        )
    return out
