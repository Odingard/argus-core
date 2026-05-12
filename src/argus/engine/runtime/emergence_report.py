"""Phase J — Emergence Report.

Structured artefact that surfaces the emergent multi-step behaviour of
a chain run: which class harvested which artefact, which downstream
class consumed it, and which step landed a verdict.

The same data is reconstructable by reading the JSONL audit trail and
walking ``ChainStepRecord.harvested`` step-by-step. The
:class:`EmergenceReport` collapses that walk into a presentation-ready
artefact so callers (CLI summary, validation harness, compare tooling)
don't each reimplement the traversal.

Determinism (AGENTS.md rule #7): the report is a pure function of the
``ChainResult`` it is built from. Same chain → same report bytes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .chain_runner import ChainResult


@dataclass(frozen=True, slots=True)
class EmergenceLink:
    """One producer→consumer hop in a chain.

    Built when ``ChainStepRecord.harvested`` on step ``N`` shares a
    field with the slot the class at step ``N+M`` (M ≥ 1) consumes.
    The report keeps every direct hop that fired in the executed plan;
    the synthesised plan's edge metadata is the source of truth for
    "what was supposed to happen" and the per-step records are the
    source of truth for "what actually happened".
    """

    producer_class_id: str
    producer_step_index: int
    """Zero-indexed position of the producer step in the executed plan."""

    consumer_class_id: str
    consumer_step_index: int
    """Zero-indexed position of the consumer step in the executed plan.
    Always strictly greater than ``producer_step_index``."""

    harvested_field: str
    """Recon-profile slot name that carried the artefact (e.g.
    ``leaked_credentials``, ``tool_names``)."""

    artefact_count: int
    """Number of values produced for ``harvested_field`` at the
    producer step (bounded by the class' harvest cap, e.g. Phase C
    caps at 8)."""

    def as_dict(self) -> dict[str, Any]:
        return {
            "producer_class_id": self.producer_class_id,
            "producer_step_index": self.producer_step_index,
            "consumer_class_id": self.consumer_class_id,
            "consumer_step_index": self.consumer_step_index,
            "harvested_field": self.harvested_field,
            "artefact_count": self.artefact_count,
        }


@dataclass(frozen=True, slots=True)
class EmergenceReport:
    """End-to-end emergence summary for one chain execution.

    The report is shippable in two forms:
      * As a structured dataclass for callers that consume it
        programmatically (validation harness, CLI report renderer).
      * As a JSON-serialisable dict via :meth:`as_dict` for the JSONL
        audit trail.
    """

    chain_id: str
    completed: bool
    landed_class_ids: tuple[str, ...]
    """Class IDs that landed a verdict, in step order. The supervisor
    feeds this to :class:`EngagementMemory` so future engagements
    against the same target can bias roster ordering toward
    previously-proven classes."""

    links: tuple[EmergenceLink, ...] = ()
    """Producer→consumer artefact hops, in chain order. Empty when no
    step harvested or no downstream step consumed."""

    fallback_events: tuple[dict[str, object], ...] = ()
    """X8 plausibility-gate fallback events for this chain (mirrors
    ``ChainResult.fallback_events``). Surfaced here so the report
    captures every non-default decision the runner made — required
    by AGENTS.md rule #9."""

    summary: str = ""
    """Human-readable one-line summary of the emergence path. Built
    deterministically from the link list; empty when the chain
    landed nothing or harvested nothing."""

    def as_dict(self) -> dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "completed": self.completed,
            "landed_class_ids": list(self.landed_class_ids),
            "links": [link.as_dict() for link in self.links],
            "fallback_events": [dict(ev) for ev in self.fallback_events],
            "summary": self.summary,
        }


def _slot_consumers(class_id: str) -> frozenset[str]:
    """Return the set of recon slots ``class_id`` consumes.

    Lazy registry lookup so tests that build the report without a
    live registry (stubbed classes) still get a non-empty link set
    when at least one class is registered. Falls back to an empty
    set when the class is unknown.
    """
    try:
        from ..core.registry import get as registry_get

        cls = registry_get(class_id)
    except (ImportError, KeyError):
        return frozenset()
    consumes = getattr(cls, "consumes", None)
    if consumes is None:
        return frozenset()
    return frozenset(str(c) for c in consumes)


def build_emergence_report(result: ChainResult) -> EmergenceReport:
    """Materialise an :class:`EmergenceReport` from a ``ChainResult``.

    Walks the chain steps in order, tracks which slots were harvested
    on each step, and emits one :class:`EmergenceLink` for every later
    step that consumes one of the harvested slots. The first
    consumer per (producer, slot) wins so a wide harvest doesn't
    inflate the link count.

    The function is purely deterministic — same ``ChainResult`` →
    same bytes-identical report.
    """
    landed: list[str] = [s.class_id for s in result.steps if s.landed]
    pending: dict[str, tuple[str, int, int]] = {}
    """field -> (producer_class_id, producer_step_index, artefact_count)"""

    links: list[EmergenceLink] = []
    for step_index, step in enumerate(result.steps):
        # Record what THIS step harvested for downstream consumers.
        if step.landed:
            for field_name, values in step.harvested:
                if not values:
                    continue
                # First producer wins per slot — later harvests don't
                # overwrite an unconsumed earlier producer.
                if field_name not in pending:
                    pending[field_name] = (step.class_id, step_index, len(values))

        # Now check whether THIS step is a consumer for any pending
        # producer's slot.
        consumes = _slot_consumers(step.class_id)
        if not consumes:
            continue
        for field_name in sorted(consumes):
            producer = pending.get(field_name)
            if producer is None:
                continue
            producer_class_id, producer_step_index, artefact_count = producer
            if producer_step_index >= step_index:
                continue
            links.append(
                EmergenceLink(
                    producer_class_id=producer_class_id,
                    producer_step_index=producer_step_index,
                    consumer_class_id=step.class_id,
                    consumer_step_index=step_index,
                    harvested_field=field_name,
                    artefact_count=artefact_count,
                )
            )
            # Slot consumed — drop so a later step doesn't double-count.
            del pending[field_name]

    summary = _format_summary(links, landed, completed=result.completed)
    return EmergenceReport(
        chain_id=result.chain_id,
        completed=result.completed,
        landed_class_ids=tuple(landed),
        links=tuple(links),
        fallback_events=result.fallback_events,
        summary=summary,
    )


def _format_summary(
    links: tuple[EmergenceLink, ...] | list[EmergenceLink],
    landed_class_ids: list[str],
    *,
    completed: bool,
) -> str:
    """Render a human-readable one-line summary.

    Format: ``producer_a → consumer_b → consumer_c``. When no link
    fired we fall back to ``landed: x, y`` so callers never get an
    empty string for a non-empty result.
    """
    if links:
        ordered = sorted(links, key=lambda link: link.producer_step_index)
        chain: list[str] = [ordered[0].producer_class_id]
        last_step = ordered[0].producer_step_index
        for link in ordered:
            if link.producer_step_index >= last_step:
                chain.append(link.consumer_class_id)
                last_step = link.consumer_step_index
        return " → ".join(chain) + (" (chain completed)" if completed else "")
    if landed_class_ids:
        return "landed: " + ", ".join(landed_class_ids)
    return ""


@dataclass(slots=True)
class EmergenceLog:
    """Container for emergence reports built across an engagement.

    Used by the supervisor when ``chain_phase`` is enabled — every
    chain run produces one :class:`EmergenceReport` and the log keeps
    them in execution order. The aggregated log is what gets
    persisted to ``EngagementMemory.landed_class_ids`` and surfaced
    to the engagement summary.
    """

    reports: list[EmergenceReport] = field(default_factory=list)

    def append(self, report: EmergenceReport) -> None:
        self.reports.append(report)

    def landed_class_ids(self) -> tuple[str, ...]:
        seen: set[str] = set()
        out: list[str] = []
        for report in self.reports:
            for cid in report.landed_class_ids:
                if cid in seen:
                    continue
                seen.add(cid)
                out.append(cid)
        return tuple(out)

    def as_dict(self) -> dict[str, Any]:
        return {"reports": [r.as_dict() for r in self.reports]}


__all__ = [
    "EmergenceLink",
    "EmergenceLog",
    "EmergenceReport",
    "build_emergence_report",
]
