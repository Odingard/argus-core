"""
argus/diagnostics/blackboard_loader.py

Production LogLoader implementation for the swarm runtime. Reads
the blackboard JSONL that every swarm run writes at
``<output_dir>/swarm_blackboard.jsonl`` and builds, per agent, an
aggregated text blob suitable for the heuristic classifier in
``causes.py``.

The blob contains:

  - finding titles the agent posted
  - observed_behavior text from each finding
  - raw_response excerpts (the MCP server's reply bytes)
  - annotations tagged with the agent as ``posted_by`` / ``source``

Deliberately quiet-failing: if the file is missing or a line is
malformed, we drop it and continue rather than crashing the
diagnostic pass. The swarm runtime's glue treats a failed
diagnostic as non-fatal; this module follows the same stance.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Callable, Iterable


def build_blackboard_log_loader(
    output_dir: str,
    *,
    max_chars_per_agent: int = 8000,
) -> Callable[[str], str]:
    """Factory — returns a LogLoader that reads
    ``output_dir/swarm_blackboard.jsonl`` once, indexes events by
    agent, and returns the aggregated text for any agent_id.

    The one-time read means the classifier can iterate all 12
    agents without re-parsing the file per agent. The per-agent
    cap (``max_chars_per_agent``) guards against huge logs
    crashing the pattern matchers on pathological outputs."""
    events_by_agent = _index_blackboard(output_dir)

    def _load(agent_id: str) -> str:
        events = events_by_agent.get(agent_id) or []
        if not events:
            return ""
        # Concatenate + trim. Order matches on-disk order so
        # earlier (often more informative) events win the cap.
        parts: list[str] = []
        total = 0
        for e in events:
            chunk = _event_to_text(e)
            if total + len(chunk) > max_chars_per_agent:
                parts.append(chunk[: max_chars_per_agent - total])
                break
            parts.append(chunk)
            total += len(chunk)
        return "\n".join(parts)

    return _load


# ── Internals ─────────────────────────────────────────────────────────────────

def _index_blackboard(output_dir: str) -> dict[str, list[dict]]:
    """Read swarm_blackboard.jsonl and group events by agent_id.

    Each line is ``{"kind": "<kind>", "data": {...}, "ts": ...}`` where
    the per-kind payload shapes are:

      kind=finding:    data has "agent_id" + finding fields
      kind=hot_file:   data has "posted_by"
      kind=hypothesis: data has "trigger_agents"
      kind=annotation: data has "finding_id", "key", "value"

    Any event that mentions an agent gets copied into that agent's
    bucket. Annotations are associated by looking at value["source"]
    when present (correlator stamps this).
    """
    path = Path(output_dir) / "swarm_blackboard.jsonl"
    if not path.is_file():
        return {}

    by_agent: dict[str, list[dict]] = {}
    try:
        with open(path, encoding="utf-8") as fh:
            for raw_line in fh:
                try:
                    rec = json.loads(raw_line)
                except json.JSONDecodeError:
                    continue
                for aid in _agent_ids_from_event(rec):
                    by_agent.setdefault(aid, []).append(rec)
    except OSError:
        return {}
    return by_agent


def _agent_ids_from_event(rec: dict) -> Iterable[str]:
    """Extract any agent_ids the event mentions. Returns a set so
    each event is only indexed once per agent even if it mentions
    the same agent via both ``agent_id`` and ``posted_by``."""
    data = rec.get("data") or {}
    if not isinstance(data, dict):
        return ()
    seen: set[str] = set()
    for field in ("agent_id", "posted_by"):
        v = data.get(field)
        if isinstance(v, str) and v:
            seen.add(v)
    # Hypotheses carry a list of trigger agents.
    trig = data.get("trigger_agents")
    if isinstance(trig, list):
        for a in trig:
            if isinstance(a, str) and a:
                seen.add(a)
    # Correlator annotations stamp a source field.
    value = data.get("value")
    if isinstance(value, dict):
        src = value.get("source")
        if isinstance(src, str) and src:
            seen.add(src)
    return seen


def _event_to_text(rec: dict) -> str:
    """Flatten one event into a text chunk the pattern matchers
    can scan. Pulls the text-like fields per event kind."""
    kind = rec.get("kind") or "?"
    data = rec.get("data") or {}
    if not isinstance(data, dict):
        return f"[{kind}]"
    parts: list[str] = [f"[{kind}]"]
    for field in (
        "title", "observed_behavior", "expected_behavior",
        "payload_used", "raw_response", "remediation", "key",
        "reason",
    ):
        v = data.get(field)
        if isinstance(v, str) and v:
            parts.append(f"{field}: {v}")
    # Annotation values can carry nested dicts the correlator wrote.
    value = data.get("value")
    if isinstance(value, (dict, list)):
        parts.append(f"value: {json.dumps(value)[:400]}")
    elif isinstance(value, str):
        parts.append(f"value: {value}")
    return " | ".join(parts)


__all__ = [
    "build_blackboard_log_loader",
]
