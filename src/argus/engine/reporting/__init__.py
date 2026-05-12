"""Phase M reporting layer — deterministic offline renderers.

The reporting layer is a *pure-function* projection of a forensic
JSONL run-log into two artefacts:

* a single-file HTML report (``html.render_html``) — zero external
  dependencies, zero JavaScript, safe to email or commit;
* a CI-friendly Markdown summary (``markdown.render_markdown``) —
  drop-in for GitHub / GitLab PR comments and Slack snippets.

Both renderers consume the same in-memory :class:`EngagementReport`
built by :func:`jsonl_reader.parse_jsonl`. The model captures every
fact downstream consumers need (target metadata, per-class rollups,
findings, refusal-KB hits, recon-plausibility fallbacks, chain
emergence links) and is deterministic — same JSONL in → same report
out (AGENTS.md rule #7).
"""

from __future__ import annotations

from .html import render_html
from .jsonl_reader import parse_jsonl, parse_jsonl_text
from .markdown import render_markdown
from .model import (
    ChainEmergenceLink,
    ClassRollup,
    EngagementReport,
    FallbackEvent,
    FindingRow,
    RefusalRow,
    RunMetadata,
)

__all__ = [
    "ChainEmergenceLink",
    "ClassRollup",
    "EngagementReport",
    "FallbackEvent",
    "FindingRow",
    "RefusalRow",
    "RunMetadata",
    "parse_jsonl",
    "parse_jsonl_text",
    "render_html",
    "render_markdown",
]
