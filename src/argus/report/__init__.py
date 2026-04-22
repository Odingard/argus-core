"""
argus.report — renders an engagement's artifact package into a
customer-facing single-page HTML report.

Input: an engagement output directory (the one
``argus engage`` / ``argus demo:*`` writes). Output: a
``report.html`` file that displays:

  • chain id, target, harm score, severity label, regulatory impact
  • kill-chain steps with OWASP badges
  • per-agent landing summary
  • blast-radius map (directly-reached + transitively-reachable)
  • deterministic-evidence summary (pcap hop count, integrity sha)
  • Wilson bundle + ALEC envelope references

Zero external deps — no Jinja, no JavaScript framework, no CSS
build step. Just stdlib + one self-contained HTML string.

CLI:
    argus report <engagement_dir>
"""
from argus.report.render import (
    RenderedReport, render_html_from_dir, render_html,
)

__all__ = ["RenderedReport", "render_html_from_dir", "render_html"]
