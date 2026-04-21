"""
argus/evidence/collector.py
Deterministic evidence collection — the AI-Slop filter.

Each agent that wants its findings to ship Wilson-Proof grade evidence
opens an ``EvidenceCollector`` for the attack session, records what
happened, and seals the collector into a ``DeterministicEvidence``
object that travels with the AgentFinding.

The shape is deliberately framework-light: every field is JSON-
serialisable, every artifact is integrity-hashed, and seal is
idempotent — once sealed, mutations raise EvidenceError.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


class EvidenceError(Exception):
    """Raised on misuse: writing to a sealed collector, missing
    required artifact at seal time, etc."""


# ── Artifact shapes ─────────────────────────────────────────────────────────

@dataclass
class PcapRecord:
    """One direction of one wire transaction. Adapter-agnostic;
    in-memory adapters synthesise these from request/response pairs."""
    timestamp_ms: int
    direction:    str            # "out" (attacker→target) | "in" (target→attacker)
    surface:      str
    request_id:   str
    payload:      Any            # JSON-serialisable shape

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class OOBCallbackRecord:
    """One out-of-band callback the target made to our listener."""
    timestamp_ms: int
    token:        str
    source_ip:    str
    method:       str
    path:         str
    headers:      dict = field(default_factory=dict)
    body:         str = ""

    def to_dict(self) -> dict:
        return asdict(self)


# ── DeterministicEvidence ───────────────────────────────────────────────────

@dataclass
class DeterministicEvidence:
    """
    Sealed bundle of non-LLM proof artifacts. Treat as immutable
    post-seal: changing any field invalidates ``integrity_sha``.
    """
    evidence_id:        str
    sealed_at:          str
    target_id:          str
    session_id:         str
    pcap:               list[PcapRecord]      = field(default_factory=list)
    container_logs:     str                   = ""
    oob_callbacks:      list[OOBCallbackRecord] = field(default_factory=list)
    env_snapshot:       dict                  = field(default_factory=dict)
    notes:              str                   = ""
    integrity_sha:      str                   = ""

    def to_dict(self) -> dict:
        return {
            "evidence_id":     self.evidence_id,
            "sealed_at":       self.sealed_at,
            "target_id":       self.target_id,
            "session_id":      self.session_id,
            "pcap":            [r.to_dict() for r in self.pcap],
            "container_logs":  self.container_logs,
            "oob_callbacks":   [r.to_dict() for r in self.oob_callbacks],
            "env_snapshot":    dict(self.env_snapshot),
            "notes":           self.notes,
            "integrity_sha":   self.integrity_sha,
        }

    def write(self, output_dir: str | Path) -> Path:
        """Persist the evidence as a single JSON artifact. Returns the path."""
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        path = output_dir / f"{self.evidence_id}.json"
        path.write_text(json.dumps(self.to_dict(), indent=2),
                        encoding="utf-8")
        return path

    def is_proof_grade(self) -> bool:
        """
        True iff the evidence carries something the operator can
        replay deterministically — at least one pcap record AND at
        least one of (container_logs, oob_callbacks). Echo-only
        evidence does not pass.
        """
        if not self.pcap:
            return False
        if self.container_logs.strip():
            return True
        if self.oob_callbacks:
            return True
        return False


# ── Collector ───────────────────────────────────────────────────────────────

class EvidenceCollector:
    """
    Mutable accumulator the agent feeds during the attack session;
    call ``seal()`` to produce the immutable ``DeterministicEvidence``.

    Usage:

        with EvidenceCollector(target_id="mcp://x", session_id="s1") as ev:
            ev.record_request(surface="chat", request_id="r1",
                              payload="hello")
            ev.record_response(surface="chat", request_id="r1",
                               payload="hi")
            ev.attach_oob_callbacks(listener.drain())
            ev.attach_container_logs(target.logs())
            sealed = ev.seal()
    """

    def __init__(
        self,
        *,
        target_id:  str,
        session_id: str,
        notes:      str = "",
    ) -> None:
        if not target_id or not session_id:
            raise EvidenceError("target_id and session_id required")
        self.target_id  = target_id
        self.session_id = session_id
        self._pcap:           list[PcapRecord]        = []
        self._oob:            list[OOBCallbackRecord] = []
        self._container_logs: list[str]               = []
        self._env:            dict                    = {}
        self._notes:          str                     = notes
        self._sealed:         Optional[DeterministicEvidence] = None
        self._t0_ms = int(time.time() * 1000)

    # ── Recording ───────────────────────────────────────────────────────

    def record_request(
        self, *, surface: str, request_id: str, payload: Any,
    ) -> None:
        self._guard()
        self._pcap.append(PcapRecord(
            timestamp_ms=self._now_ms(),
            direction="out", surface=surface,
            request_id=request_id, payload=payload,
        ))

    def record_response(
        self, *, surface: str, request_id: str, payload: Any,
    ) -> None:
        self._guard()
        self._pcap.append(PcapRecord(
            timestamp_ms=self._now_ms(),
            direction="in", surface=surface,
            request_id=request_id, payload=payload,
        ))

    def attach_container_logs(self, text: str) -> None:
        self._guard()
        if text:
            self._container_logs.append(text)

    def attach_oob_callbacks(self, records: list[OOBCallbackRecord]) -> None:
        self._guard()
        self._oob.extend(records)

    def attach_env_snapshot(self, env: dict) -> None:
        self._guard()
        self._env.update(env or {})

    def add_note(self, line: str) -> None:
        self._guard()
        self._notes = (self._notes + "\n" + line).strip() if self._notes else line

    # ── Seal ────────────────────────────────────────────────────────────

    def seal(self) -> DeterministicEvidence:
        if self._sealed is not None:
            return self._sealed
        evidence_id = self._stable_id()
        evidence = DeterministicEvidence(
            evidence_id=evidence_id,
            sealed_at=datetime.now(timezone.utc).isoformat(),
            target_id=self.target_id,
            session_id=self.session_id,
            pcap=list(self._pcap),
            container_logs="\n".join(self._container_logs).strip(),
            oob_callbacks=list(self._oob),
            env_snapshot=dict(self._env),
            notes=self._notes,
        )
        evidence.integrity_sha = _integrity(evidence)
        self._sealed = evidence
        return evidence

    # ── Context manager sugar ───────────────────────────────────────────

    def __enter__(self) -> "EvidenceCollector":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if exc is None and self._sealed is None:
            self.seal()

    # ── Internals ───────────────────────────────────────────────────────

    def _guard(self) -> None:
        if self._sealed is not None:
            raise EvidenceError(
                "EvidenceCollector is sealed; mutations are not permitted"
            )

    def _now_ms(self) -> int:
        return int(time.time() * 1000) - self._t0_ms

    def _stable_id(self) -> str:
        raw = f"{self.target_id}|{self.session_id}|{len(self._pcap)}|" \
              f"{len(self._oob)}|{self._t0_ms}"
        return "ev-" + hashlib.sha256(raw.encode()).hexdigest()[:14]


# ── Attach helper ───────────────────────────────────────────────────────────

def attach_evidence(finding, evidence: DeterministicEvidence) -> None:
    """
    Attach a sealed evidence object to an AgentFinding. The finding
    grows two fields: ``evidence_id`` and ``evidence_proof_grade``.
    The full evidence is persisted alongside via ``evidence.write()``;
    the finding only carries the pointer + grade so it stays small
    enough for the report layer.
    """
    if evidence.integrity_sha == "":
        raise EvidenceError("evidence is not sealed")
    setattr(finding, "evidence_id",          evidence.evidence_id)
    setattr(finding, "evidence_integrity",   evidence.integrity_sha)
    setattr(finding, "evidence_proof_grade", evidence.is_proof_grade())


# ── Integrity ───────────────────────────────────────────────────────────────

def _integrity(evidence: DeterministicEvidence) -> str:
    """SHA-256 over the canonical JSON of every artifact field."""
    raw = json.dumps({
        "evidence_id":    evidence.evidence_id,
        "target_id":      evidence.target_id,
        "session_id":     evidence.session_id,
        "pcap":           [r.to_dict() for r in evidence.pcap],
        "container_logs": evidence.container_logs,
        "oob_callbacks":  [r.to_dict() for r in evidence.oob_callbacks],
        "env_snapshot":   evidence.env_snapshot,
    }, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()
