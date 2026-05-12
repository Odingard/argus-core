"""Phase J — Engagement Memory.

JSONL-backed persistence keyed by ``TargetFingerprint`` so successive
engagements against the same target rehydrate prior trust markers,
refusal signatures, and recon artefacts instead of starting from
scratch.

Privacy contract (AGENTS.md rule #4 — hard-fail on credential exposure):
leaked credentials are **never** persisted. Phase C's
``leaked_credentials`` slot is excluded from the recon snapshot before
serialisation; only structural refusal signatures, framing prefixes,
and accepted-persona names cross the engagement boundary.

Determinism contract (AGENTS.md rule #7): every fingerprint is a
deterministic SHA-256 over canonicalised inputs. Same manifest +
model_id → same fingerprint → same memory key. Two engagements
launched against a redeployed agent (manifest-hash drift) get
distinct keys and the new engagement starts cold.

Layout:
    <memory_dir>/<fingerprint_id>.jsonl

Each line is a JSON object describing one persisted record. Append-only
log so concurrent engagements don't clobber each other; ``get`` reads
the latest record per fingerprint.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import tempfile
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..recon.mcp_introspect import TargetManifest

DEFAULT_TTL_SECONDS: int = 7 * 24 * 60 * 60
"""7 days. Tunable per-call via ``EngagementMemory(ttl_seconds=...)``.

Chosen because most agentic deployments stabilise on a manifest within
a week — shorter TTL forces too many cold starts; longer TTL accepts
stale persona/refusal data after the target has likely re-trained or
re-prompted. Manifest-hash drift invalidates the entry immediately
regardless of TTL so a redeployed target never reuses stale state.
"""

_FINGERPRINT_RECON_FIELDS_EXCLUDED: frozenset[str] = frozenset({"leaked_credentials"})
"""Recon-profile fields that must NOT be persisted across engagements.

``leaked_credentials`` carries literal canary-bearing secret strings
harvested by Phase C's ``ext-credential-leak``. AGENTS.md rule #4
forbids cross-engagement credential persistence even when the engine
holds the strings only locally — a hostile process reading the JSONL
would gain the same leak ARGUS just demonstrated.
"""


@dataclass(frozen=True, slots=True)
class TargetFingerprint:
    """Stable identifier for a target across engagements.

    Composed of three structural hashes plus the model identifier:
      * ``manifest_hash`` — sorted tool / resource / prompt names.
      * ``tool_schema_hash`` — concatenated tool schemas (catches
        schema drift even when names match).
      * ``transport_hash`` — transport family (openai / anthropic /
        ollama / mcp / argt).
      * ``model_id`` — caller-supplied model identifier (e.g.
        ``gpt-4o``). Empty string when unknown.

    The combined SHA-256 over the four fields produces a 64-hex
    character ``fingerprint_id`` that names the JSONL file on disk.
    """

    manifest_hash: str
    tool_schema_hash: str
    transport_hash: str
    model_id: str

    @property
    def fingerprint_id(self) -> str:
        h = hashlib.sha256()
        h.update(self.manifest_hash.encode("utf-8"))
        h.update(b"\x1f")
        h.update(self.tool_schema_hash.encode("utf-8"))
        h.update(b"\x1f")
        h.update(self.transport_hash.encode("utf-8"))
        h.update(b"\x1f")
        h.update(self.model_id.encode("utf-8"))
        return h.hexdigest()

    def as_dict(self) -> dict[str, str]:
        return {
            "manifest_hash": self.manifest_hash,
            "tool_schema_hash": self.tool_schema_hash,
            "transport_hash": self.transport_hash,
            "model_id": self.model_id,
            "fingerprint_id": self.fingerprint_id,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TargetFingerprint:
        return cls(
            manifest_hash=str(data["manifest_hash"]),
            tool_schema_hash=str(data["tool_schema_hash"]),
            transport_hash=str(data["transport_hash"]),
            model_id=str(data.get("model_id", "")),
        )


def compute_target_fingerprint(
    manifest: TargetManifest,
    *,
    model_id: str = "",
) -> TargetFingerprint:
    """Compute a deterministic ``TargetFingerprint`` from a manifest.

    The hashes are SHA-256 over canonicalised JSON projections of the
    manifest. Tool / resource / prompt names are sorted before hashing
    so manifest-listing order does not perturb the fingerprint. Tool
    schemas are hashed separately because two tools with the same
    name but different schemas are not the same target — schema drift
    must invalidate the cached entry.
    """
    tool_names = sorted(t.name for t in manifest.tools)
    resource_names = sorted(r.name or r.uri for r in manifest.resources)
    prompt_names = sorted(p.name for p in manifest.prompts)
    manifest_payload = json.dumps(
        {
            "tools": tool_names,
            "resources": resource_names,
            "prompts": prompt_names,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    manifest_hash = hashlib.sha256(manifest_payload).hexdigest()

    schemas = []
    for tool in sorted(manifest.tools, key=lambda t: t.name):
        schemas.append(
            {
                "name": tool.name,
                "input_schema": tool.parameters_schema,
            }
        )
    schema_payload = json.dumps(schemas, sort_keys=True, separators=(",", ":")).encode("utf-8")
    tool_schema_hash = hashlib.sha256(schema_payload).hexdigest()

    transport_hash = hashlib.sha256((manifest.transport or "").encode("utf-8")).hexdigest()

    return TargetFingerprint(
        manifest_hash=manifest_hash,
        tool_schema_hash=tool_schema_hash,
        transport_hash=transport_hash,
        model_id=model_id,
    )


@dataclass(frozen=True, slots=True)
class TrustMarker:
    """A framing / persona / prefix the target accepted (didn't refuse).

    Captured by :func:`extract_trust_marker` whenever a probe lands or
    is accepted-but-not-landed. Rehydrated into the next engagement's
    seed pool so generators bias toward primers that previously got
    past the refusal layer on this target.
    """

    kind: str
    """One of: ``prefix``, ``persona``, ``framing``."""

    value: str
    """The accepted text fragment. Bounded to 240 chars to keep the
    JSONL line size bounded; longer fragments are truncated at
    capture time."""

    accepted_count: int = 1
    """Number of times this marker has been observed accepted across
    engagements. Increments on subsequent hits with the same
    ``(kind, value)`` pair."""

    last_seen: float = 0.0
    """Unix timestamp of the most-recent acceptance."""

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "value": self.value,
            "accepted_count": self.accepted_count,
            "last_seen": self.last_seen,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TrustMarker:
        return cls(
            kind=str(data["kind"]),
            value=str(data["value"]),
            accepted_count=int(data.get("accepted_count", 1)),
            last_seen=float(data.get("last_seen", 0.0)),
        )


_TRUST_MARKER_VALUE_CAP: int = 240
_TRUST_MARKER_KINDS: frozenset[str] = frozenset({"prefix", "persona", "framing"})


def normalise_trust_value(value: str) -> str:
    """Strip control characters and cap length for safe JSONL storage."""
    cleaned = "".join(ch for ch in value if ch.isprintable() or ch in (" ", "\t"))
    cleaned = cleaned.strip()
    if len(cleaned) > _TRUST_MARKER_VALUE_CAP:
        cleaned = cleaned[:_TRUST_MARKER_VALUE_CAP]
    return cleaned


@dataclass(frozen=True, slots=True)
class EngagementMemoryEntry:
    """One persisted record per ``(fingerprint, write)`` pair.

    Append-only on disk so concurrent engagements never clobber each
    other — ``EngagementMemory.get`` reads the latest record per
    fingerprint. Older records remain readable for audit but are
    skipped during rehydrate.
    """

    fingerprint: TargetFingerprint
    trust_markers: tuple[TrustMarker, ...] = ()
    refusal_signatures: tuple[str, ...] = ()
    """Refusal signatures persisted from prior engagements'
    ``RefusalKB``. Seeded back via
    :meth:`RefusalKB.seed_from_signatures` at rehydrate so the X8
    plausibility gate warms up immediately rather than waiting for
    the first 5 refusals of the new engagement."""

    recon_snapshot: dict[str, tuple[str, ...]] = field(default_factory=dict)
    """Persisted ``ReconProfile`` fields (excluding
    ``leaked_credentials``). Rehydrated as the initial recon profile
    when the new engagement starts. Manifest-derived fields will be
    re-merged from the live manifest at rehydrate time so any drift
    is caught immediately."""

    landed_class_ids: tuple[str, ...] = ()
    """Class IDs that landed in prior engagements. Surfaced through
    :class:`EmergenceReport` at rehydrate so the supervisor can bias
    the roster ordering toward classes already proven against this
    target."""

    last_seen: float = 0.0
    ttl_seconds: int = DEFAULT_TTL_SECONDS

    def is_expired(self, now: float | None = None) -> bool:
        ts = now if now is not None else time.time()
        return (ts - self.last_seen) > self.ttl_seconds

    def as_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint.as_dict(),
            "trust_markers": [tm.as_dict() for tm in self.trust_markers],
            "refusal_signatures": list(self.refusal_signatures),
            "recon_snapshot": {k: list(v) for k, v in self.recon_snapshot.items()},
            "landed_class_ids": list(self.landed_class_ids),
            "last_seen": self.last_seen,
            "ttl_seconds": self.ttl_seconds,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EngagementMemoryEntry:
        recon_snapshot_raw = data.get("recon_snapshot", {}) or {}
        recon_snapshot: dict[str, tuple[str, ...]] = {}
        for key, values in recon_snapshot_raw.items():
            if key in _FINGERPRINT_RECON_FIELDS_EXCLUDED:
                # Defensive: even if a malicious or older writer leaked
                # a forbidden field onto disk, refuse to rehydrate it.
                continue
            if not isinstance(values, list | tuple):
                continue
            recon_snapshot[str(key)] = tuple(str(v) for v in values)
        return cls(
            fingerprint=TargetFingerprint.from_dict(data["fingerprint"]),
            trust_markers=tuple(TrustMarker.from_dict(tm) for tm in data.get("trust_markers", [])),
            refusal_signatures=tuple(str(s) for s in data.get("refusal_signatures", [])),
            recon_snapshot=recon_snapshot,
            landed_class_ids=tuple(str(s) for s in data.get("landed_class_ids", [])),
            last_seen=float(data.get("last_seen", 0.0)),
            ttl_seconds=int(data.get("ttl_seconds", DEFAULT_TTL_SECONDS)),
        )


def filter_persistable_recon(snapshot: dict[str, Sequence[str]]) -> dict[str, tuple[str, ...]]:
    """Strip credential-bearing recon slots before persistence.

    AGENTS.md rule #4 — credentials never cross the engagement
    boundary. Manifest-derived fields and synthesised artefacts are
    fine; the ``leaked_credentials`` slot Phase C populates is the
    one explicit exclusion.
    """
    out: dict[str, tuple[str, ...]] = {}
    for key, values in snapshot.items():
        if key in _FINGERPRINT_RECON_FIELDS_EXCLUDED:
            continue
        out[str(key)] = tuple(str(v) for v in values)
    return out


@dataclass(slots=True)
class EngagementMemory:
    """JSONL-backed engagement memory keyed by ``TargetFingerprint``.

    The on-disk layout is one append-only ``<fingerprint_id>.jsonl``
    per fingerprint under ``memory_dir``. Concurrent engagements
    against the same fingerprint append independently; ``get`` always
    returns the most-recent non-expired entry.

    Files are written atomically via temp-file + rename to avoid
    torn writes on crash; readers ignore lines that fail to parse so
    a partially-flushed write at the tail is tolerated.
    """

    memory_dir: Path
    ttl_seconds: int = DEFAULT_TTL_SECONDS

    def __post_init__(self) -> None:
        self.memory_dir = Path(self.memory_dir)
        self.memory_dir.mkdir(parents=True, exist_ok=True)

    def _path_for(self, fingerprint: TargetFingerprint) -> Path:
        return self.memory_dir / f"{fingerprint.fingerprint_id}.jsonl"

    def get(
        self,
        fingerprint: TargetFingerprint,
        *,
        now: float | None = None,
    ) -> EngagementMemoryEntry | None:
        """Return the most-recent non-expired entry, or ``None``.

        Returns ``None`` when:
          * The JSONL file does not exist (cold start).
          * Every line in the file fails to parse (corrupt).
          * The latest valid entry is past its TTL.

        TTL invalidation is computed at read time so writers don't
        need to know the reader's clock; ``now`` overrides
        ``time.time()`` for tests.
        """
        path = self._path_for(fingerprint)
        if not path.exists():
            return None
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return None
        latest: EngagementMemoryEntry | None = None
        for line in reversed(lines):
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            try:
                entry = EngagementMemoryEntry.from_dict(payload)
            except (KeyError, TypeError, ValueError):
                continue
            # Latest-write wins; we walk in reverse so the first
            # successfully-parsed entry is the freshest.
            latest = entry
            break
        if latest is None:
            return None
        if latest.is_expired(now):
            return None
        return latest

    def write(self, entry: EngagementMemoryEntry) -> None:
        """Append ``entry`` to the JSONL file for its fingerprint.

        Uses a per-file temp + atomic-rename pattern so partial flushes
        on crash never leave a corrupt tail in the canonical file.
        """
        path = self._path_for(entry.fingerprint)
        # Read existing lines (if any) so we can rewrite atomically
        # with the new entry appended. Append-only logical semantics
        # are preserved by always writing the cumulative log; bounded
        # by the per-fingerprint compaction below.
        existing: list[str] = []
        if path.exists():
            try:
                existing = path.read_text(encoding="utf-8").splitlines()
            except OSError:
                existing = []
        existing = [line for line in existing if line.strip()]
        existing.append(json.dumps(entry.as_dict(), sort_keys=True, separators=(",", ":")))
        # Bound the log so a long-lived target doesn't grow unboundedly.
        # 32 records is enough for a year of weekly engagements.
        if len(existing) > 32:
            existing = existing[-32:]

        fd, tmp_path_str = tempfile.mkstemp(
            prefix=f".{entry.fingerprint.fingerprint_id}.",
            suffix=".jsonl.tmp",
            dir=str(self.memory_dir),
        )
        tmp_path = Path(tmp_path_str)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write("\n".join(existing))
                fh.write("\n")
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_path, path)
        except OSError:
            if tmp_path.exists():
                with contextlib.suppress(OSError):
                    tmp_path.unlink()
            raise

    def invalidate(self, fingerprint: TargetFingerprint) -> bool:
        """Delete the on-disk record for ``fingerprint``.

        Returns ``True`` if a file was removed, ``False`` otherwise.
        Used by the supervisor when manifest-hash drift is detected
        between rehydrate and the live recon scan — the cached entry
        is no longer trustworthy and should not silently linger.
        """
        path = self._path_for(fingerprint)
        if not path.exists():
            return False
        try:
            path.unlink()
        except OSError:
            return False
        return True

    def list_fingerprints(self) -> tuple[TargetFingerprint, ...]:
        """Enumerate every fingerprint with an on-disk record.

        Best-effort — files that fail to parse are skipped. Used by
        diagnostic CLI commands and tests; the supervisor never
        scans the whole memory directory at runtime.
        """
        out: list[TargetFingerprint] = []
        for entry_path in sorted(self.memory_dir.glob("*.jsonl")):
            try:
                first_line = entry_path.read_text(encoding="utf-8").splitlines()[0]
            except (OSError, IndexError):
                continue
            try:
                payload = json.loads(first_line)
                fingerprint = TargetFingerprint.from_dict(payload["fingerprint"])
            except (json.JSONDecodeError, KeyError, TypeError, ValueError):
                continue
            out.append(fingerprint)
        return tuple(out)


def merge_trust_markers(
    existing: Iterable[TrustMarker],
    incoming: Iterable[TrustMarker],
    *,
    now: float | None = None,
) -> tuple[TrustMarker, ...]:
    """Merge two trust-marker streams, deduplicating by (kind, value).

    When the same ``(kind, value)`` appears in both streams the
    counts are summed and ``last_seen`` advances to ``max``. Output
    is sorted by descending ``accepted_count`` then by ``-last_seen``
    so the supervisor's seed pool consumes the most-trusted markers
    first.
    """
    ts = now if now is not None else time.time()
    table: dict[tuple[str, str], TrustMarker] = {}
    for stream in (existing, incoming):
        for marker in stream:
            if marker.kind not in _TRUST_MARKER_KINDS:
                continue
            value = normalise_trust_value(marker.value)
            if not value:
                continue
            key = (marker.kind, value)
            if key in table:
                prior = table[key]
                table[key] = TrustMarker(
                    kind=marker.kind,
                    value=value,
                    accepted_count=prior.accepted_count + marker.accepted_count,
                    last_seen=max(prior.last_seen, marker.last_seen, ts),
                )
            else:
                table[key] = TrustMarker(
                    kind=marker.kind,
                    value=value,
                    accepted_count=marker.accepted_count,
                    last_seen=marker.last_seen if marker.last_seen > 0 else ts,
                )
    ordered = sorted(
        table.values(),
        key=lambda m: (-m.accepted_count, -m.last_seen, m.kind, m.value),
    )
    return tuple(ordered)


__all__ = [
    "DEFAULT_TTL_SECONDS",
    "EngagementMemory",
    "EngagementMemoryEntry",
    "TargetFingerprint",
    "TrustMarker",
    "compute_target_fingerprint",
    "filter_persistable_recon",
    "merge_trust_markers",
    "normalise_trust_value",
]
