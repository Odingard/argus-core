"""
argus/alec/bridge.py
ALEC evidence-chain bridge — Phase 4 stub.

Wilson bundles are ARGUS' signed forensic packages — JSON manifest +
artifacts + signature. ALEC ingests evidence chains for regulator-
defensible audit. The bridge converts a Wilson bundle directory into
an ``ALECEnvelope`` that ALEC's ingestion contract knows how to read.

The stub posture:
  • build_envelope reads a Wilson bundle directory and produces a
    coherent ALECEnvelope with manifest, integrity hash, and a
    deterministic envelope_id.
  • write_envelope persists it to disk (the on-disk shape is what
    ALEC's batch ingester historically consumes).
  • submit_to_alec invokes a pluggable transport (HTTP / mTLS / S3
    drop). The default transport is the offline writer — Phase-5
    swaps in the live HTTP push without changing this surface.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional


@dataclass
class ALECEnvelope:
    envelope_id:       str
    schema_version:    str
    target_id:         str
    bundle_id:         str
    bundle_path:       str
    finding_count:     int
    severity_summary:  dict[str, int]
    techniques:        list[str]
    owasp_categories:  list[str]
    manifest:          dict
    integrity:         str
    generated_at:      str
    transport_phase:   str = "stub-offline"

    def to_dict(self) -> dict:
        return asdict(self)


def build_envelope(
    bundle_dir: str | Path,
    *,
    target_id:        Optional[str] = None,
    schema_version:   str = "alec.v0-stub",
) -> ALECEnvelope:
    """
    Read a Wilson bundle directory and synthesize an ALECEnvelope.
    The directory is expected to contain ``manifest.json`` (the Wilson
    bundle's manifest); other artifacts are inventoried by integrity
    hash but not parsed.
    """
    bundle_path = Path(bundle_dir)
    if not bundle_path.exists() or not bundle_path.is_dir():
        raise FileNotFoundError(
            f"build_envelope: bundle dir not found: {bundle_path}"
        )

    manifest_path = bundle_path / "manifest.json"
    manifest: dict = {}
    if manifest_path.exists():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            manifest = {"_warning": "manifest.json present but not valid JSON"}

    bundle_id = (
        manifest.get("bundle_id")
        or manifest.get("id")
        or bundle_path.name
    )
    target = (
        target_id
        or manifest.get("target_id")
        or manifest.get("target")
        or "unknown://target"
    )

    findings_in = manifest.get("findings") or []
    sev_summary: dict[str, int] = {}
    techniques: list[str] = []
    owasp: list[str] = []
    for f in findings_in:
        s = (f.get("severity") or "UNKNOWN").upper()
        sev_summary[s] = sev_summary.get(s, 0) + 1
        if t := (f.get("attack_variant_id") or f.get("technique")):
            techniques.append(t)
        # Manifest may carry a pre-computed owasp tag from chain v2.
        if o := f.get("owasp_id"):
            owasp.append(o)

    techniques = sorted(set(techniques))
    owasp = sorted(set(owasp))

    integrity = _bundle_integrity(bundle_path)
    envelope_id = "alec-" + hashlib.sha256(
        f"{bundle_id}|{target}|{integrity}".encode()
    ).hexdigest()[:14]

    return ALECEnvelope(
        envelope_id=envelope_id,
        schema_version=schema_version,
        target_id=target,
        bundle_id=str(bundle_id),
        bundle_path=str(bundle_path),
        finding_count=len(findings_in),
        severity_summary=sev_summary,
        techniques=techniques,
        owasp_categories=owasp,
        manifest=manifest,
        integrity=integrity,
        generated_at=datetime.now(timezone.utc).isoformat(),
    )


def write_envelope(
    envelope: ALECEnvelope,
    output_dir: str | Path,
    *,
    filename: Optional[str] = None,
) -> Path:
    """Persist an envelope to disk. Returns the path written."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    out = output_dir / (filename or f"{envelope.envelope_id}.json")
    out.write_text(json.dumps(envelope.to_dict(), indent=2),
                   encoding="utf-8")
    return out


# Default transport used by submit_to_alec when no caller-supplied
# transport is provided. Writes to disk in the same directory as the
# bundle. Phase-5 swaps this out for the live HTTP push.
def _offline_transport(envelope: ALECEnvelope) -> dict:
    out_dir = Path(envelope.bundle_path) / "alec_outbox"
    path = write_envelope(envelope, out_dir)
    return {"status": "written", "path": str(path),
            "envelope_id": envelope.envelope_id}


TransportFn = Callable[[ALECEnvelope], dict]


def submit_to_alec(
    bundle_dir: str | Path,
    *,
    target_id:  Optional[str] = None,
    transport:  Optional[TransportFn] = None,
) -> dict:
    """
    End-to-end submit: build envelope from bundle, then ship via
    ``transport`` (default = offline writer). Returns the transport's
    response dict — typically {status, envelope_id, path|http_status}.
    """
    envelope = build_envelope(bundle_dir, target_id=target_id)
    fn = transport or _offline_transport
    return fn(envelope)


# ── Internals ───────────────────────────────────────────────────────────────

def _bundle_integrity(bundle_path: Path) -> str:
    """SHA-256 over every regular file in the bundle (sorted for
    determinism). Tampering with any artifact changes the envelope's
    integrity field."""
    h = hashlib.sha256()
    for p in sorted(bundle_path.rglob("*")):
        if not p.is_file():
            continue
        h.update(p.relative_to(bundle_path).as_posix().encode("utf-8"))
        h.update(b"\x00")
        try:
            h.update(p.read_bytes())
        except OSError:
            pass
        h.update(b"\x00")
    return h.hexdigest()
