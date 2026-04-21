"""
argus.alec — Wilson bundle → ALEC evidence-chain integration (Phase 4 stub).

Per Tech_Architecture.docx §ALEC Integration: "Wilson bundles are
ARGUS' signed evidence packaging unit. The ALEC platform ingests
those bundles into a regulator-defensible evidence chain. Phase-4
ships the bridge — a Wilson-bundle-to-ALEC-envelope converter that
ALEC's ingestion API knows how to consume."

Phase-4 stub posture: produces a coherent ALEC envelope (bundle id,
target id, finding manifest, attestation) and ``submit_to_alec`` ships
it through the public converter; the actual HTTP / mTLS push to
ALEC's ingestion endpoint is a Phase-5 plug-in (the converter contract
is fixed here so the network layer is just a transport swap).
"""
from argus.alec.bridge import (
    ALECEnvelope, build_envelope, submit_to_alec, write_envelope,
)

__all__ = ["ALECEnvelope", "build_envelope", "submit_to_alec",
           "write_envelope"]
