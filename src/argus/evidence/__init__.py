"""
argus.evidence — deterministic non-LLM evidence ("AI Slop filter").

The Bugcrowd-era pain point: AI-generated reports that have no
verifiable proof beyond "the model said it worked". ARGUS findings
must come with deterministic, reproducible artifacts an operator can
inspect without running a model:

  Pcap            wire-byte log of every request/response on the
                  attack session — replayable, diffable
  ContainerLogs   captured stdout/stderr of any in-process target,
                  or a sidecar log stream the adapter exposes
  OOBCallback     out-of-band webhook record proving the target
                  reached back to an attacker-controlled listener
                  (the "shell popped" ground truth)

Every Phase-1+ finding SHOULD carry a sealed ``DeterministicEvidence``
object. The Wilson bundle composer treats its presence as a precondition
for sealing — no evidence, no Wilson-Proof.
"""
from argus.evidence.collector import (
    DeterministicEvidence, EvidenceCollector, EvidenceError,
    PcapRecord, OOBCallbackRecord, attach_evidence,
)
from argus.evidence.oob import OOBListener

__all__ = [
    "DeterministicEvidence", "EvidenceCollector", "EvidenceError",
    "PcapRecord", "OOBCallbackRecord", "attach_evidence",
    "OOBListener",
]
