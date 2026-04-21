"""
argus.corpus — training corpus curation.

Walks accumulated ARGUS results (per-run layer JSONs + agent findings +
Wilson bundles + flywheel entries), extracts prompt/response training
pairs, dedups by semantic fingerprint, and emits a labeled JSONL file
suitable for handoff to an Anthropic / OpenAI / Gemma fine-tune job.

This is the write side of Pillar 1 (Lazarus Edge). The fine-tune itself
is intentionally out-of-band — we ship the runbook in
``argus/corpus/finetune_handoff.py`` rather than running the API call
from inside ARGUS, because different customers will have different
provider preferences, data residency constraints, and model sizes.
"""
from argus.corpus.emitter import (
    CorpusEmitter, CorpusPair, emit_from_results,
)
from argus.corpus.finetune_handoff import (
    write_handoff_manifest, split_train_val,
)

__all__ = [
    "CorpusEmitter", "CorpusPair", "emit_from_results",
    "write_handoff_manifest", "split_train_val",
]
