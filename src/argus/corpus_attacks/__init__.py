"""
argus.corpus_attacks — versioned offensive attack corpus.

Per the spec, this is "the IP." The corpus is the durable repository
of attack variants every Phase-1+ agent draws from. Two layers:

  Templates  — hand-written, curated entries in seeds/*.json with
               provenance, severity, target surfaces, tags. The
               canonical "this is what the variant says".

  Mutators   — pure functions that derive new variants from a template
               (encoding, casing, politeness wrap, language switch).
               One template + N mutators yields N+1 variants.

A ``Corpus`` instance loads every seed JSON at construction, applies
mutators on demand, and exposes ``.iter_variants()`` /
``.sample(filters)``. Acceptance: 500+ unique variants reachable
through default mutators; no duplicate variant fingerprints.
"""
from argus.corpus_attacks.corpus import (
    Corpus, Template, Variant, CorpusError,
)
from argus.corpus_attacks.mutators import (
    Mutator, IdentityMutator, Base64Mutator, ROT13Mutator,
    LeetspeakMutator, UpperCaseMutator, ToyVerboseMutator,
    PolitenessWrapMutator, default_mutators,
)

__all__ = [
    "Corpus", "Template", "Variant", "CorpusError",
    "Mutator", "IdentityMutator", "Base64Mutator", "ROT13Mutator",
    "LeetspeakMutator", "UpperCaseMutator", "ToyVerboseMutator",
    "PolitenessWrapMutator", "default_mutators",
]
