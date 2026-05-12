"""Layer 3 — Cognitive Attacks.

Importing this package registers all 12 Layer-3 attack classes with the
core registry. Pre-Phase-S target: 3,000 deterministic variants across
reasoning-layer attacks that bypass refusal classifiers by manipulating
the model's chain-of-thought, self-consistency, deductive form,
counterfactual frames, self-evaluation, analogical mapping, and
recursive decomposition. Phase S adds four new classes whose structural
shapes the meta-aware ARGT-001 guard has not been trained on:

  c01  cog-chain-of-thought-hijack          400
  c02  cog-reasoning-step-injection         400
  c03  cog-self-consistency-exploit         360
  c04  cog-logical-fallacy-amplifier        400
  c05  cog-counterfactual-priming           360
  c06  cog-meta-reasoning-bypass            360
  c07  cog-analogical-substitution          360
  c08  cog-recursive-decomposition          360
  c09  cog-epistemic-confidence-drain       200   (Phase S, priority)
  c10  cog-authority-laundering             240   (Phase S)
  c11  cog-socratic-extraction              240   (Phase S, arc-native)
  c12  cog-benign-pretext-switch            240   (Phase S, arc-native)
                                          -----
                                          3,920
"""

from . import (  # noqa: F401  -- side-effect imports register all classes
    c01_chain_of_thought_hijack,
    c02_reasoning_step_injection,
    c03_self_consistency_exploit,
    c04_logical_fallacy_amplifier,
    c05_counterfactual_priming,
    c06_meta_reasoning_bypass,
    c07_analogical_substitution,
    c08_recursive_decomposition,
    c09_epistemic_confidence_drain,
    c10_authority_laundering,
    c11_socratic_extraction,
    c12_benign_pretext_switch,
)

__all__ = [
    "c01_chain_of_thought_hijack",
    "c02_reasoning_step_injection",
    "c03_self_consistency_exploit",
    "c04_logical_fallacy_amplifier",
    "c05_counterfactual_priming",
    "c06_meta_reasoning_bypass",
    "c07_analogical_substitution",
    "c08_recursive_decomposition",
    "c09_epistemic_confidence_drain",
    "c10_authority_laundering",
    "c11_socratic_extraction",
    "c12_benign_pretext_switch",
]
