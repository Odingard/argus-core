"""Layer 4 — Extraction.

Importing this package registers all 9 Layer-4 attack classes with the
core registry. Pre-Phase-S target: 2,200 deterministic variants across
extraction-surface attacks that elicit ground-truth artefacts present
in prompt / RAG / tool-schema / training-distribution / transport-
metadata. Distinct from Layer 3 (reasoning-layer hijacks): Layer 4
attacks the disclosure boundary itself, not the reasoning surface.
Phase S adds two new classes whose structural shapes the ARGT-014-class
auth-boundary guard has not been trained on:

  e01  ext-system-prompt-leak                400
  e02  ext-tool-schema-leak                  350
  e03  ext-rag-corpus-leak                   350
  e04  ext-training-data-regurgitation       300
  e05  ext-side-channel-introspection        300
  e06  ext-auth-boundary-leak                300
  e07  ext-credential-leak                   200
  e08  ext-role-assumption-chain             200   (Phase S, arc-native)
  e09  ext-schema-boundary-confusion         200   (Phase S)
                                           -----
                                           2,600

Carrier-agnostic invariants. Each class names 3+ real-world surfaces
in its module docstring and is regression-guarded by stub harnesses
in tests/integration/stubs/ that verify variants fire across carriers
without keyword overfitting.
"""

from . import (  # noqa: F401  -- side-effect imports register all classes
    e01_system_prompt_leak,
    e02_tool_schema_leak,
    e03_rag_corpus_leak,
    e04_training_data_regurgitation,
    e05_side_channel_introspection,
    e06_auth_boundary_leak,
    e07_ext_credential_leak,
    e08_role_assumption_chain,
    e09_schema_boundary_confusion,
)

__all__ = [
    "e01_system_prompt_leak",
    "e02_tool_schema_leak",
    "e03_rag_corpus_leak",
    "e04_training_data_regurgitation",
    "e05_side_channel_introspection",
    "e06_auth_boundary_leak",
    "e07_ext_credential_leak",
    "e08_role_assumption_chain",
    "e09_schema_boundary_confusion",
]
