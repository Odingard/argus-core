"""Layer 2 — Contextual & Semantic Injection.

Importing this package registers all 11 Layer-2 attack classes with the
core registry. Total target: 4,150 deterministic variants.

Class roster:

  c01  ci-multi-token-delimiter            1,000
  c02  ci-cross-prompt-scripting             500
  c03  ci-rag-semantic-desensitization     1,200
  c04  ci-indirect-payload-splitting         300
  c05  ci-schema-level-pi                    250
  c06  ci-rag-direct-poisoning               250
  c07  ci-rag-embedding-drift                150
  c08  ci-context-window-stuffing            150
  c09  ci-conversation-history-forgery       100
  c10  ci-inline-tool-result-injection       100
  c11  ci-tool-result-rag-feedback           150
                                          -----
                                          4,150
"""

from . import (  # noqa: F401  -- side-effect imports register all classes
    c01_multi_token_delimiter,
    c02_cross_prompt_scripting,
    c03_rag_semantic_desensitization,
    c04_indirect_payload_splitting,
    c05_schema_level_pi,
    c06_rag_direct_poisoning,
    c07_rag_embedding_drift,
    c08_context_window_stuffing,
    c09_conversation_history_forgery,
    c10_inline_tool_result_injection,
    c11_tool_result_rag_feedback,
)

__all__ = [
    "c01_multi_token_delimiter",
    "c02_cross_prompt_scripting",
    "c03_rag_semantic_desensitization",
    "c04_indirect_payload_splitting",
    "c05_schema_level_pi",
    "c06_rag_direct_poisoning",
    "c07_rag_embedding_drift",
    "c08_context_window_stuffing",
    "c09_conversation_history_forgery",
    "c10_inline_tool_result_injection",
    "c11_tool_result_rag_feedback",
]
