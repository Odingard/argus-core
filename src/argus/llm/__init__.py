"""ARGUS LLM Client — optional augmentation layer.

ARGUS runs autonomously WITHOUT an API key by default. The LLM is
augmentation, not the engine. The deterministic core (corpus + scanners
+ canary detection) does the actual work; the LLM adds:

- Novel attack variant generation
- Semantic judgment of ambiguous findings
- Target simulation when no real endpoint is provided
- Compound attack chain reasoning (Correlation Agent)

Usage:
    from argus.llm import get_llm_client

    client = get_llm_client()
    if client.available:
        response = await client.generate(system_prompt="...", user_prompt="...")
    else:
        # Fall back to deterministic path
        ...
"""

from argus.llm.client import LLMClient, LLMMode, get_llm_client

__all__ = ["LLMClient", "LLMMode", "get_llm_client"]
