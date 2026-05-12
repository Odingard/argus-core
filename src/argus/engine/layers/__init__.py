"""Layer registries — importing this package registers every attack class.

Layers are shipped in order; each is benchmark-validated before the next
begins. Subsequent layers are added in follow-up PRs after Andre validates
the previous layer against the ARGUS benchmark.
"""

from . import (
    layer1_tool_poisoning,  # noqa: F401  -- registers Layer-1 classes
    layer2_contextual_injection,  # noqa: F401  -- registers Layer-2 classes
    layer3_cognitive,  # noqa: F401  -- registers Layer-3 classes
    layer4_extraction,  # noqa: F401  -- registers Layer-4 classes
    layer5_orchestration,  # noqa: F401  -- registers Layer-5 classes
)

__all__ = [
    "layer1_tool_poisoning",
    "layer2_contextual_injection",
    "layer3_cognitive",
    "layer4_extraction",
    "layer5_orchestration",
]
