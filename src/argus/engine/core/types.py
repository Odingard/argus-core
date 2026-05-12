"""Common type aliases used across the engine."""

from __future__ import annotations

from typing import Literal

Confidence = Literal["IRREFUTABLE", "HIGH", "MEDIUM", "LOW"]
"""Strict confidence ladder per AGENTS.md."""


LayerId = Literal[
    "layer1_tool_poisoning",
    "layer2_contextual_injection",
    "layer3_cognitive",
    "layer4_extraction",
    "layer5_orchestration",
]


Role = Literal["system", "user", "assistant", "tool"]


TransportName = Literal["openai", "anthropic", "ollama", "mcp"]
