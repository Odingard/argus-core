"""
argus.attacks — attack-orchestration primitives.

These are the building blocks that turn agents from single-shot
payload-firers into actual adversarial drivers. Most of ARGUS's
code lives in agents (what to attack), adapters (how to reach the
target), and corpus (what payloads to use). This module owns the
ORCHESTRATION layer — the "how many turns, read the response
between them, adapt" loop.

Current contents:

    ConversationPlan / ConversationTurn / MultiTurnDriver
        — drive a plan of N turns through a Session, abort
          early when an observer says to pivot.

Future (gap #4):
    AdaptiveAdversary — LLM-in-the-loop probe → observe → reason
        → next-probe driver.
"""
from argus.attacks.conversation import (
    ConversationPlan, ConversationTurn, MultiTurnDriver,
)
from argus.attacks.adaptive import (
    AdaptiveAdversary, AdversaryGoal, AdversaryResult,
)
from argus.attacks.judge import (
    LLMJudge, JudgeInput,
)

__all__ = [
    "ConversationPlan", "ConversationTurn", "MultiTurnDriver",
    "AdaptiveAdversary", "AdversaryGoal", "AdversaryResult",
    "LLMJudge", "JudgeInput",
]
