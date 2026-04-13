"""CONDUCTOR — Multi-Turn Attack Session Orchestrator.

The browser-automation-equivalent of ARGUS's toolchain. CONDUCTOR lets
attack agents drive stateful, multi-turn conversations with target AI
systems — required for Memory Poisoning, Identity Spoof, Context Window,
and any other Phase 2+ agent that depends on cross-turn state.

Core abstractions:
  - ConversationSession: stateful HTTP transport with shared headers,
    request history, and JSON body convention
  - TurnSpec: a single request in a sequence (path, method, body, headers)
  - TurnResult: structured response with parsed JSON, status, latency
  - AttackSequence: ordered list of TurnSpec — runs them, collects results
  - ResponseMatcher: pattern matchers (substring, regex, JSON path, sensitive marker)

Design notes:
  - Pure HTTP/JSON — no MCP-specific logic. CONDUCTOR talks to /chat,
    /execute, /memory/add type endpoints.
  - SSRF guard: ConversationSession only accepts the base URL passed at
    construction. Per-turn paths are resolved against that base.
  - Truncates response bodies to prevent memory exhaustion from huge targets.
  - No retries by default — attack agents decide when to back off.
  - Generic — does NOT hardcode benchmark canary tokens, scenario IDs, or
    target-specific paths. Per the no-benchmark-gaming rule.
"""

from argus.conductor.evaluation import (
    BehaviorEvaluator,
    EvalResult,
    EvalSpec,
    RunRecord,
    ToolCall,
    quick_eval,
)
from argus.conductor.session import (
    AttackSequence,
    ConversationSession,
    ResponseMatcher,
    TurnResult,
    TurnSpec,
)

__all__ = [
    "AttackSequence",
    "BehaviorEvaluator",
    "ConversationSession",
    "EvalResult",
    "EvalSpec",
    "ResponseMatcher",
    "RunRecord",
    "ToolCall",
    "TurnResult",
    "TurnSpec",
    "quick_eval",
]
