"""Layer 5 — Orchestration.

Importing this package registers all 6 Layer-5 attack classes with the
core registry. Total target: 1,700 deterministic variants across
multi-agent trust-seam attacks. Distinct from Layer 4 (single-model
disclosure boundary): Layer 5 attacks the **inter-agent contract**
itself — the envelope shape, authority frame, channel separation, and
sibling-recognition convention by which agents trust each other inside
a multi-agent system.

Class roster:

  o01  mas-handoff-hijack            350
  o02  mas-supervisor-override       300
  o03  mas-second-order-injection    300
  o04  mas-trust-pivot               250
  o05  mas-sandbox-escape            300
  o06  mas-a2a-token-replay          200
                                  -----
                                  1,700

Carrier-agnostic invariants. Each class names 3+ real-world surfaces
in its module docstring and is regression-guarded by stub harnesses
in tests/integration/stubs/layer5_carriers.py that verify variants
fire across carriers without keyword overfitting.

The new universal mutator ``MultiAgentEnvelopeMutator`` (in
``argus.engine.core.mutator``) produces the five envelope styles
each Layer-5 class composes around its inner pattern × indirection ×
persona × payload axes. The envelope axis is structurally distinct
from the existing schema / encoding / role / persona / language
mutators and is reused by every Layer-5 class.
"""

from . import (  # noqa: F401  -- side-effect imports register all classes
    o01_handoff_hijack,
    o02_supervisor_override,
    o03_second_order_injection,
    o04_trust_pivot,
    o05_mas_sandbox_escape,
    o06_a2a_token_replay,
)

__all__ = [
    "o01_handoff_hijack",
    "o02_supervisor_override",
    "o03_second_order_injection",
    "o04_trust_pivot",
    "o05_mas_sandbox_escape",
    "o06_a2a_token_replay",
]
