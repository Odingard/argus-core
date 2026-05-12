"""Multi-carrier stub harnesses for Layer-4 carrier-agnostic validation.

Each Layer-4 attack class ships with 3 carrier-shape renders (see the
``layer4_*`` modules in this package). The stubs are deliberately
minimal pure-Python functions that take a Variant and return a
carrier-shaped payload string. The integration tests in
``tests/integration/test_layer4_carrier_invariance.py`` verify that
every Layer-4 variant fires (produces a non-empty payload containing
the canary) across all 3 carriers per class — the carrier-agnostic
invariant that prevents bench-keyword overfitting.

Why string output and not Python objects: the rename test asserts that
swapping carrier-specific keys (e.g. OpenAI's ``"instructions"``
field for Anthropic's ``"system"`` field) does not change which
variants fire. Comparing rendered string outputs makes that
invariant easy to express.
"""

from __future__ import annotations

__all__: list[str] = []
