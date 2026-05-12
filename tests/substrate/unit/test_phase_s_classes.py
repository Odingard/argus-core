"""Phase S — class-level regression tests.

Pins, per Andre's Phase-S design lock:

* **Class registration** — all 6 Phase-S classes resolve via
  :func:`argus.engine.core.registry.get`.
* **Carrier surfaces** — each class declares the exact
  ``carrier_surfaces`` set Andre specified in the design lock:

  ============================  ====================================
  class                          surfaces
  ============================  ====================================
  cog-epistemic-confidence-drain all 5
  cog-authority-laundering       roleplay_persona + system_reflection
                                 + tool_result (indirect-only)
  cog-socratic-extraction        all 5
  cog-benign-pretext-switch      all 5
  ext-role-assumption-chain      all 5
  ext-schema-boundary-confusion  tool_result + system_reflection
                                 (auth-boundary context)
  ============================  ====================================

* **Arc-native flags** — 3 classes are arc-native (socratic +
  benign + role-assumption); 3 are not (epistemic-drain +
  authority-laundering + schema-boundary).
* **Rapport refusal policy** — socratic / benign use ``retry_alt``;
  role-assumption uses ``abort``; non-arc classes are unaffected.
* **Matcher wiring** — each class declares its expected matcher_ids
  in its variant ``matcher_ids`` field so the supervisor knows
  which structural matchers to evaluate the probe with.
* **Determinism** — same seed → same variant set (rule #7).
* **Canary preservation** — Phase-S variants render their canary
  inline in at least one message (rule #4).
"""

from __future__ import annotations

import argus.engine  # noqa: F401 -- registers all classes
from argus.engine.core.registry import get as registry_get

ALL_CARRIERS = frozenset(
    {
        "user_turn",
        "tool_result",
        "rag_document",
        "roleplay_persona",
        "system_reflection",
    }
)

PHASE_S_EXPECTED = {
    "cog-epistemic-confidence-drain": {
        "layer": "layer3_cognitive",
        "carriers": ALL_CARRIERS,
        "arc_native": False,
        "matchers_required": {"canary-echo", "hedge-density"},
    },
    "cog-authority-laundering": {
        "layer": "layer3_cognitive",
        "carriers": frozenset({"roleplay_persona", "system_reflection", "tool_result"}),
        "arc_native": False,
        "matchers_required": {"canary-echo", "authority-reference"},
    },
    "cog-socratic-extraction": {
        "layer": "layer3_cognitive",
        "carriers": ALL_CARRIERS,
        "arc_native": True,
        "rapport_refusal_policy": "retry_alt",
        "matchers_required": {"canary-echo"},
    },
    "cog-benign-pretext-switch": {
        "layer": "layer3_cognitive",
        "carriers": ALL_CARRIERS,
        "arc_native": True,
        "rapport_refusal_policy": "retry_alt",
        "matchers_required": {"canary-echo"},
    },
    "ext-role-assumption-chain": {
        "layer": "layer4_extraction",
        "carriers": ALL_CARRIERS,
        "arc_native": True,
        "rapport_refusal_policy": "abort",
        "matchers_required": {"canary-echo", "role-grant-confirmation"},
    },
    "ext-schema-boundary-confusion": {
        "layer": "layer4_extraction",
        "carriers": frozenset({"tool_result", "system_reflection"}),
        "arc_native": False,
        "matchers_required": {"canary-echo", "schema-ambiguity"},
    },
}


def _generate(class_id: str, seed: int = 42):
    cls = registry_get(class_id)
    return list(cls.factory(seed_value=seed).generate())


# --- registration & metadata ---------------------------------------


def test_all_phase_s_classes_registered() -> None:
    for class_id in PHASE_S_EXPECTED:
        assert registry_get(class_id) is not None, f"{class_id} missing from registry"


def test_phase_s_classes_attached_to_correct_layer() -> None:
    for class_id, spec in PHASE_S_EXPECTED.items():
        cls = registry_get(class_id)
        assert cls.layer == spec["layer"], f"{class_id} layer={cls.layer} expected={spec['layer']}"


def test_phase_s_carrier_surfaces_match_design_lock() -> None:
    for class_id, spec in PHASE_S_EXPECTED.items():
        cls = registry_get(class_id)
        assert cls.carrier_surfaces == spec["carriers"], (
            f"{class_id} carriers={sorted(cls.carrier_surfaces)} expected={sorted(spec['carriers'])}"
        )


def test_phase_s_arc_native_flags_match_design_lock() -> None:
    for class_id, spec in PHASE_S_EXPECTED.items():
        cls = registry_get(class_id)
        assert cls.arc_native is spec["arc_native"], (
            f"{class_id} arc_native={cls.arc_native} expected={spec['arc_native']}"
        )


def test_phase_s_rapport_refusal_policy_on_arc_native_classes() -> None:
    for class_id, spec in PHASE_S_EXPECTED.items():
        if not spec["arc_native"]:
            continue
        cls = registry_get(class_id)
        assert cls.rapport_refusal_policy == spec["rapport_refusal_policy"], (
            f"{class_id} rapport_refusal_policy={cls.rapport_refusal_policy} expected={spec['rapport_refusal_policy']}"
        )


def test_phase_s_non_arc_classes_keep_default_policy() -> None:
    """Non-arc classes shouldn't override rapport_refusal_policy — the
    field is ignored when arc_native=False but a non-default value
    would imply intent the supervisor never honours."""
    for class_id, spec in PHASE_S_EXPECTED.items():
        if spec["arc_native"]:
            continue
        cls = registry_get(class_id)
        assert cls.rapport_refusal_policy == "abort", (
            f"{class_id} non-arc class must keep default policy 'abort', got {cls.rapport_refusal_policy}"
        )


# --- variant-level invariants --------------------------------------


def test_phase_s_variants_declare_required_matchers() -> None:
    for class_id, spec in PHASE_S_EXPECTED.items():
        variants = _generate(class_id)
        assert variants, f"{class_id} produced 0 variants"
        sample = variants[0]
        declared = set(sample.matcher_ids)
        missing = spec["matchers_required"] - declared
        assert not missing, f"{class_id} variants missing matchers: {missing} (declared: {declared})"


def test_phase_s_variants_are_deterministic() -> None:
    for class_id in PHASE_S_EXPECTED:
        a = [v.variant_id for v in _generate(class_id, seed=42)]
        b = [v.variant_id for v in _generate(class_id, seed=42)]
        assert a == b, f"{class_id} non-deterministic with seed=42"


def test_phase_s_variant_ids_unique_within_class() -> None:
    for class_id in PHASE_S_EXPECTED:
        ids = [v.variant_id for v in _generate(class_id)]
        assert len(ids) == len(set(ids)), f"{class_id} has duplicate variant_ids"


def test_phase_s_canary_present_in_rendered_messages() -> None:
    """Rule #4 — every variant must carry its canary inside the
    rendered messages (verifiable structural anchor)."""
    for class_id in PHASE_S_EXPECTED:
        for v in _generate(class_id):
            if v.canaries is None:
                continue
            primary = v.canaries.primary
            joined = "\n".join(m.content for m in v.messages)
            assert primary in joined, f"{class_id}/{v.variant_id} canary {primary} not rendered"


def test_phase_s_no_literal_canary_placeholder_leaks() -> None:
    """Rule #4 / #9 — no raw `{canary}` placeholders survive
    rendering."""
    for class_id in PHASE_S_EXPECTED:
        for v in _generate(class_id):
            for msg in v.messages:
                assert "{canary}" not in msg.content, f"{class_id}/{v.variant_id} leaked literal {{canary}} placeholder"


def test_phase_s_variants_emit_at_least_one_message() -> None:
    """Every Phase-S variant emits at least one rendered message.

    Arc-native variants emit a single seed payload that the
    Phase-Q ArcRunner unrolls into the 5-stage canonical arc at
    execution time (rapport → persona_seed → boundary_probe →
    boundary_erode → extract); the variant itself is a single
    message addressed at the model with the canary already
    rendered (rule #4). Stage expansion lives in the runner, not
    in the catalog (rule #7 — same seed → same variant set).
    """
    for class_id in PHASE_S_EXPECTED:
        for v in _generate(class_id):
            assert len(v.messages) >= 1, f"{class_id}/{v.variant_id} no messages rendered"


def test_phase_s_messages_are_user_role() -> None:
    """Phase S variants address the model via the user channel; no
    variant should emit a fabricated assistant/system turn that
    would leak through carriers."""
    for class_id in PHASE_S_EXPECTED:
        for v in _generate(class_id):
            for msg in v.messages:
                assert msg.role in {"user", "system"}, (
                    f"{class_id}/{v.variant_id} produced message role="
                    f"{msg.role!r} — phase S classes use user/system turns only"
                )


# --- carrier surface integration -----------------------------------


def test_phase_s_carrier_surfaces_are_subset_of_known_surfaces() -> None:
    for class_id in PHASE_S_EXPECTED:
        cls = registry_get(class_id)
        assert cls.carrier_surfaces.issubset(ALL_CARRIERS), (
            f"{class_id} carriers={cls.carrier_surfaces} contains unknown surface"
        )


def test_authority_laundering_uses_only_indirect_carriers() -> None:
    """Andre's design lock: authority-laundering must NOT be
    available via the user_turn or rag_document carriers — the
    fabricated-authority shape needs a trusted-context wrapper to
    land."""
    cls = registry_get("cog-authority-laundering")
    assert "user_turn" not in cls.carrier_surfaces, (
        "cog-authority-laundering must not declare user_turn — fabricated authority needs an indirect carrier wrapper"
    )
    assert "rag_document" not in cls.carrier_surfaces, (
        "cog-authority-laundering must not declare rag_document — "
        "design lock restricted to roleplay/reflection/tool surfaces"
    )


def test_schema_boundary_confusion_restricted_to_auth_carriers() -> None:
    """Andre's design lock: schema-boundary-confusion only renders
    through tool_result / system_reflection — the auth boundary
    only exists on those surfaces."""
    cls = registry_get("ext-schema-boundary-confusion")
    assert cls.carrier_surfaces == frozenset({"tool_result", "system_reflection"}), (
        f"ext-schema-boundary-confusion carriers={sorted(cls.carrier_surfaces)} "
        "expected={'tool_result','system_reflection'}"
    )
