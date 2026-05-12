"""Path 1 neutral-framing per-class divergence tests.

For each of the six classes whose mutator was rewritten under the
recon-substrate redesign (e01/e02/o01/o04/c03/c05), pin two invariants:

1. **Structural divergence under recon.** A variant fired with a
   non-empty ``ReconProfile`` carries the recon artefact in a
   neutral-framing surface (``system`` message, tool stub schema,
   citation block) — not as a user-prompt directive ahead of the
   probe. The Path 1 redesign moves recon out of content-side
   directives because PR #13's live-fire data showed those directives
   tripped RLHF refusal heuristics ahead of the probe.

2. **Bit-identical baseline.** A variant fired without ``recon=`` is
   byte-identical to the pre-redesign baseline shape — same single
   ``user`` message, no system manifest, no tool stub, no citation.
   This is the AGENTS.md backward-compat contract: classes not in
   ``recon_aware_classes`` must behave identically to the recon=OFF
   arm of every live-fire A/B run on file.

The ten-class generic invariants (recon artefact appears somewhere in
the variant; variant_ids deterministic under recon) are pinned in
``tests/integration/test_recon_param_per_class.py``.
"""

from __future__ import annotations

import argus.engine  # noqa: F401  -- registers all classes
from argus.engine.core.recon_profile import ReconProfile
from argus.engine.core.registry import get


def _first_variant(class_id: str, *, recon: ReconProfile | None = None):
    cls = get(class_id)
    gen = cls.factory(seed_value=42, recon=recon) if recon else cls.factory(seed_value=42)
    return next(iter(gen.generate()))


def _user_messages(variant) -> list[str]:
    return [m.content for m in variant.messages if m.role == "user"]


def _system_messages(variant) -> list[str]:
    return [m.content for m in variant.messages if m.role == "system"]


# ---------- e01: system-prompt-leak — Path 1a system-slot framing -----------


def test_e01_recon_emits_system_manifest() -> None:
    profile = ReconProfile(persona_fragments=("ArgusAuthBot",), framework_hints=("argus-runtime",))
    v = _first_variant("ext-system-prompt-leak", recon=profile)
    sys_msgs = _system_messages(v)
    user_msgs = _user_messages(v)

    assert sys_msgs, "Path 1a requires a separate system manifest message"
    assert any("ArgusAuthBot" in m or "argus-runtime" in m for m in sys_msgs)
    # Recon artefact must NOT appear inline in the user prompt directive —
    # that was the PR #13 substrate failure shape.
    assert not any(m.startswith("As ArgusAuthBot") for m in user_msgs)


def test_e01_baseline_has_no_system_manifest() -> None:
    v = _first_variant("ext-system-prompt-leak")
    assert _system_messages(v) == [], "baseline (recon=None) must not emit a system manifest"


# ---------- e02: tool-schema-leak — Path 1b tool-call framing ---------------


def test_e02_recon_emits_param_introspect_tool_stub() -> None:
    profile = ReconProfile(tool_parameter_keys=("argus_param_x", "argus_param_y"))
    v = _first_variant("ext-tool-schema-leak", recon=profile)
    tool_names = [t.name for t in v.tools]

    assert "argus_param_introspect" in tool_names, "Path 1b tool stub missing under recon"
    properties = next(
        (t.parameters_schema.get("properties", {}) for t in v.tools if t.name == "argus_param_introspect"),
        {},
    )
    assert "argus_param_x" in properties
    # Recon parameter keys must NOT appear inline as a "Confirm in particular
    # the parameter keys X..." directive — that was the PR #13 failure shape.
    body = " ".join(_user_messages(v))
    assert "Confirm in particular the parameter keys" not in body


def test_e02_baseline_has_no_param_introspect_tool() -> None:
    v = _first_variant("ext-tool-schema-leak")
    tool_names = [t.name for t in v.tools]
    assert "argus_param_introspect" not in tool_names


# ---------- o01: handoff-hijack — Path 1c citation framing ------------------


def test_o01_recon_emits_citation_block() -> None:
    profile = ReconProfile(agent_role_names=("ArgusRouter",))
    v = _first_variant("mas-handoff-hijack", recon=profile)
    body = " ".join(_user_messages(v))

    assert "[ref: ArgusRouter]" in body, "Path 1c requires a [ref: <role>] citation"
    # Authority slot must not have been spliced with the recon role —
    # that was the slot-substitution shape that triggered PR #13 refusals.
    assert "ArgusRouter (" not in body


def test_o01_baseline_has_no_citation_block() -> None:
    v = _first_variant("mas-handoff-hijack")
    body = " ".join(_user_messages(v))
    assert "[ref:" not in body


# ---------- o04: trust-pivot — Path 1c citation framing ---------------------


def test_o04_recon_emits_xref_citation() -> None:
    profile = ReconProfile(
        agent_role_names=("ArgusRouter",),
        agent_envelope_styles=("__ARGUS_PIVOT_ENVELOPE__",),
    )
    v = _first_variant("mas-trust-pivot", recon=profile)
    body = " ".join(_user_messages(v))

    assert "[xref:" in body, "Path 1c requires an [xref: ...] citation block"
    assert "role=ArgusRouter" in body
    assert "envelope=__ARGUS_PIVOT_ENVELOPE__" in body
    # Envelope must not have been prepended above the directive — that was
    # the PR #13 shape that surfaced recon ahead of the probe.
    assert not body.startswith("__ARGUS_PIVOT_ENVELOPE__")


def test_o04_baseline_has_no_xref_citation() -> None:
    v = _first_variant("mas-trust-pivot")
    body = " ".join(_user_messages(v))
    assert "[xref:" not in body


# ---------- c03: self-consistency-exploit — Path 1a system-slot framing -----


def test_c03_recon_emits_system_manifest() -> None:
    profile = ReconProfile(framework_hints=("argus-langchain-runtime",))
    v = _first_variant("cog-self-consistency-exploit", recon=profile)
    sys_msgs = _system_messages(v)
    user_msgs = _user_messages(v)

    assert any("argus-langchain-runtime" in m for m in sys_msgs)
    # User prompt must not begin with the "Operating under <framework>." preamble.
    assert not any(m.startswith("Operating under argus-langchain-runtime") for m in user_msgs)


def test_c03_baseline_has_no_system_manifest() -> None:
    v = _first_variant("cog-self-consistency-exploit")
    assert _system_messages(v) == []


# ---------- c05: counterfactual-priming — Path 1a system-slot framing -------


def test_c05_recon_emits_system_manifest() -> None:
    profile = ReconProfile(persona_fragments=("ArgusAuthBot",))
    v = _first_variant("cog-counterfactual-priming", recon=profile)
    sys_msgs = _system_messages(v)
    user_msgs = _user_messages(v)

    assert any("ArgusAuthBot" in m for m in sys_msgs)
    # User prompt must not begin with the "As <persona>," preamble.
    assert not any(m.startswith("As ArgusAuthBot") for m in user_msgs)


def test_c05_baseline_has_no_system_manifest() -> None:
    v = _first_variant("cog-counterfactual-priming")
    assert _system_messages(v) == []


# ---------- 4-class structural-Path-1b coverage (c01/c02/c04/c06) ----------


def test_c01_recon_artefact_in_tool_schema_not_body() -> None:
    profile = ReconProfile(tool_names=("argus_calculator",))
    v = _first_variant("tp-protocol-exploit", recon=profile)
    tool_names = [t.name for t in v.tools]
    body = " ".join(_user_messages(v))

    assert any("argus_calculator" in n for n in tool_names)
    assert "argus_calculator" not in body


def test_c02_recon_artefact_in_tool_schema_not_body() -> None:
    profile = ReconProfile(tool_names=("argus_calculator",))
    v = _first_variant("tp-schema-shadowing", recon=profile)
    tool_names = [t.name for t in v.tools]
    body = " ".join(_user_messages(v))

    assert any("argus_calculator" in n for n in tool_names)
    assert "argus_calculator" not in body


def test_c04_recon_artefact_in_resource_uri_not_body() -> None:
    profile = ReconProfile(resource_uris=("file:///etc/argus/policy",))
    v = _first_variant("tp-resource-stego", recon=profile)
    resource_uris = [r.uri for r in v.resources]
    body = " ".join(_user_messages(v))

    assert any("file:///etc/argus/policy" in u for u in resource_uris)
    assert "file:///etc/argus/policy" not in body


def test_c06_recon_artefact_in_rag_corpus_not_directive() -> None:
    profile = ReconProfile(rag_corpus_excerpts=("Argus runbook section 4.2 — incident triage policy.",))
    v = _first_variant("ci-rag-direct-poisoning", recon=profile)
    body = " ".join(_user_messages(v))

    assert any("Argus runbook section 4.2" in doc for doc in v.rag_corpus)
    # The directive frames the corpus, not the recon excerpt.
    assert "Argus runbook section 4.2" not in body
