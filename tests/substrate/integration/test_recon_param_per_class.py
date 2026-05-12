"""Per-class recon-param adoption tests.

For each of the 10 adopting classes, assert that:

* the class registry advertises ``recon_aware=True``;
* invoking ``factory(seed_value, recon=<profile>)`` produces a deterministic
  variant set;
* at least one variant body contains a recon-derived artefact substring
  (proof that the recon profile actually flowed into the rendered text).
"""

from __future__ import annotations

import pytest

import argus.engine  # noqa: F401  -- registers all classes
from argus.engine.core.recon_profile import ReconProfile
from argus.engine.core.registry import get


def _bodies(generator) -> list[str]:
    out: list[str] = []
    for v in generator.generate():
        for m in v.messages:
            if isinstance(m, dict):
                out.append(str(m.get("content", "")))
            else:
                content = getattr(m, "content", "")
                out.append(str(content))
        for t in v.tools:
            out.append(str(getattr(t, "name", "")))
            out.append(str(getattr(t, "description", "")))
            out.append(str(getattr(t, "parameters_schema", "")))
            out.append(str(getattr(t, "annotations", "")))
        for r in v.resources:
            out.append(str(getattr(r, "uri", "")))
            out.append(str(getattr(r, "description", "")))
            out.append(str(getattr(r, "annotations", "")))
        for doc in v.rag_corpus:
            out.append(str(doc))
    return out


def _all_text(generator) -> str:
    return "\n".join(_bodies(generator))


ADOPTING_CLASSES: list[str] = [
    "tp-protocol-exploit",
    "tp-schema-shadowing",
    "tp-resource-stego",
    "ci-rag-direct-poisoning",
    "cog-counterfactual-priming",
    "cog-self-consistency-exploit",
    "ext-system-prompt-leak",
    "ext-tool-schema-leak",
    "mas-handoff-hijack",
    "mas-trust-pivot",
]


def test_all_adopting_classes_marked_recon_aware():
    for class_id in ADOPTING_CLASSES:
        cls = get(class_id)
        assert cls.recon_aware is True, f"{class_id} missing recon_aware=True"


@pytest.mark.parametrize(
    ("class_id", "profile_kwargs", "expected_substring"),
    [
        (
            "tp-protocol-exploit",
            {"tool_names": ("argus_calculator",)},
            "argus_calculator",
        ),
        (
            "tp-schema-shadowing",
            {"tool_names": ("argus_calculator",)},
            "argus_calculator",
        ),
        (
            "tp-resource-stego",
            {"resource_uris": ("file:///etc/argus/policy",)},
            "file:///etc/argus/policy",
        ),
        (
            "ci-rag-direct-poisoning",
            {"rag_corpus_excerpts": ("Argus runbook section 4.2 — incident triage policy.",)},
            "Argus runbook section 4.2",
        ),
        (
            "cog-counterfactual-priming",
            {"persona_fragments": ("ArgusAuthBot",)},
            "ArgusAuthBot",
        ),
        (
            "cog-self-consistency-exploit",
            {"framework_hints": ("argus-langchain-runtime",)},
            "argus-langchain-runtime",
        ),
        (
            "ext-system-prompt-leak",
            {
                "persona_fragments": ("ArgusAuthBot",),
                "framework_hints": ("argus-runtime",),
            },
            "ArgusAuthBot",
        ),
        (
            "ext-tool-schema-leak",
            {"tool_parameter_keys": ("argus_param_x",)},
            "argus_param_x",
        ),
        (
            "mas-handoff-hijack",
            {"agent_role_names": ("ArgusRouter",)},
            "ArgusRouter",
        ),
        (
            "mas-trust-pivot",
            {"agent_envelope_styles": ("__ARGUS_PIVOT_ENVELOPE__",)},
            "__ARGUS_PIVOT_ENVELOPE__",
        ),
    ],
)
def test_adopting_class_embeds_recon_artefact(class_id: str, profile_kwargs: dict, expected_substring: str):
    cls = get(class_id)
    profile = ReconProfile(**profile_kwargs)
    text = _all_text(cls.factory(seed_value=42, recon=profile))
    assert expected_substring in text, (
        f"{class_id} did not embed recon artefact {expected_substring!r}; sample={text[:300]!r}"
    )


@pytest.mark.parametrize("class_id", ADOPTING_CLASSES)
def test_adopting_class_deterministic_under_recon(class_id: str):
    cls = get(class_id)
    profile = ReconProfile(
        tool_names=("argus_calculator",),
        resource_uris=("file:///etc/argus/policy",),
        rag_corpus_excerpts=("Argus runbook section 4.2 — incident triage policy.",),
        persona_fragments=("ArgusAuthBot",),
        framework_hints=("argus-langchain-runtime",),
        tool_parameter_keys=("argus_param_x",),
        agent_role_names=("ArgusRouter",),
        agent_envelope_styles=("__ARGUS_PIVOT_ENVELOPE__",),
    )
    a = [v.variant_id for v in cls.factory(seed_value=42, recon=profile).generate()]
    b = [v.variant_id for v in cls.factory(seed_value=42, recon=profile).generate()]
    assert a == b, f"{class_id} non-deterministic under recon"
    assert len(a) >= 100, f"{class_id} produced suspiciously few variants ({len(a)})"
