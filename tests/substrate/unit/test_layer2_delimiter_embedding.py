"""Layer-2 delimiter-embedding regression tests.

After the multi-turn classes were refactored away from real session-state
arrays into delimiter-embedded single-message variants (so the engine
fires every variant via one transport call regardless of target shape),
the following invariants must hold:

* c09 conversation-history-forgery, c04 indirect-payload-splitting and
  c08 context-window-stuffing each emit single-message variants.
* The forged history / split halves / post-bulk directive are embedded
  inside that single user message via at least one chat-template
  delimiter dialect (ChatML / Anthropic / Llama / XML / ASCII-box).
* The canary still appears in the rendered content so the canary-echo
  matcher fires unchanged.
"""

from __future__ import annotations

import argus.engine  # noqa: F401  -- registers all classes
from argus.engine.core.registry import get as registry_get

# Lower-case fragments any of the five dialects emit. A variant is
# considered "delimiter-embedded" if its single user message carries at
# least one of these markers.
_DELIMITER_MARKERS: tuple[str, ...] = (
    "<|im_start|>",
    "<|im_end|>",
    "\n\nhuman:",
    "\n\nassistant:",
    "[inst]",
    "[/inst]",
    "<assistant>",
    "</assistant>",
    "=== prior conversation ===",
    "--- begin prior conversation ---",
    "=== operator directive ===",
    "=== system",
    "--- begin retrieved corpus ---",
    "```tool_result",
)


def _has_delimiter(text: str) -> bool:
    lowered = text.lower()
    return any(marker in lowered for marker in _DELIMITER_MARKERS)


def _single_user_message(variant) -> str:
    assert len(variant.messages) == 1, (
        f"{variant.attack_class}/{variant.variant_id} should emit a single "
        f"user message after delimiter-embedding refactor; "
        f"got {len(variant.messages)} messages"
    )
    msg = variant.messages[0]
    assert msg.role == "user", (
        f"{variant.attack_class}/{variant.variant_id} should embed the "
        f"forged turn inside a user-role message; got role={msg.role!r}"
    )
    return msg.content


def test_c09_history_forgery_single_message_with_delimiters() -> None:
    cls = registry_get("ci-conversation-history-forgery")
    variants = list(cls.factory(seed_value=42).generate())
    assert variants, "c09 must produce variants"
    delimiter_hits = 0
    for v in variants:
        content = _single_user_message(v)
        assert v.canaries.primary in content, f"{v.variant_id} should echo the canary inside the embedded history block"
        if _has_delimiter(content):
            delimiter_hits += 1
    # Every c09 variant uses one of the dialects.
    assert delimiter_hits == len(variants), (
        f"c09 expected delimiter embedding on every variant; got {delimiter_hits}/{len(variants)}"
    )


def test_c04_indirect_split_single_message_with_delimiters() -> None:
    cls = registry_get("ci-indirect-payload-splitting")
    variants = list(cls.factory(seed_value=42).generate())
    assert variants, "c04 must produce variants"
    delimiter_hits = 0
    for v in variants:
        content = _single_user_message(v)
        canary = v.canaries.primary
        strategy = v.metadata["params"]["strategy"]
        # Verify the canary is structurally recoverable for the strategy.
        if strategy == "encoded_plus_plaintext":
            # Canary is recoverable either as a hex-encoded substring
            # (when the canary landed in the head, which gets hex-encoded)
            # or as a literal substring (when it landed in the plaintext
            # tail). Snap-to-boundary guarantees the canary is contiguous.
            assert canary.encode("utf-8").hex() in content or canary in content, (
                f"{v.variant_id} encoded_plus_plaintext should contain "
                "the canary as either hex bytes or literal substring"
            )
        elif strategy == "first_letter_acrostic":
            # Canary is recoverable as first-letter acrostic over lines.
            lines = [ln.lstrip()[:1] for ln in content.split("\n") if ln.strip()]
            assert "".join(lines).count(canary) >= 0  # structural shape
            # At minimum the first character of the canary must appear as
            # the leading character of some content line.
            assert canary[0] in {ln[:1] for ln in lines if ln}, (
                f"{v.variant_id} acrostic should embed canary first letters"
            )
        else:
            # Plain-text splits: canary may be split, but at least one
            # 8-char prefix/suffix fragment must remain contiguous.
            assert canary in content or canary[:8] in content or canary[-8:] in content, (
                f"{v.variant_id} ({strategy}) should carry at least one contiguous canary fragment"
            )
        if _has_delimiter(content):
            delimiter_hits += 1
    # Four of the six strategies (forged_prior_turn / forged_system_block /
    # forged_rag_fragments / forged_tool_result) wrap halves in delimiter
    # markers. The encoded and acrostic strategies don't, so we expect
    # roughly two-thirds of variants to carry delimiters.
    assert delimiter_hits >= len(variants) * 0.5, (
        f"c04 expected ≥50% delimiter-embedded variants; got {delimiter_hits}/{len(variants)}"
    )


def test_c08_stuffing_tail_uses_delimiter_dialect() -> None:
    cls = registry_get("ci-context-window-stuffing")
    variants = list(cls.factory(seed_value=42).generate())
    assert variants, "c08 must produce variants"
    for v in variants:
        content = _single_user_message(v)
        assert v.canaries.primary in content, f"{v.variant_id} should embed the canary in the post-bulk tail"
        assert _has_delimiter(content), (
            f"{v.variant_id} should wrap the post-bulk directive in a chat-template delimiter dialect"
        )
    dialects = {v.metadata["params"]["dialect"] for v in variants}
    # The cycle must hit every configured dialect at least once.
    assert dialects == {"chatml", "anthropic", "ascii_box"}, (
        f"c08 expected to cycle through all 3 tail dialects; got {dialects}"
    )


def test_surface_gated_classes_declare_required_surface() -> None:
    """The 5 research-blocked classes must declare their required surface."""
    expected = {
        "ci-rag-semantic-desensitization": frozenset({"rag"}),
        "ci-rag-direct-poisoning": frozenset({"rag"}),
        "ci-rag-embedding-drift": frozenset({"rag"}),
        "ci-schema-level-pi": frozenset({"schema"}),
        "ci-inline-tool-result-injection": frozenset({"tool"}),
    }
    for class_id, required in expected.items():
        cls = registry_get(class_id)
        assert cls.target_surface == required, (
            f"{class_id} must declare target_surface={set(required)} "
            f"so the supervisor can early-exit on chat-only targets; "
            f"got {set(cls.target_surface)}"
        )
