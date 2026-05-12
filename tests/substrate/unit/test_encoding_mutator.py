"""Encoding-mutator regression tests.

The encoding mutator already shipped with Layer 3 (PR #6).  This module
adds the missing test coverage for the two newly-registered
compositions and pins the cipher-stack invariants the layer3 build
quietly assumed.

Pinned invariants:
  * Every entry in ``_ENCODINGS`` resolves through ``_encode`` without
    raising — no orphaned registry entries.
  * ``_encode`` is deterministic for a fixed ``rng`` (AGENTS.md rule #7).
  * The Morse table covers every ASCII letter ``a-z``.
  * The two new compositions (``morse_then_rot13``, ``base64_then_morse``)
    differ from each component cipher in isolation — the composition is
    not silently equivalent to either step alone.  ``morse_then_rot13``
    is implemented as ``rot13(plaintext) -> Morse`` (Morse-first would
    no-op rot13 on the dots/dashes; see PR #9 fix-up commit).
  * ``EncodingMutator`` produces one variant per encoding (per repeat).
"""

from __future__ import annotations

import string
from random import Random

from argus.engine.core.seed import Seed
from argus.engine.mutators.encoding import _ENCODINGS, _MORSE, EncodingMutator, _encode


def _seed() -> Seed:
    return Seed(
        seed_id="enc-test-seed",
        attack_class="cog-chain-of-thought-hijack",
        layer="layer3_cognitive",
        version=1,
        template="hello world",
    )


def test_morse_table_covers_ascii_lowercase() -> None:
    """Morse must cover every ASCII letter or _encode falls back to ch."""
    missing = [ch for ch in string.ascii_lowercase if ch not in _MORSE]
    assert not missing, f"Morse table missing letters: {missing!r}"


def test_morse_encoding_is_deterministic() -> None:
    """Same input → same output, every time (AGENTS.md rule #7)."""
    rng = Random(0)
    a = _encode("morse", "the quick brown fox", rng)
    b = _encode("morse", "the quick brown fox", Random(99))
    c = _encode("morse", "the quick brown fox", rng)
    assert a == b == c
    # Spot-check a known segment ("the" = "- .... .").
    assert a.startswith("- .... .")


def test_morse_then_rot13_is_registered() -> None:
    assert "morse_then_rot13" in _ENCODINGS


def test_base64_then_morse_is_registered() -> None:
    assert "base64_then_morse" in _ENCODINGS


def test_morse_then_rot13_round_trip_deterministic() -> None:
    rng = Random(0)
    a = _encode("morse_then_rot13", "hello world", rng)
    b = _encode("morse_then_rot13", "hello world", Random(99))
    assert a == b


def test_morse_then_rot13_differs_from_plain_morse_for_letter_input() -> None:
    """The composition must produce a different Morse string than plain Morse.

    Implementation order is rot13(plaintext) -> Morse.  ``hello world``
    rot13s to ``uryyb jbeyq``; the Morse encoding of that string differs
    byte-for-byte from the Morse encoding of ``hello world`` because the
    underlying letters changed before the Morse table lookup.  Pinning
    this invariant prevents the no-op-composition regression that
    Devin Review caught on the first cut of this PR (Morse-then-rot13,
    where rot13 silently no-ops on dots/dashes).
    """
    rng = Random(0)
    plain_morse = _encode("morse", "hello world", rng)
    composed = _encode("morse_then_rot13", "hello world", rng)
    assert composed != plain_morse
    # Sanity: the composition equals plain Morse of the rot13'd source.
    rotated_morse = _encode("morse", "uryyb jbeyq", rng)
    assert composed == rotated_morse


def test_morse_then_rot13_passes_non_letters_through() -> None:
    """Non-letter characters must round-trip rot13 (no-op) and Morse (fallback).

    ``_MORSE`` has no digit entries and rot13 leaves digits untouched,
    so digits in the plaintext appear verbatim in the output.
    """
    rng = Random(0)
    composed = _encode("morse_then_rot13", "abc123", rng)
    # Letters get rot13'd then Morse-encoded.  Digits pass through both
    # steps unchanged.
    assert "1" in composed and "2" in composed and "3" in composed
    # And it must differ from plain Morse on the same input (because
    # the letters were rotated before encoding).
    plain_morse = _encode("morse", "abc123", rng)
    assert composed != plain_morse


def test_base64_then_morse_round_trip_deterministic() -> None:
    rng = Random(0)
    a = _encode("base64_then_morse", "hello world", rng)
    b = _encode("base64_then_morse", "hello world", Random(99))
    assert a == b
    # base64("hello world") = "aGVsbG8gd29ybGQ=".  The base64 alphabet
    # contains uppercase letters that Morse lower-cases before lookup,
    # so the encoded form must contain morse symbols (dots/dashes).
    assert "." in a or "-" in a


def test_base64_then_morse_differs_from_either_component_alone() -> None:
    """The composition must not be silently equivalent to either step."""
    rng = Random(0)
    just_b64 = _encode("base64", "hello world", rng)
    just_morse = _encode("morse", "hello world", rng)
    composed = _encode("base64_then_morse", "hello world", rng)
    assert composed != just_b64
    assert composed != just_morse


def test_all_registered_encodings_resolve_through_encode() -> None:
    """No orphan entries in ``_ENCODINGS`` that ``_encode`` doesn't handle."""
    rng = Random(0)
    for name in _ENCODINGS:
        # Should not raise.
        out = _encode(name, "abc", rng)
        assert isinstance(out, str)
        assert out  # non-empty


def test_encoding_mutator_emits_one_variant_per_encoding() -> None:
    """Default repeat=1 → exactly one variant per registered encoding."""
    mutator = EncodingMutator()
    rng = Random(0)
    variants = list(mutator.mutate(_seed(), rng))
    assert len(variants) == len(_ENCODINGS), f"expected {len(_ENCODINGS)} variants, got {len(variants)}"
    seen_encodings = {meta["encoding"] for _, _, meta in variants}
    assert seen_encodings == set(_ENCODINGS)


def test_encoding_mutator_includes_morse_compositions() -> None:
    """Mutator output must include the two new Morse compositions."""
    mutator = EncodingMutator()
    rng = Random(0)
    variants = list(mutator.mutate(_seed(), rng))
    encodings_seen = {meta["encoding"] for _, _, meta in variants}
    assert "morse_then_rot13" in encodings_seen
    assert "base64_then_morse" in encodings_seen


def test_encoding_mutator_is_deterministic() -> None:
    """Same seed + same Random → same variant set, byte-for-byte."""
    mutator = EncodingMutator()
    a = list(mutator.mutate(_seed(), Random(42)))
    b = list(mutator.mutate(_seed(), Random(42)))
    assert [(rendered, vid) for rendered, vid, _ in a] == [(rendered, vid) for rendered, vid, _ in b]
