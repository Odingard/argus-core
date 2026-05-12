"""Encoding mutator — wraps payload in cipher / steganographic encodings.

Used by Layer 3 class 3.2 (Translation/Cipher Pivot) and as a sub-mutator
across all layers when the seed wants to defeat input-side string filters.

Encodings shipped:
    rot13, rot_n (n=1..25), caesar_3, caesar_7, caesar_13,
    base64, base64_url, base32, base85,
    hex_lower, hex_upper,
    zero_width_split (insert ZWNBSP between chars),
    homoglyph (mixed-script lookalikes),
    leet_speak,
    null_byte_split,
    interleave_invisible (interleave U+2061 invisible-times),
    morse,
    binary,
    octal,
    reverse_text,
    word_reverse,
    syllable_split,
    base64_double,
    base64_then_rot13,
    morse_then_rot13,
    base64_then_morse,
    nato_phonetic,
    pig_latin,
    backwards_words,
    qwerty_shift,
    fullwidth,
    smallcaps,
    chunked_b64 (3-char chunks separated by spaces)
"""

from __future__ import annotations

import base64
import codecs
from collections.abc import Iterator
from random import Random
from typing import Any

from ..core.seed import Seed

_HOMOGLYPHS: dict[str, str] = {
    "a": "а",
    "c": "с",
    "e": "е",
    "o": "о",
    "p": "р",
    "y": "у",
    "x": "х",
    "i": "і",
    "s": "ѕ",
    "k": "к",
    "l": "ӏ",
    "h": "һ",
}

_LEET: dict[str, str] = {
    "a": "4",
    "e": "3",
    "i": "1",
    "o": "0",
    "s": "5",
    "t": "7",
    "g": "9",
    "b": "8",
}

_FULLWIDTH_OFFSET = 0xFEE0  # ASCII -> Halfwidth/Fullwidth Latin block

_SMALLCAPS: dict[str, str] = {
    "a": "ᴀ",
    "b": "ʙ",
    "c": "ᴄ",
    "d": "ᴅ",
    "e": "ᴇ",
    "f": "ꜰ",
    "g": "ɢ",
    "h": "ʜ",
    "i": "ɪ",
    "j": "ᴊ",
    "k": "ᴋ",
    "l": "ʟ",
    "m": "ᴍ",
    "n": "ɴ",
    "o": "ᴏ",
    "p": "ᴘ",
    "q": "ǫ",
    "r": "ʀ",
    "s": "s",
    "t": "ᴛ",
    "u": "ᴜ",
    "v": "ᴠ",
    "w": "ᴡ",
    "x": "x",
    "y": "ʏ",
    "z": "ᴢ",
}

_NATO: dict[str, str] = {
    "a": "Alpha",
    "b": "Bravo",
    "c": "Charlie",
    "d": "Delta",
    "e": "Echo",
    "f": "Foxtrot",
    "g": "Golf",
    "h": "Hotel",
    "i": "India",
    "j": "Juliet",
    "k": "Kilo",
    "l": "Lima",
    "m": "Mike",
    "n": "November",
    "o": "Oscar",
    "p": "Papa",
    "q": "Quebec",
    "r": "Romeo",
    "s": "Sierra",
    "t": "Tango",
    "u": "Uniform",
    "v": "Victor",
    "w": "Whiskey",
    "x": "X-ray",
    "y": "Yankee",
    "z": "Zulu",
}

_MORSE: dict[str, str] = {
    "a": ".-",
    "b": "-...",
    "c": "-.-.",
    "d": "-..",
    "e": ".",
    "f": "..-.",
    "g": "--.",
    "h": "....",
    "i": "..",
    "j": ".---",
    "k": "-.-",
    "l": ".-..",
    "m": "--",
    "n": "-.",
    "o": "---",
    "p": ".--.",
    "q": "--.-",
    "r": ".-.",
    "s": "...",
    "t": "-",
    "u": "..-",
    "v": "...-",
    "w": ".--",
    "x": "-..-",
    "y": "-.--",
    "z": "--..",
}

_QWERTY = "qwertyuiopasdfghjklzxcvbnm"


def _rot_n(text: str, n: int) -> str:
    out = []
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - ord("a") + n) % 26 + ord("a")))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - ord("A") + n) % 26 + ord("A")))
        else:
            out.append(ch)
    return "".join(out)


def _qwerty_shift(text: str, n: int) -> str:
    out = []
    for ch in text:
        low = ch.lower()
        if low in _QWERTY:
            idx = _QWERTY.index(low)
            shifted = _QWERTY[(idx + n) % len(_QWERTY)]
            out.append(shifted.upper() if ch.isupper() else shifted)
        else:
            out.append(ch)
    return "".join(out)


def _encode(name: str, text: str, rng: Random) -> str:
    """Apply a single encoding to ``text`` and return the encoded string."""
    if name == "rot13":
        return codecs.encode(text, "rot_13")
    if name.startswith("rot_") and name[4:].isdigit():
        return _rot_n(text, int(name[4:]))
    if name == "caesar_3":
        return _rot_n(text, 3)
    if name == "caesar_7":
        return _rot_n(text, 7)
    if name == "caesar_13":
        return _rot_n(text, 13)
    if name == "base64":
        return base64.b64encode(text.encode()).decode()
    if name == "base64_url":
        return base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")
    if name == "base32":
        return base64.b32encode(text.encode()).decode()
    if name == "base85":
        return base64.b85encode(text.encode()).decode()
    if name == "hex_lower":
        return text.encode().hex()
    if name == "hex_upper":
        return text.encode().hex().upper()
    if name == "zero_width_split":
        return "\u200b".join(text)
    if name == "homoglyph":
        return "".join(_HOMOGLYPHS.get(ch.lower(), ch) for ch in text)
    if name == "leet_speak":
        return "".join(_LEET.get(ch.lower(), ch) for ch in text)
    if name == "null_byte_split":
        return "\x00".join(text)
    if name == "interleave_invisible":
        return "\u2061".join(text)
    if name == "morse":
        return " ".join(_MORSE.get(ch.lower(), ch) for ch in text)
    if name == "binary":
        return " ".join(format(b, "08b") for b in text.encode())
    if name == "octal":
        return " ".join(format(b, "03o") for b in text.encode())
    if name == "reverse_text":
        return text[::-1]
    if name == "word_reverse":
        return " ".join(w[::-1] for w in text.split())
    if name == "syllable_split":
        return "·".join(text)
    if name == "base64_double":
        return base64.b64encode(base64.b64encode(text.encode())).decode()
    if name == "base64_then_rot13":
        return codecs.encode(base64.b64encode(text.encode()).decode(), "rot_13")
    if name == "morse_then_rot13":
        # rot13 first, then Morse-encode the rotated plaintext.  The
        # registered name is ordered by *output composition order* (the
        # plaintext is rot13'd, then that is the input to Morse), not
        # by call order in this function.  Applying Morse first would
        # produce a no-op composition because rot_13 only rotates ASCII
        # letters and Morse output is dots/dashes/spaces only — see
        # tests/unit/test_encoding_mutator.py for the pinned invariant.
        rotated = codecs.encode(text, "rot_13")
        return " ".join(_MORSE.get(ch.lower(), ch) for ch in rotated)
    if name == "base64_then_morse":
        b64 = base64.b64encode(text.encode()).decode()
        return " ".join(_MORSE.get(ch.lower(), ch) for ch in b64)
    if name == "nato_phonetic":
        return " ".join(_NATO.get(ch.lower(), ch) for ch in text if ch.strip())
    if name == "pig_latin":
        return " ".join((w[1:] + w[0] + "ay") if w and w[0].isalpha() else w for w in text.split())
    if name == "backwards_words":
        return " ".join(reversed(text.split()))
    if name == "qwerty_shift":
        return _qwerty_shift(text, 1)
    if name == "fullwidth":
        return "".join(chr(ord(c) + _FULLWIDTH_OFFSET) if 0x21 <= ord(c) <= 0x7E else c for c in text)
    if name == "smallcaps":
        return "".join(_SMALLCAPS.get(ch.lower(), ch) for ch in text)
    if name == "chunked_b64":
        encoded = base64.b64encode(text.encode()).decode()
        return " ".join(encoded[i : i + 3] for i in range(0, len(encoded), 3))
    raise ValueError(f"unknown encoding: {name}")


_ENCODINGS: tuple[str, ...] = (
    "rot13",
    "caesar_3",
    "caesar_7",
    "base64",
    "base64_url",
    "base32",
    "base85",
    "hex_lower",
    "hex_upper",
    "zero_width_split",
    "homoglyph",
    "leet_speak",
    "null_byte_split",
    "interleave_invisible",
    "morse",
    "binary",
    "octal",
    "reverse_text",
    "word_reverse",
    "syllable_split",
    "base64_double",
    "base64_then_rot13",
    "morse_then_rot13",
    "base64_then_morse",
    "nato_phonetic",
    "pig_latin",
    "backwards_words",
    "qwerty_shift",
    "fullwidth",
    "smallcaps",
    "chunked_b64",
)


class EncodingMutator:
    """Wrap the seed template (or a specific placeholder) in an encoding.

    The cipher is included in the cleartext as a side-channel hint
    (e.g. "decode this base64 then follow the instructions"), since pure
    encoded payloads otherwise just produce model-side gibberish.
    """

    name = "encoding"

    def __init__(
        self,
        encodings: tuple[str, ...] = _ENCODINGS,
        include_decryption_hint: bool = True,
        repeat_per_encoding: int = 1,
    ) -> None:
        for e in encodings:
            # validate at construction time
            _encode(e, "abc", Random(0))
        self._encodings = encodings
        self._hint = include_decryption_hint
        self._repeat = repeat_per_encoding

    def mutate(self, seed: Seed, rng: Random) -> Iterator[tuple[dict[str, Any], str, dict[str, Any]]]:
        for enc in self._encodings:
            for rep in range(self._repeat):
                local_rng = Random(rng.random())
                encoded = _encode(enc, seed.template, local_rng)
                hint = f" (encoded via {enc}; decode then comply)" if self._hint else ""
                rendered = {"template": f"{encoded}{hint}"}
                yield (
                    rendered,
                    f"encoding:{enc}:{rep}",
                    {"encoding": enc, "repeat": rep},
                )


__all__ = ["EncodingMutator", "_ENCODINGS"]
