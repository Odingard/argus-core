import random
import re

class SentryAgent:
    """Tier 1: Stealth & Evasion specialist. Bypasses 2026 ASIC filters."""

    def __init__(self):
        # April 2026 Unicode Bypass Map
        self.homoglyphs = {
            'a': '\u0430', 'e': '\u0435', 'o': '\u043e', 
            'p': '\u0440', 's': '\u0455', 'i': '\u0456'
        }

    def apply_stealth_protocol(self, payload: str, turn: int) -> str:
        """Applies multi-stage stealth based on the Crescendo turn count."""
        # Turn 1-2: Benign Context (No mutations needed)
        if turn < 3:
            return payload
        
        # Turn 3-4: Scrambling (Middle-char reordering to bypass ASICs)
        mutated = self._scramble_inner_chars(payload)
        
        # Turn 5+: Full Homoglyph Substitution (Visual identity, byte-level diff)
        if turn >= 5:
            mutated = self._apply_homoglyphs(mutated)
            
        return mutated

    def _scramble_inner_chars(self, text: str) -> str:
        """Scrambles internal word chars; humans read it, hardware regexes fail."""
        def scramble_word(word):
            if len(word) <= 3: return word
            mid = list(word[1:-1])
            random.shuffle(mid)
            return word[0] + "".join(mid) + word[-1]
        return " ".join(scramble_word(w) for w in text.split())

    def _apply_homoglyphs(self, text: str) -> str:
        """Substitutes ASCII for visually identical Cyrillic/Greek tokens."""
        return "".join(self.homoglyphs.get(c, c) if random.random() > 0.4 else c for c in text)
