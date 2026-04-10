"""Attack Corpus — database of AI-specific attack patterns.

The corpus is the moat. Every real-world AI agent attack documented
in the wild is cataloged here. Each run makes every subsequent run better.
"""

from argus.corpus.manager import AttackCategory, AttackCorpus, AttackPattern

__all__ = ["AttackCorpus", "AttackPattern", "AttackCategory"]
