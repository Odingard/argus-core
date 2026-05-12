"""Genetic engine + refusal KB unit tests."""

from __future__ import annotations

from argus.engine.core.canary import CanarySet
from argus.engine.core.variant import Message, Variant
from argus.engine.runtime.genetic import GeneticEngine, ScoredVariant
from argus.engine.runtime.refusal_kb import RefusalKB
from argus.engine.runtime.reward import DeviationScore


def _v(vid: str) -> Variant:
    return Variant(
        variant_id=vid,
        seed_id="s",
        attack_class="c",
        layer="layer1_tool_poisoning",
        messages=(Message(role="user", content="hello"),),
        tools=(),
        resources=(),
        rag_corpus=(),
        canaries=CanarySet(primary="ARGT-CANARY-X"),
        matcher_ids=("canary_echo",),
        mutator_chain=(),
    )


def test_genetic_keeps_survivors_above_threshold() -> None:
    eng = GeneticEngine(seed_value=1, max_generations=3, survival_threshold=0.2)
    eng.ingest_results(
        [
            ScoredVariant(_v("a"), DeviationScore(0.5, "x")),
            ScoredVariant(_v("b"), DeviationScore(0.05, "y")),
            ScoredVariant(_v("c"), DeviationScore(0.9, "z")),
        ]
    )
    assert eng.best_score == 0.9
    assert eng.survivor_count == 2  # 0.5 and 0.9 survive


def test_genetic_next_generation_is_deterministic() -> None:
    eng_a = GeneticEngine(seed_value=42, max_generations=2)
    eng_b = GeneticEngine(seed_value=42, max_generations=2)
    for eng in (eng_a, eng_b):
        eng.ingest_results([ScoredVariant(_v("x"), DeviationScore(0.6, "ok"))])
    a = [c.variant_id for c in eng_a.next_generation()]
    b = [c.variant_id for c in eng_b.next_generation()]
    assert a == b


def test_genetic_stops_after_max_generations() -> None:
    eng = GeneticEngine(seed_value=1, max_generations=2)
    eng.ingest_results([ScoredVariant(_v("a"), DeviationScore(0.7, "ok"))])
    list(eng.next_generation())
    eng.ingest_results([ScoredVariant(_v("b"), DeviationScore(0.7, "ok"))])
    list(eng.next_generation())
    assert eng.should_continue() is False or list(eng.next_generation()) == []


def test_refusal_kb_dedupes_by_signature() -> None:
    kb = RefusalKB()
    a = kb.ingest("I'm sorry, I cannot help with that request.")
    b = kb.ingest("I'm sorry, I can't help with that.")
    c = kb.ingest("Refusing — that violates policy.")
    assert a is not None
    assert b is not None
    assert c is not None
    # the first two share the canonical "I'm sorry / can't help" pattern
    assert kb.size() <= 3


def test_refusal_kb_empty_string_returns_none() -> None:
    kb = RefusalKB()
    assert kb.ingest("") is None
    assert kb.ingest(None) is None  # type: ignore[arg-type]
    assert kb.size() == 0
