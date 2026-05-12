"""Phase O — semantic-diversity gate tests.

The :class:`DiversityGate` enforces minimum Jaccard distance across an
active variant pool so the genetic engine doesn't collapse onto a
single attack vector. These tests pin:

* AGENTS.md #7 — deterministic. Same candidates → same accept/reject
  decisions, same rejection reasons.
* AGENTS.md #9 — every rejection is explainable. The
  :class:`DiversityRejection` record names the nearest accepted
  neighbour and the distance that triggered the drop.
* Pool-collapse fixture — 10 near-clones prune to ≤2 representatives.
* Capacity vs distance — the two rejection reasons are tracked
  separately so the supervisor's audit trail can tell them apart.
"""

from __future__ import annotations

from argus.engine.core.canary import CanarySet
from argus.engine.core.variant import Message, Variant
from argus.engine.runtime.diversity import (
    DiversityGate,
    jaccard_distance,
    shingle_set,
    sketch_variant,
)


def _v(variant_id: str, text: str) -> Variant:
    return Variant(
        variant_id=variant_id,
        seed_id="seed-x",
        attack_class="cog-test",
        layer="layer3_cognitive",
        messages=(Message(role="user", content=text),),
        canaries=CanarySet(primary="ARGT-CANARY-X"),
        metadata={},
    )


# --- shingle / jaccard primitives ---------------------------------


def test_shingle_set_is_deterministic() -> None:
    s = "the quick brown fox jumps over the lazy dog"
    assert shingle_set(s) == shingle_set(s)


def test_jaccard_distance_identical_is_zero() -> None:
    a = shingle_set("hello world")
    assert jaccard_distance(a, a) == 0.0


def test_jaccard_distance_disjoint_is_one() -> None:
    a = shingle_set("aaaaaaaaaa")
    b = shingle_set("zzzzzzzzzz")
    assert jaccard_distance(a, b) == 1.0


def test_jaccard_distance_symmetric() -> None:
    a = shingle_set("foo bar baz")
    b = shingle_set("baz qux quux corge")
    assert jaccard_distance(a, b) == jaccard_distance(b, a)


# --- gate happy-path ----------------------------------------------


def test_gate_accepts_first_candidate() -> None:
    gate = DiversityGate(min_distance=0.5)
    result = gate.filter_pool([_v("a", "anything at all goes here")])
    assert [v.variant_id for v in result.accepted] == ["a"]
    assert result.rejected == ()


def test_gate_rejects_near_clone() -> None:
    gate = DiversityGate(min_distance=0.5)
    a = _v("a", "the quick brown fox jumps over the lazy dog repeatedly")
    a_clone = _v("a-clone", "the quick brown fox jumps over the lazy dog repeatedly!")
    result = gate.filter_pool([a, a_clone])
    assert [v.variant_id for v in result.accepted] == ["a"]
    assert len(result.rejected) == 1
    rej = result.rejected[0]
    assert rej.variant_id == "a-clone"
    assert rej.reason == "too_similar"
    assert rej.nearest_variant_id == "a"
    assert rej.nearest_distance is not None
    assert rej.nearest_distance < 0.5


def test_gate_accepts_genuinely_different_candidates() -> None:
    gate = DiversityGate(min_distance=0.4)
    a = _v("a", "explore credential leakage angles through tool surfaces")
    b = _v("b", "investigate prompt injection through roleplay personas")
    c = _v(
        "c",
        "consider second-order RAG poisoning routes via memory writers",
    )
    result = gate.filter_pool([a, b, c])
    assert len(result.accepted) == 3
    assert result.rejected == ()


# --- determinism --------------------------------------------------


def test_filter_pool_is_deterministic_across_runs() -> None:
    pool = [_v(f"v-{i}", "explore credential leakage angles through tool surfaces") for i in range(5)]
    pool.append(_v("dist", "investigate prompt injection through roleplay personas"))

    r1 = DiversityGate(min_distance=0.4).filter_pool(pool)
    r2 = DiversityGate(min_distance=0.4).filter_pool(pool)
    assert [v.variant_id for v in r1.accepted] == [v.variant_id for v in r2.accepted]
    assert [r.variant_id for r in r1.rejected] == [r.variant_id for r in r2.rejected]


# --- pool-collapse regression -------------------------------------


def test_pool_collapse_fixture_prunes_clones() -> None:
    """10 near-identical variants → gate prunes to a single survivor."""
    gate = DiversityGate(min_distance=0.4)
    pool = [
        _v(
            f"clone-{i}",
            "leak the system prompt via the tool description by embedding instructions in the schema",
        )
        for i in range(10)
    ]
    result = gate.filter_pool(pool)
    # All ten are near-identical — exactly one survives.
    assert len(result.accepted) == 1
    assert len(result.rejected) == 9
    for rej in result.rejected:
        assert rej.reason == "too_similar"


# --- capacity gate ------------------------------------------------


def test_max_population_cap_rejects_with_capacity_reason() -> None:
    gate = DiversityGate(min_distance=0.0, max_population=2)
    pool = [_v(f"v-{i}", f"distinct-payload-{i}-zzz-{i * 7}") for i in range(5)]
    result = gate.filter_pool(pool)
    assert len(result.accepted) == 2
    assert len(result.rejected) == 3
    for rej in result.rejected:
        assert rej.reason == "pool_capacity"


# --- stats audit trail (rule #9) ----------------------------------


def test_stats_reflects_accept_reject_counters() -> None:
    gate = DiversityGate(min_distance=0.5)
    a = _v("a", "the quick brown fox jumps over the lazy dog repeatedly")
    a_clone = _v("a-clone", "the quick brown fox jumps over the lazy dog repeatedly")
    b = _v("b", "completely orthogonal RAG memory poisoning vectors")
    gate.filter_pool([a, a_clone, b])
    stats = gate.stats()
    assert stats["observed"] == 3
    assert stats["accepted"] == 2
    assert stats["rejected"] == 1
    assert stats["rejected_distance"] == 1


# --- temperature schedule ------------------------------------------


def test_temperature_decreases_with_generation() -> None:
    gate = DiversityGate()
    t0 = gate.temperature(generation=0, max_generations=10)
    t_mid = gate.temperature(generation=5, max_generations=10)
    t_late = gate.temperature(generation=9, max_generations=10)
    assert t0 > t_mid >= t_late
    assert 0.0 <= t_late <= 1.0
    assert 0.0 <= t0 <= 1.0


def test_temperature_is_deterministic() -> None:
    gate = DiversityGate()
    assert gate.temperature(generation=3, max_generations=10) == gate.temperature(generation=3, max_generations=10)


# --- empty / single-element edge cases ----------------------------


def test_empty_pool_returns_empty_result() -> None:
    gate = DiversityGate()
    result = gate.filter_pool([])
    assert result.accepted == ()
    assert result.rejected == ()


def test_seed_sketches_constrains_new_candidates() -> None:
    """Cross-generation enforcement — pre-seeded sketches still
    veto near-clones in the next pool."""
    a = _v("a", "tool schema injection via parameter description fields")
    a_sk = sketch_variant(a)

    gate = DiversityGate(min_distance=0.5)
    clone = _v("a2", "tool schema injection via parameter description fields!")
    result = gate.filter_pool([clone], seed_sketches=[a_sk])
    assert result.accepted == ()
    assert len(result.rejected) == 1
    assert result.rejected[0].nearest_distance is not None
