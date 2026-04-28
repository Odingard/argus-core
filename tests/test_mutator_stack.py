"""
tests/test_mutator_stack.py — corpus mutator stack coverage.

Covers:
  - Static mutators always present (zero keys)
  - Sentry mutators (CognitiveCamouflage, Crescendo) always present
  - LLM mutators added when key available
  - Correct total counts per environment
  - LLMMutator seed indices differ per call (entropy)
  - Each mutator has a unique name
  - LLMMutator job-specific routing table entries exist
"""


def _mutator_names(mutators: list) -> list[str]:
    return [m.name if hasattr(m, "name") else type(m).__name__
            for m in mutators]


def test_static_mutators_always_present(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    # Need to reimport after env change
    import importlib
    import argus.corpus_attacks.mutators as mod
    importlib.reload(mod)
    mutators = mod.default_mutators()
    names = _mutator_names(mutators)
    for expected in ["identity", "base64", "hex", "rot13",
                     "leetspeak", "uppercase"]:
        assert expected in names, f"Missing static mutator: {expected}"


def test_sentry_mutators_always_present(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    import importlib
    import argus.corpus_attacks.mutators as mod
    importlib.reload(mod)
    mutators = mod.default_mutators()
    names = _mutator_names(mutators)
    assert "crescendo" in names
    assert "cognitive_camouflage" in names


def test_keyless_count(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    import importlib
    import argus.corpus_attacks.mutators as mod
    importlib.reload(mod)
    mutators = mod.default_mutators()
    # 8 static + crescendo + cognitive_camouflage = 10
    assert len(mutators) == 10


def test_llm_mutators_added_with_key(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    import importlib
    import argus.corpus_attacks.mutators as mod
    importlib.reload(mod)
    mutators = mod.default_mutators()
    names = _mutator_names(mutators)
    llm_names = [n for n in names if n.startswith("llm_")]
    assert len(llm_names) == 3


def test_with_key_count(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    import importlib
    import argus.corpus_attacks.mutators as mod
    importlib.reload(mod)
    mutators = mod.default_mutators()
    # 8 static + 2 sentry + 3 llm = 13
    assert len(mutators) == 13


def test_llm_seed_indices_unique_per_call(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    import importlib
    import argus.corpus_attacks.mutators as mod
    importlib.reload(mod)
    # Two calls should produce different seed indices
    m1 = mod.default_mutators()
    m2 = mod.default_mutators()
    seeds1 = {m.seed_index for m in m1
              if hasattr(m, "seed_index")}
    seeds2 = {m.seed_index for m in m2
              if hasattr(m, "seed_index")}
    # Extremely unlikely to collide with 3-byte entropy
    assert seeds1 != seeds2


def test_all_mutator_names_unique(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    import importlib
    import argus.corpus_attacks.mutators as mod
    importlib.reload(mod)
    names = _mutator_names(mod.default_mutators())
    assert len(names) == len(set(names)), f"Duplicate names: {names}"


def test_llm_routing_jobs_exist():
    from argus.routing.models import _DEFAULT_CHAINS
    assert "rephrase_adversarial" in _DEFAULT_CHAINS
    assert "authority_framing" in _DEFAULT_CHAINS
    assert "indirect_reference" in _DEFAULT_CHAINS


def test_llm_routing_uses_cheap_models():
    from argus.routing.models import _DEFAULT_CHAINS
    for job in ("rephrase_adversarial", "authority_framing", "indirect_reference"):
        chain = _DEFAULT_CHAINS[job]
        models = [m for _, m in chain]
        # Should use Haiku / Flash / mini — not Opus or full GPT-4
        assert any("haiku" in m or "flash" in m or "mini" in m
                   for m in models), f"{job} not routed to fast model"
