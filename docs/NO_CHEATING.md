# The No-Cheating Contract

Every ARGUS finding is a claim the operator will hand to a
customer's CISO, SOC, or regulator. That claim has to hold up. This
document is the integrity contract every ARGUS module honours.

---

## Non-negotiable rules

### 1. Echo is not a finding

> "A finding is only confirmed when the injection causes a
> measurable, reproducible change in the agent's behavior."
> — from the original spec

A model repeating the attack payload back is not a finding. The
ObservationEngine compares a baseline transcript to a post-attack
transcript; only a measurable delta produces a verdict.

### 2. No LLM in the validation path

Mutation may use an LLM (OfflineMutatorBackend and
OpenEvolveMutatorBackend both exist). Scoring never does. Every
finding's verdict is emitted by a deterministic regex / shape /
counter detector.

### 3. No scenario-aware branching in ARGUS code

```python
# BANNED
if scenario_id == "crewai-quickstart":
    inject_known_payload()
```

Agents attack with generic techniques. If a corpus variant lands,
it lands because the technique works; if it doesn't, the score is
the score.

### 4. No hardcoded canary values in module code

Canary tokens are injected into payloads at RUNTIME and detected at
runtime via generic pattern matching. There is no `if "ARGUS-
CANARY-07" in response: return True` anywhere in `src/`.

### 5. No pre-fabricated findings in acceptance tests

Acceptance tests run REAL agents against REAL labrats. They never
construct `AgentFinding` objects by hand to feed downstream
components.

### 6. Assertions on shape, not values

```python
# OK
assert chain.severity in {"HIGH", "CRITICAL", "CATASTROPHIC"}
assert "SECRET" in impact["data_classes_exposed"]
assert len(chain["owasp_categories"]) >= 3

# NOT OK (brittle + encourages cheating)
assert impact["harm_score"] == 100
assert chain["steps"][3]["surface"] == "tool:delete_user"
```

### 7. No secret scanners' worst nightmare

Fake credentials in labrat fixtures are assembled at runtime:

```python
# NOT "sk_live_abcdefghijklmnop"
"STRIPE_LIVE_KEY=" + "sk_" + "live_" + "a" * 24
```

The pattern survives through the classifier, the scanner doesn't
flag the literal.

---

## How to detect cheating in review

- `grep -r "if.*scenario.*==" src/` → must be zero
- `grep -r "ARGUS-CANARY-[0-9]" src/` → must be zero
  (canaries are runtime-generated in `argus.evidence.oob`)
- `grep -rn "manually constructed.*AgentFinding" tests/` → must be zero
- Tests that assert exact harm-score values → rewrite to union membership
- Adapter logic that inspects `AgentFinding` objects → must be zero
  (adapters never see findings)

---

## The test suite enforces this

`tests/test_contracts.py` codifies these invariants as pytest
checks. Run it before every commit:

```bash
pytest tests/test_contracts.py -q
```

If it goes red, the platform has drifted off-spec. Fix the drift
before shipping.
