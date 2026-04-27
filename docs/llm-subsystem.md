# LLM Subsystem — Internal Engineering Note

What lives in `argus.shared.client`, why it's there, what to touch when
something changes. Not customer-facing.

---

## What it is

Every LLM call in ARGUS — from the judge to the CVE pipeline to the
mcp_live_attacker to whatever target adapter is calling its framework's
LLM — routes through `argus.shared.client.ArgusClient`. Eight production
call sites, all consuming the same surface:

```python
from argus.shared.client import ArgusClient

client = ArgusClient()
resp = client.messages.create(
    model="claude-sonnet-4-5",
    messages=[...],
    max_tokens=4000,
)
text = resp.content[0].text
```

The response shape is Anthropic's. OpenAI and Gemini responses are wrapped
in `MockMessageResponse` / `MockMessageContent` so consumers don't need
provider-aware response handling.

## What it does

1. **Provider routing.** Model name → provider via prefix matching
   (`gpt-`/`o1`/`o3` → openai, `gemini` → gemini, else anthropic).
2. **Per-provider dispatch with hard timeouts.** 45-second timeout per
   call (configurable via `ARGUS_JUDGE_TIMEOUT_S` env var, name kept for
   backwards compat — applies to all calls).
3. **Response normalisation.** OpenAI/Gemini responses → Anthropic shape.
4. **Failover chain walking.** If `ARGUS_LLM_CHAIN` is set in env (or a
   `chain=[...]` kwarg is passed), `messages.create` walks the chain on
   every call, blacklisting any model that returns a recognised quota /
   credit / auth error and falling over to the next.
5. **Process-wide dead-provider blacklist.** Class-level
   `ArgusMessagesAPI._dead_models`. Once a model is blacklisted, every
   consumer in the process skips it. Cleared between engagements via
   `ArgusClient.reset_blacklist()`.
6. **Litellm bridge.** `ArgusClient.build_litellm_kwargs(provider, model,
   chain=...)` produces a kwargs dict for litellm-based frameworks
   (crewAI, future Langchain) that includes `fallbacks=[...]` propagating
   ARGUS's chain into the framework's own LLM calls.

## Configuration surface

All config is via env vars, loaded from `.env` at process start:

| Env var | Purpose |
|---|---|
| `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` / `GEMINI_API_KEY` | Provider credentials. At least one must be set for `LLMJudge.available()` to return True. |
| `ARGUS_LLM_CHAIN` | Comma-separated default chain for all consumers. Empty/unset means single-attempt semantics. |
| `ARGUS_JUDGE_MODELS` | Plural override for the judge specifically. Layers on top of `ARGUS_LLM_CHAIN`. |
| `ARGUS_JUDGE_MODEL` | Singular legacy form of the judge override. Honoured for back-compat. |
| `ARGUS_JUDGE_TIMEOUT_S` | Per-call timeout in seconds. Default 45. Applies to ALL LLM calls, not just the judge. |
| `ARGUS_JUDGE` | When set to `1`, the judge is enabled. Tests that exercise the judge gate on this. |
| `ARGUS_OFFLINE` | When set to `1`, the offline-gate fires in `corpus_attacks/dynamic.py` to suppress live LLM mutator calls. The standard pytest gate sets this. |

## Failover semantics

Default: **single-attempt.** `client.messages.create(model="X", ...)`
calls X exactly once. If X raises, the exception propagates. Preserves
backwards compat with the original 8 call sites.

Failover is **opt-in** via `ARGUS_LLM_CHAIN`:

```bash
export ARGUS_LLM_CHAIN="claude-sonnet-4-5-20250929,gpt-4o,gemini-2.5-pro"
```

When set, `messages.create` walks the chain. Per-call opt-out with
`failover=False` for harness/test paths.

## Error taxonomy

`_PROVIDER_EXHAUSTED_PATTERNS` — substring patterns matched
case-insensitively against `str(exc)`. Hits → blacklist + advance.
Misses → propagate (model is probably fine, failure is transient).

Currently 19 patterns covering: `insufficient_quota`, `credit balance is
too low`, `rate_limit_exceeded`, `invalid_api_key`,
`authentication_error`, `permission_denied`, billing, and HTTP
401/402/403/429.

`AllProvidersExhausted` raised when every model in the chain has been
blacklisted. Consumers handle this by degrading gracefully (e.g. judge
emits UNAVAILABLE verdict) rather than crashing.

## Why we don't classify by exception class

Provider SDKs (OpenAI vs Anthropic vs Gemini) format errors differently,
SDK versions change error class hierarchies, and litellm wraps them into
yet a fourth shape. Substring matching on the error message is robust
across all four — at the cost of occasional false positives (model
slightly too aggressively blacklisted, recovers next process start) and
false negatives (one extra failed call before propagation). Both are
preferable to brittle class-based dispatch.

## What consumes it

```
src/argus/attacks/judge.py            LLMJudge — passes own chain via models=[...]
src/argus/agents/base.py              All MAAC agents — for in-agent LLM calls
src/argus/layer6/cve_pipeline.py      CVE candidate synthesis + advisory body
src/argus/mcp_attacker/               Two LLM call sites in mcp_live_attacker.py
src/argus/engagement/runner.py        Engagement-level synthesis
src/argus/routing/models.py           Cost-aware routing wraps client
src/argus/attacks/adaptive.py         Adaptive mutation strategy
src/argus/corpus_attacks/dynamic.py   Dynamic corpus mutator
src/argus/harness/stub_llm.py         Offline test stub matching the surface
src/argus/adapter/real_crewai.py      Uses build_litellm_kwargs(...) to propagate
                                      failover into crewAI's internal LLM calls
```

## Operator escape hatches

```python
ArgusClient.reset_blacklist()   # clear dead-provider list mid-run
ArgusClient.blacklist_snapshot() # observability — what's currently dead
```

Typical use: operator notices ARGUS skipped Claude all engagement because
of a transient quota issue, tops up the account, calls `reset_blacklist()`
between phases.

## Observability today

Failover events are emitted as `_LOGGER.warning` log lines. There is no
structured event stream yet. When the UI is built (Directive 3),
structured events should be added — the engagement event log is the
natural integration point, and the policy module is the natural place to
put a subscriber-pattern hook. **Not built yet — flagged here so the
next person who needs it doesn't redesign it from scratch.**

## What NOT to do

- **Don't add per-call-site failover.** All 8+ call sites already
  consume `ArgusClient`. New call sites must too. Universal-fit
  (Directive 1).
- **Don't add a new `argus.llm` package.** This subsystem is in
  `argus.shared.client`. Moving it for aesthetic reasons is pure churn
  with risk of breakage. If the path bothers you, add a re-export shim
  at the new path; don't relocate the source.
- **Don't classify exceptions by class.** Substring matching on
  `str(exc)` is the deliberate choice. Read the rationale above before
  changing it.
- **Don't make failover the unconditional default.** It is opt-in via
  env var for a reason: the 8 existing call sites have working
  single-attempt behaviour and tests that mock single calls. Changing
  the default cascades to test breakage across the suite.

---

*Last updated: 2026-04-27. Update this document when the LLM subsystem
changes shape.*
