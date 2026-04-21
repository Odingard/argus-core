# ARGUS — Deferred Work

Items that are intentionally open at end of 2026-04-21. Every one of these
was scoped but not shipped in-session; they're tracked here so they can't
slip through cracks the next time a future session asks "what's still to do?"

None of these are gaps in a shipped pillar — each is a **further deepening**
of an already-closed one.

## 1. Corpus PII / target-name scrubber  (Pillar 1)

**Context:** `src/argus/corpus/emitter.py` extracts training pairs from
scan results. Raw findings can contain target names, file paths, and
excerpts of scanned source. The RUNBOOK.md warns about it and says
"redact manually before upload."

**Scope to ship:**
- Regex + named-entity filter over every prompt/completion pair
- Strip: URLs, hostnames, email addresses, IP/CIDR, Bearer tokens,
  AWS/GCP key patterns, paths under known target roots
- Replace with stable placeholders (`<TARGET_HOST>`, `<ID>`, etc.)
- Add a `--scrub` flag to `emit_from_results`
- Test against a seeded adversarial corpus with planted leakage

**Why deferred:** write a separate `src/argus/corpus/scrub.py` after
we have a real engagement's results to tune the regex set on.

## 2. DeepMind-style MCTS exploit-chain search  (Pillar 1 + L5)

**Context:** Today L5 does one-shot Opus chain synthesis. A Monte
Carlo Tree Search would propose chain variations, score each in the
L7 sandbox (verifier), and expand promising branches.

**Scope to ship:**
- `src/argus/search/` package
- `ExploitMCTS` with UCT selection, sandbox-as-verifier backup
- Budget-capped (wall-clock + API tokens)
- Integration point: when correlator escalates to Opus, MCTS runs
  instead of a single completion

**Why deferred:** meaningful LOC (600+) and API spend to tune. Needs
a target that produces many real findings before the search tree is
non-trivial. The routing work shipped today makes MCTS cheap to wire
when we get there — it can use the same `route_call` machinery.

## 3. L7 eBPF / pcap network capture  (Pillar 3)

**Context:** Today L7 sandbox extracts a `[net]` summary from PoC
stdout. Full packet capture (pcap) or eBPF tracing would prove —
not just infer — what the PoC touched.

**Scope to ship:**
- Sidecar container running `tcpdump -i any -w /shared/trace.pcap`
- Or privileged sibling container with `bpftrace` hooking `connect()`
- Include trace in Wilson bundle as `network.pcap`
- `--net-trace full` opt-in flag (default off — adds latency)

**Why deferred:** requires privileged Docker (`--cap-add=NET_ADMIN`)
which breaks the current capability-drop hardening. Needs a two-
container sandbox refactor — too invasive for this session.

## 4. Fleet-scale webhook backing store  (Pillar 4)

**Context:** `argus --serve` is single-process, in-memory job table.
Fine for single-operator. Fleet deployments need a queue + worker
pool.

**Scope to ship:**
- Redis-backed job queue (`argus-job` keyspace)
- Pluggable worker driver (Celery / arq / custom)
- Postgres job-table for durable status + audit
- Auth hardening: per-client API keys + rate limits

**Why deferred:** MVP is designed for one operator; we don't have
a fleet customer yet. Land when the first SaaS engagement signs.

## 5. Multi-model consensus for CRITICAL findings  (Pillar 3 / S4)

**Context:** MAAC §3 recommends "agreement from multiple independent
models before executing high-stakes actions." Today a CRITICAL chain
rests on Opus alone.

**Scope to ship:**
- `src/argus/audit/consensus.py`
- Given a chain, pose the same premise-verification to 3 models
  across providers (Anthropic + Google + OpenAI — already in the
  router chain)
- Require N-of-3 agreement (configurable) to keep `blast_radius`
  CRITICAL; downgrade to HIGH otherwise
- Record each vote in the Wilson bundle

**Why deferred:** pairs naturally with the MCTS search (#2). Doing
them together is much more efficient than doing them separately.
Cost-manageable once the router is in production (it already is).

---

## How to revisit

These five items live in `DEFERRED.md` at the repo root. Check them
at the top of every significant new session. The memory file
`feedback_moat_pillars.md` names the pillars / sinkholes each maps
to so future work can be prioritized against the moat, not ad-hoc.

Last updated: 2026-04-21
